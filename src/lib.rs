//! aunzip 内核库 —— CLI 和 Tauri 桌面壳共用同一套逻辑。
//!
//! 对外只暴露两个动作：
//!   `inspect`  拍照体检，不动硬盘
//!   `unpack`   解压（含暂存、落位、抢救）

pub mod extract;
pub mod name;
pub mod safe;
pub mod sniff;

use anyhow::{anyhow, bail, Context, Result};
use safe::Limits;
use serde::Serialize;
use sniff::Kind;
use std::fs;
use std::path::{Path, PathBuf};

/// 文件来源（从 macOS 隔离标记里读出来）
#[derive(Debug, Clone, Serialize)]
pub struct Origin {
    /// 原始代理名，如 Chrome / WeChat / Feishu
    pub agent: String,
    /// 人话版本，如「微信收到的」
    pub label: String,
    /// 多久以前
    pub when: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExeItem {
    pub name: String,
    pub kind: String,
}

/// 照片元数据画像（只描述「是什么来路」，不读取画面内容）
#[derive(Debug, Clone, Serialize, Default)]
pub struct ExifSummary {
    /// 成功解析了多少张
    pub analyzed: usize,
    /// 没有 EXIF 的（截图、导出的图常见）
    pub no_exif: usize,
    pub cameras: Vec<String>,
    pub software: Vec<String>,
    /// 带 GPS 定位的张数
    pub with_gps: usize,
    pub taken_from: Option<String>,
    pub taken_to: Option<String>,
}

impl ExifSummary {
    pub fn one_line(&self) -> String {
        let mut p = Vec::new();
        if !self.cameras.is_empty() {
            p.push(format!("相机 {}", self.cameras.join(" / ")));
        }
        if let Some(from) = &self.taken_from {
            let f = short_dt(from);
            match &self.taken_to {
                Some(to) if to != from => {
                    let t = short_dt(to);
                    // 同一天就省略日期，读起来更顺
                    if f.len() >= 10 && t.len() >= 10 && f[..10] == t[..10] {
                        p.push(format!("拍摄于 {} ~ {}", f, &t[11..]));
                    } else {
                        p.push(format!("拍摄于 {f} ~ {t}"));
                    }
                }
                _ => p.push(format!("拍摄于 {f}")),
            }
        }
        if !self.software.is_empty() {
            p.push(format!("经手过 {}", self.software.join(" / ")));
        }
        if self.no_exif > 0 {
            p.push(format!("{} 张无 EXIF", self.no_exif));
        }
        p.join(" · ")
    }
}

/// "2026-10-11 09:55:14" → "2026-10-11 09:55"
fn short_dt(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 16 && t.as_bytes().get(10) == Some(&b' ') {
        t[..16].to_string()
    } else {
        t.to_string()
    }
}

/// 交付完整性：目录名承诺的数量 vs 实际文件数
#[derive(Debug, Clone, Serialize)]
pub struct GroupCheck {
    pub dir: String,
    pub expected: usize,
    pub actual: usize,
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Inspection {
    pub path: String,
    pub file_name: String,
    pub kind: String,
    pub kind_label: String,
    pub is_archive: bool,
    pub dangerous: bool,
    pub disguise: Option<String>,
    pub bytes: u64,
    pub entries: usize,
    pub declared_bytes: u64,
    pub ratio: f64,
    pub traversal: Vec<String>,
    /// 文件名欺骗（看不见的字符 / 双扩展名）
    pub spoofing: Vec<String>,
    pub executables: Vec<ExeItem>,
    pub encrypted: usize,
    pub junk: usize,
    pub bomb: bool,
    /// 体检结论
    pub blocking: bool,
    /// 三级结论：safe / caution / danger
    pub verdict: String,
    /// 一句话人话结论
    pub headline: String,
    /// 为什么这么判断（给焦虑用户看的大白话）
    pub reasons: Vec<String>,
    /// 这个文件从哪来的
    pub origin: Option<Origin>,
    /// 压缩包注释（常含制作方、密码提示、联系方式）
    pub comment: Option<String>,
    /// 交付完整性核对结果
    pub completeness: Vec<GroupCheck>,
    /// 机器可读判定码，Agent 直接 switch
    pub codes: Vec<String>,
}

/// 解压后的内容画像：按「真实类型」统计，不信扩展名
#[derive(Debug, Clone, Serialize, Default)]
pub struct ContentSummary {
    pub images: usize,
    pub videos: usize,
    pub documents: usize,
    pub archives: usize,
    pub executables: usize,
    pub other: usize,
    /// 扩展名与真实内容不符的文件（伪装）
    pub mismatches: Vec<String>,
}

impl ContentSummary {
    pub fn total(&self) -> usize {
        self.images + self.videos + self.documents + self.archives + self.executables + self.other
    }
    pub fn one_line(&self) -> String {
        let mut parts = Vec::new();
        if self.images > 0 {
            parts.push(format!("{} 张图片", self.images));
        }
        if self.videos > 0 {
            parts.push(format!("{} 个视频", self.videos));
        }
        if self.documents > 0 {
            parts.push(format!("{} 份文档", self.documents));
        }
        if self.archives > 0 {
            parts.push(format!("{} 个压缩包", self.archives));
        }
        if self.other > 0 {
            parts.push(format!("{} 个其他文件", self.other));
        }
        if self.executables > 0 {
            parts.push(format!("⚠ {} 个可执行程序", self.executables));
        }
        if parts.is_empty() {
            "空".to_string()
        } else {
            parts.join(" · ")
        }
    }
}

/// 打包前检查结果：打的是「我自己给出去的东西」，所以要防的是泄漏
#[derive(Debug, Clone, Serialize, Default)]
pub struct PackCheck {
    pub entries: usize,
    pub bytes: u64,
    /// 可执行文件（别把自己的程序发给客户）
    pub executables: Vec<String>,
    /// 隐藏文件 / 密钥目录
    pub hidden: Vec<String>,
    /// 文件名里疑似 PII
    pub pii: Vec<String>,
    pub codes: Vec<String>,
}

impl PackCheck {
    pub fn blocking(&self) -> bool {
        !self.executables.is_empty() || !self.hidden.is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PackReport {
    pub archive: String,
    pub format: String,
    pub entries: usize,
    pub bytes: u64,
    pub encrypted: bool,
    pub seconds: f64,
    pub warnings: Vec<String>,
    pub codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub dir: String,
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
    pub seconds: f64,
    pub junk_skipped: usize,
    pub traversal_blocked: usize,
    pub encrypted: usize,
    pub failed: usize,
    pub executables: Vec<ExeItem>,
    pub note: Option<String>,
    /// 解压后的真实内容画像
    pub content: ContentSummary,
    /// 交付完整性核对结果
    pub completeness: Vec<GroupCheck>,
    /// 照片元数据（包里有图片时才有）
    pub exif: Option<ExifSummary>,
}

/// `.app/Contents/MacOS/applet` 这类一堆条目归并成「照片查看器.app」一条
fn dedupe_names(list: &[(String, &'static str)]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (n, _) in list {
        let key = match n.find(".app/") {
            Some(i) => n[..i + 4].to_string(),
            None => n.clone(),
        };
        if seen.insert(key.clone()) {
            out.push(key);
        }
    }
    out
}

fn exe_items(list: &[(String, &'static str)]) -> Vec<ExeItem> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (n, k) in list {
        let key = match n.find(".app/") {
            Some(i) => n[..i + 4].to_string(),
            None => n.clone(),
        };
        if seen.insert(key.clone()) {
            out.push(ExeItem { name: key, kind: k.to_string() });
        }
    }
    out
}

/// 拍照体检：只读头部/目录，不解压
pub fn inspect(path: &Path) -> Result<Inspection> {
    if !path.exists() {
        bail!("文件不存在");
    }
    let meta = fs::metadata(path)?;
    if meta.is_dir() {
        bail!("这是文件夹，不是压缩包");
    }
    let kind = sniff::sniff_path(path).context("读取文件头失败")?;
    let disguise = sniff::disguise_hint(path, kind);
    let limits = Limits::default();

    let (entries, declared, traversal, executables, encrypted, junk, bomb, spoofing, comment, completeness, media, docs) =
        if kind.is_archive() {
            let risk = extract::scan(kind, path, &limits)?;
            let sp = risk
                .spoofing
                .iter()
                .map(|(n, h)| format!("{n} —— {h}"))
                .collect();
            let comment = risk.comment.as_deref().and_then(clean_comment);
            let completeness = risk
                .groups
                .iter()
                .filter_map(|(dir, actual)| {
                    expected_count(dir).map(|expected| GroupCheck {
                        dir: dir.clone(),
                        expected,
                        actual: *actual,
                        ok: expected == *actual,
                    })
                })
                .collect();
            (
                risk.entries,
                risk.declared_bytes,
                risk.traversal,
                risk.executables,
                risk.encrypted,
                risk.junk,
                risk.bomb_suspect,
                sp,
                comment,
                completeness,
                risk.media,
                risk.docs,
            )
        } else {
            (0, 0, vec![], vec![], 0, 0, false, vec![], None, vec![], 0, 0)
        };

    let ratio = if meta.len() > 0 {
        declared as f64 / meta.len() as f64
    } else {
        0.0
    };
    let origin = read_origin(path);
    let (verdict, headline, mut reasons) = judge(
        kind,
        &disguise,
        &spoofing,
        &traversal,
        &executables,
        encrypted,
        junk,
        bomb,
        entries,
        declared,
        meta.len(),
        media,
        docs,
    );

    // 只有 danger 才阻断；caution 交给用户判断（否则「纯软件包」会被误伤）
    let blocking = verdict == "danger";

    // 机器判定码：稳定、可枚举，Agent 直接 switch
    let mut codes: Vec<String> = Vec::new();
    if matches!(kind, Kind::Rar | Kind::Rar4) && !cfg!(feature = "rar") {
        codes.push("RAR_DISABLED".into());
    }
    if kind.is_dangerous() {
        codes.push("DISGUISED_ARCHIVE".into());
    }
    if !kind.is_archive() && !kind.is_dangerous() {
        codes.push("NOT_AN_ARCHIVE".into());
    }
    if !spoofing.is_empty() {
        codes.push("SPOOFED_NAME".into());
    }
    if !traversal.is_empty() {
        codes.push("PATH_TRAVERSAL".into());
    }
    if !executables.is_empty() {
        if media + docs > 0 {
            codes.push("EXECUTABLE_IN_MEDIA".into());
        } else {
            codes.push("EXECUTABLE_PACKAGE".into());
        }
        codes.push("EXECUTABLE_ENTRY".into());
    }
    if bomb {
        codes.push("POSSIBLE_BOMB".into());
    }
    if encrypted > 0 {
        codes.push("ENCRYPTED".into());
    }
    if completeness.iter().any(|g| !g.ok) {
        codes.push("COUNT_MISMATCH".into());
    }
    if codes.is_empty() {
        codes.push("OK".into());
    }

    // 交付数量对不上，虽然不是安全问题，但对他就是「少一张要赔钱」
    let missing: Vec<String> = completeness
        .iter()
        .filter(|g| !g.ok)
        .map(|g| format!("{} 说 {} 张，实际 {}", g.dir, g.expected, g.actual))
        .collect();
    if !missing.is_empty() {
        reasons.push(format!("交付数量对不上：{}", missing.join("；")));
    }

    Ok(Inspection {
        path: path.display().to_string(),
        file_name: path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default(),
        kind: format!("{kind:?}"),
        kind_label: kind.label().to_string(),
        is_archive: kind.is_archive(),
        dangerous: kind.is_dangerous(),
        disguise,
        bytes: meta.len(),
        entries,
        declared_bytes: declared,
        ratio,
        traversal,
        spoofing,
        executables: exe_items(&executables),
        encrypted,
        junk,
        bomb,
        blocking,
        verdict,
        headline,
        reasons,
        origin,
        comment,
        completeness,
        codes,
    })
}

/// 从目录名里读出「应该有几张」：9p / 9张 / 9页
fn expected_count(dir: &str) -> Option<usize> {
    let lower = dir.to_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    let mut i = 0;
    let mut found = None;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let num: usize = chars[start..i].iter().collect::<String>().parse().ok()?;
            // 允许数字与单位之间有空格
            let mut j = i;
            while j < chars.len() && chars[j] == ' ' {
                j += 1;
            }
            if let Some(&unit) = chars.get(j) {
                let hit = match unit {
                    '张' | '页' | '入' => true,
                    'p' => !matches!(chars.get(j + 1), Some(&'x') | Some(&'t') | Some(&'c') | Some(&'s')),
                    _ => false,
                };
                if hit && (1..=999).contains(&num) {
                    found = Some(num);
                }
            }
        } else {
            i += 1;
        }
    }
    found
}

/// 注释可能带编码问题或控制字符，清理成可显示的一句话
fn clean_comment(raw: &[u8]) -> Option<String> {
    let text = name::decode_name(raw, false);
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut out: String = trimmed.chars().take(300).collect();
    if trimmed.chars().count() > 300 {
        out.push('…');
    }
    Some(out)
}

/// 把技术判定翻译成「能不能放心」的人话
#[allow(clippy::too_many_arguments)]
fn judge(
    kind: Kind,
    disguise: &Option<String>,
    spoofing: &[String],
    traversal: &[String],
    executables: &[(String, &'static str)],
    encrypted: usize,
    junk: usize,
    bomb: bool,
    entries: usize,
    declared: u64,
    compressed: u64,
    media: usize,
    docs: usize,
) -> (String, String, Vec<String>) {
    if matches!(kind, Kind::Rar | Kind::Rar4) && !cfg!(feature = "rar") {
        return (
            "caution".into(),
            "这个版本不带 RAR 支持".into(),
            vec![
                "它是 RAR 压缩包，但当前构建裁掉了 UnRAR（自由软件版）。".into(),
                "要解它请安装带 rar 特性的构建：cargo install aunzip --features rar".into(),
            ],
        );
    }
    if kind.is_dangerous() {
        return (
            "danger".into(),
            "别碰它：这不是压缩包".into(),
            vec![format!(
                "名字看起来像个压缩包，但里面其实是一个{}。这是典型的伪装手法——双击就会运行它。",
                kind.label()
            )],
        );
    }
    if bomb {
        let ratio = if compressed > 0 {
            declared as f64 / compressed as f64
        } else {
            0.0
        };
        return (
            "danger".into(),
            "可疑：这个包解开会撑爆硬盘".into(),
            vec![format!(
                "包只有 {}，解开却有 {}（{:.0} 倍）。正常的照片包不会这样，这是「压缩炸弹」的特征。",
                human(compressed),
                human(declared),
                ratio
            )],
        );
    }
    if !spoofing.is_empty() {
        return (
            "danger".into(),
            "危险：文件名在骗你".into(),
            vec![
                spoofing.first().cloned().unwrap_or_default(),
                format!("一共 {} 个文件用了这种手法。看不见的字符能让 .exe 显示成 .png，肉眼识别不了。", spoofing.len()),
            ],
        );
    }

    if !traversal.is_empty() {
        return (
            "danger".into(),
            "可疑：包里有文件想偷偷写到别处".into(),
            vec![format!(
                "其中 {} 个文件把目标路径指到了压缩包外面（例如 ../../），正常文件不会这样写。已全部拦下。",
                traversal.len()
            )],
        );
    }

    if !executables.is_empty() {
        let uniq = dedupe_names(executables);
        let names: Vec<String> = uniq.iter().take(3).cloned().collect();
        // 判断「协调性」：软件包里的 .app 正常；照片包里的 .app 才是钓鱼
        let media_or_doc = media + docs;
        if media_or_doc > 0 {
            return (
                "danger".into(),
                "危险：照片/文档里夹着程序".into(),
                vec![
                    format!(
                        "包里有 {} 个媒体/文档文件，同时有 {} 个可执行内容：{}。",
                        media_or_doc,
                        uniq.len(),
                        names.join("、")
                    ),
                    "交付照片或文件时不会夹带安装程序。这是骗你装软件最常见的形态，建议整包删掉。".into(),
                ],
            );
        }
        // 整包就是软件包/安装包：正常，只是要确认来源
        return (
            "caution".into(),
            "这是个软件包，里面有程序".into(),
            vec![
                format!("{} 个可执行内容：{}。", uniq.len(), names.join("、")),
                "包里没有照片或文档，看起来就是一个正常的软件/安装包。确认来源可靠（官网、同事、你自己的构建产物）就可以解。".into(),
                "解压后不要给它管理员权限，也不要绕过系统的「无法验证开发者」提示。".into(),
            ],
        );
    }

    if encrypted > 0 {
        return (
            "caution".into(),
            "有密码：看不清里面，但这是常规做法".into(),
            vec![
                format!("{} 个文件设了密码，看不到内容。", encrypted),
                "影楼、摄影师交付底片常常加密码防外泄，属于正常做法。确认密码是对方给你的，就可以解。".into(),
            ],
        );
    }

    if !kind.is_archive() {
        let mut r = vec![format!("它的真实身份是「{}」。", kind.label())];
        if let Some(d) = disguise {
            r.push(d.clone());
        }
        return ("caution".into(), "这不是压缩包".into(), r);
    }

    // 干净包
    let mut r = vec![format!(
        "{} 个文件，解开约 {}，里面没有程序、没有伪装、没有越界路径。",
        entries,
        human(declared)
    )];
    if junk > 0 {
        r.push(format!("顺手会清掉 {} 个系统的垃圾文件（不影响内容）。", junk));
    }
    ("safe".into(), "可以放心解开".into(), r)
}

pub fn human(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// 直接读 com.apple.quarantine（不 fork 子进程，App Sandbox 下也能用）
#[cfg(target_os = "macos")]
fn quarantine_of(path: &Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let name = std::ffi::CString::new("com.apple.quarantine").ok()?;
    let mut buf = [0u8; 1024];
    let n = unsafe {
        libc::getxattr(
            cpath.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            0,
        )
    };
    if n <= 0 {
        return None;
    }
    String::from_utf8(buf[..n as usize].to_vec()).ok()
}

/// 读 macOS 的隔离标记，告诉用户「这个文件从哪来的」
fn read_origin(path: &Path) -> Option<Origin> {
    #[cfg(target_os = "macos")]
    {
        // 走 syscall 而不是起 xattr 子进程：App Sandbox 下 fork/exec 会被拒，
        // 而且这样也没有依赖外部命令的脆弱性。
        let raw = quarantine_of(path)?;
        let parts: Vec<&str> = raw.trim().split(';').collect();
        let agent = parts.get(2).copied().unwrap_or("").trim().to_string();
        let secs: i64 = parts
            .get(1)
            .and_then(|h| i64::from_str_radix(h.trim(), 16).ok())
            .unwrap_or(0);
        if agent.is_empty() && secs == 0 {
            return None;
        }
        let label = match agent.as_str() {
            "" => "来源不明（下载标记已被清理）".to_string(),
            "Safari" => "从 Safari 下载".to_string(),
            "Chrome" | "Google Chrome" => "从 Chrome 下载".to_string(),
            "WeChat" => "从微信收到的".to_string(),
            "Feishu" | "Lark" | "飞书" => "从飞书收到的".to_string(),
            "QQ" => "从 QQ 收到的".to_string(),
            "Mail" => "邮件附件".to_string(),
            "Thunder" | "aria2" | "curl" => "用下载工具下的".to_string(),
            other => format!("从 {other} 来的"),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let delta = (now - secs).max(0);
        let when = if secs == 0 {
            "时间未知".to_string()
        } else if delta < 120 {
            "刚刚".to_string()
        } else if delta < 3600 {
            format!("{} 分钟前", delta / 60)
        } else if delta < 86400 {
            format!("{} 小时前", delta / 3600)
        } else {
            format!("{} 天前", delta / 86400)
        };
        return Some(Origin { agent, label, when });
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        None
    }
}

pub fn strip_known_ext(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let suffixes = [
        ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2", ".tbz", ".txz", ".zip", ".rar", ".7z",
        ".tar", ".gz", ".bz2", ".xz", ".cbr", ".cbz", ".cpgz",
    ];
    for s in suffixes {
        if lower.ends_with(s) {
            return name[..name.len() - s.len()].to_string();
        }
    }
    match name.rsplit_once('.') {
        Some((a, _)) if !a.is_empty() => a.to_string(),
        _ => name.to_string(),
    }
}

fn unique_dir(parent: &Path, base: &str) -> PathBuf {
    let mut candidate = parent.join(base);
    let mut i = 2;
    while candidate.exists() && i <= 999 {
        candidate = parent.join(format!("{base}_{i}"));
        i += 1;
    }
    candidate
}

/// 真正解压。`out_parent` 为空则解到压缩包旁边。
pub fn unpack(
    path: &Path,
    out_parent: Option<&Path>,
    password: Option<&str>,
    force: bool,
) -> Result<Report> {
    let insp = inspect(path)?;
    if insp.dangerous {
        bail!("这不是压缩包，是伪装成压缩包的可执行程序，已拒绝");
    }
    if !insp.is_archive {
        bail!("不支持的文件类型：{}", insp.kind_label);
    }
    if insp.encrypted > 0 && password.is_none() {
        bail!("这个包加密了，需要密码。填上密码我再解");
    }
    if insp.blocking && !force {
        bail!("体检发现问题，需要确认后再解压");
    }

    let kind = sniff::sniff_path(path)?;
    let parent = match out_parent {
        Some(d) => {
            fs::create_dir_all(d)?;
            d.to_path_buf()
        }
        None => path
            .parent()
            .map(|p| {
                if p.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    p.to_path_buf()
                }
            })
            .unwrap_or_else(|| PathBuf::from(".")),
    };
    let base = strip_known_ext(&path.file_name().unwrap_or_default().to_string_lossy());
    let final_dir = unique_dir(&parent, if base.trim().is_empty() { "解压结果" } else { base.trim() });
    let staging = parent.join(format!(".aunzip-tmp-{}-{}", std::process::id(), fast_rand()));

    let t0 = std::time::Instant::now();
    let limits = Limits::default();
    let outcome = extract::extract(kind, path, &staging, &limits, password, force).map_err(|e| {
        let _ = fs::remove_dir_all(&staging);
        // 密码类错误本身已经说清楚了，不要再套一层「解压失败」制造困惑
        let msg = format!("{e:#}");
        if msg.contains("密码") || msg.contains("加密") {
            e
        } else {
            e.context("解压失败（暂存目录已清理）")
        }
    })?;

    if outcome.files == 0 && outcome.dirs == 0 {
        let _ = fs::remove_dir_all(&staging);
        return Err(anyhow!("什么都没解出来（空包或格式异常）"));
    }
    let (content, exif) = postcheck(&staging);

    if final_dir.exists() {
        let _ = fs::remove_dir_all(&staging);
        return Err(anyhow!("目标目录已被占用：{}", final_dir.display()));
    }
    fs::rename(&staging, &final_dir).context("落位失败")?;

    Ok(Report {
        dir: final_dir.display().to_string(),
        files: outcome.files,
        dirs: outcome.dirs,
        bytes: outcome.bytes,
        seconds: t0.elapsed().as_secs_f64(),
        junk_skipped: outcome.junk_skipped,
        traversal_blocked: outcome.traversal_blocked,
        encrypted: outcome.encrypted,
        failed: outcome.failed,
        executables: exe_items(&outcome.executables),
        note: outcome.note,
        content,
        completeness: insp.completeness.clone(),
        exif: if exif.analyzed > 0 { Some(exif) } else { None },
    })
}

/// 解压后逐个文件核对「真实类型 vs 扩展名」——这是防「假照片」的最后一道关口
fn postcheck(root: &Path) -> (ContentSummary, ExifSummary) {
    let mut out = ContentSummary::default();
    let mut exif = ExifSummary::default();
    walk(root, root, &mut out, &mut exif);
    (out, exif)
}

fn walk(dir: &Path, root: &Path, out: &mut ContentSummary, exif: &mut ExifSummary) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk(&p, root, out, exif);
            continue;
        }
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .display()
            .to_string();
        let ext = p
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let kind = sniff::sniff_path(&p).unwrap_or(Kind::Unknown);

        if kind.is_dangerous() {
            out.executables += 1;
            let claims_media = matches!(
                ext.as_str(),
                "jpg" | "jpeg" | "png" | "gif" | "heic" | "webp" | "bmp" | "tif" | "tiff"
                    | "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "txt" | "md"
                    | "mp4" | "mov" | "avi" | "mkv" | "m4v" | "zip" | "rar" | "7z"
            );
            if claims_media {
                out.mismatches.push(format!(
                    "{rel}：扩展名是 .{ext}，内容其实是{}",
                    kind.label()
                ));
            }
        } else if matches!(kind, Kind::Image) {
            out.images += 1;
            // 只抽样解析，别把固实包拖到天荒地老
            if exif.analyzed + exif.no_exif < EXIF_SAMPLE_LIMIT {
                match exif_digest(&p) {
                    Some(d) => {
                        exif.analyzed += 1;
                        if let Some(c) = d.0 {
                            if !exif.cameras.contains(&c) {
                                exif.cameras.push(c);
                            }
                        }
                        if let Some(sf) = d.1 {
                            if !exif.software.contains(&sf) {
                                exif.software.push(sf);
                            }
                        }
                        if let Some(dt) = d.2 {
                            let cur_min = exif.taken_from.clone();
                            let cur_max = exif.taken_to.clone();
                            exif.taken_from =
                                Some(match cur_min { Some(c) => c.min(dt.clone()), None => dt.clone() });
                            exif.taken_to = Some(match cur_max { Some(c) => c.max(dt), None => dt });
                        }
                        if d.3 {
                            exif.with_gps += 1;
                        }
                    }
                    None => exif.no_exif += 1,
                }
            }
        } else {
            match ext.as_str() {
                "mp4" | "mov" | "avi" | "mkv" | "m4v" | "wmv" | "flv" => out.videos += 1,
                "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "txt" | "md" | "csv" => {
                    out.documents += 1
                }
                "zip" | "rar" | "7z" | "tar" | "gz" => out.archives += 1,
                _ => out.other += 1,
            }
        }
    }
}

/// 只抽样这么多张，避免固实包被拖慢
const EXIF_SAMPLE_LIMIT: usize = 60;

/// 从一张图里读出：相机、软件、拍摄时间、是否有 GPS
fn exif_digest(p: &Path) -> Option<(Option<String>, Option<String>, Option<String>, bool)> {
    let f = fs::File::open(p).ok()?;
    let mut r = std::io::BufReader::new(f);
    let parsed = exif::Reader::new().read_from_container(&mut r).ok()?;

    let get = |tag: exif::Tag| -> Option<String> {
        parsed
            .get_field(tag, exif::In::PRIMARY)
            .map(|f| f.display_value().to_string())
            .map(|v| v.trim_matches('"').trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let camera = get(exif::Tag::Model).or_else(|| get(exif::Tag::Make));
    let software = get(exif::Tag::Software);
    let dt = get(exif::Tag::DateTimeOriginal).or_else(|| get(exif::Tag::DateTime));
    // 只说「有没有」，不打印坐标本身（避免把客户住址写进日志/截图）
    let gps = parsed
        .get_field(exif::Tag::GPSLatitude, exif::In::PRIMARY)
        .is_some()
        && parsed
            .get_field(exif::Tag::GPSLongitude, exif::In::PRIMARY)
            .is_some();
    Some((camera, software, dt, gps))
}

// ---------------------------------------------------------------- 打包

/// 递归收集要打包的文件：(绝对路径, 包内相对路径)
fn collect_inputs(path: &Path, base: &Path, out: &mut Vec<(PathBuf, String)>) -> Result<()> {
    if path.is_dir() {
        for e in fs::read_dir(path)?.flatten() {
            collect_inputs(&e.path(), base, out)?;
        }
    } else if path.is_file() {
        let rel = path
            .strip_prefix(base)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.file_name().unwrap_or_default().to_string_lossy().to_string());
        out.push((path.to_path_buf(), rel.replace('\\', "/")));
    }
    Ok(())
}

/// 文件名里的敏感信息：手机号 / 身份证 / 明确的字眼
fn find_pii(s: &str) -> Option<&'static str> {
    let lower = s.to_lowercase();
    for kw in ["身份证", "手机号", "手机号码", "银行卡", "密码", "住址"] {
        if lower.contains(kw) {
            return Some("文件名含敏感字眼");
        }
    }
    // 中国大陆手机号：1 开头、第二位 3-9、共 11 位
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i + 11 <= b.len() {
        if b[i] == '1'
            && b[i + 1].is_ascii_digit()
            && ('3'..='9').contains(&b[i + 1])
            && b[i..i + 11].iter().all(|c| c.is_ascii_digit())
        {
            let before_ok = i == 0 || !b[i - 1].is_ascii_digit();
            let after_ok = i + 11 >= b.len() || !b[i + 11].is_ascii_digit();
            if before_ok && after_ok {
                return Some("文件名含手机号");
            }
        }
        i += 1;
    }
    None
}

fn is_secret_dir(name: &str) -> bool {
    matches!(name, ".git" | ".ssh" | ".gnupg" | ".aws" | ".kube")
}

/// 打包前检查（不写盘）
pub fn check_pack_inputs(inputs: &[PathBuf]) -> Result<PackCheck> {
    let mut out = PackCheck::default();
    for input in inputs {
        if !input.exists() {
            bail!("路径不存在：{}", input.display());
        }
        let mut files = Vec::new();
        collect_inputs(input, input, &mut files)?;
        if input.is_file() {
            // 单文件：相对名就是文件名
            files.clear();
            collect_inputs_file(input, &mut files)?;
        }
        for (abs, rel) in files {
            out.entries += 1;
            if let Ok(m) = fs::metadata(&abs) {
                out.bytes += m.len();
            }
            // 隐藏文件 / 密钥目录
            let mut cur = abs.parent();
            while let Some(dir) = cur {
                if let Some(n) = dir.file_name().and_then(|x| x.to_str()) {
                    if is_secret_dir(n) {
                        out.hidden.push(format!("{rel}（在 {} 里）", n));
                        break;
                    }
                }
                cur = dir.parent();
            }
            if let Some(name) = abs.file_name().and_then(|x| x.to_str()) {
                if name.starts_with('.') && name != ".DS_Store" {
                    out.hidden.push(rel.clone());
                }
            }
            if let Some(k) = safe::executable_kind(&rel) {
                out.executables.push(format!("{rel}  [{k}]"));
            } else if let Ok(kind) = sniff::sniff_path(&abs) {
                if kind.is_dangerous() {
                    out.executables.push(format!("{rel}  [实际是{}]", kind.label()));
                }
            }
            if let Some(why) = find_pii(&rel) {
                out.pii.push(format!("{rel} —— {why}"));
            }
        }
    }

    let mut codes = Vec::new();
    if !out.executables.is_empty() {
        codes.push("PACK_EXECUTABLE".to_string());
    }
    if !out.hidden.is_empty() {
        codes.push("PACK_HIDDEN".to_string());
    }
    if !out.pii.is_empty() {
        codes.push("PACK_PII".to_string());
    }
    if codes.is_empty() {
        codes.push("OK".to_string());
    }
    out.codes = codes;
    Ok(out)
}

fn collect_inputs_file(path: &Path, out: &mut Vec<(PathBuf, String)>) -> Result<()> {
    let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
    out.push((path.to_path_buf(), name));
    Ok(())
}

/// 打包。format 由输出后缀决定：.zip / .tar.gz / .tgz / .tar
pub fn pack(
    inputs: &[PathBuf],
    output: &Path,
    password: Option<&str>,
    level: u32,
    force: bool,
) -> Result<PackReport> {
    let check = check_pack_inputs(inputs)?;
    if check.blocking() && !force {
        bail!("打包前检查未通过，已中止（确认无误后再加 --force）");
    }

    // 收集
    let mut files: Vec<(PathBuf, String)> = Vec::new();
    for input in inputs {
        if input.is_dir() {
            let base = input.parent().unwrap_or(Path::new("."));
            collect_inputs(input, base, &mut files)?;
        } else {
            collect_inputs_file(input, &mut files)?;
        }
    }
    if files.is_empty() {
        bail!("没有可打包的文件");
    }

    let name = output.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
    let t0 = std::time::Instant::now();
    let mut written = 0u64;

    let format = if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        "tar.gz"
    } else if name.ends_with(".tar") {
        "tar"
    } else if name.ends_with(".zip") {
        "zip"
    } else {
        bail!("不支持这个输出格式。用 .zip（通用）或 .tar.gz（开发用）");
    };

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    match format {
        "zip" => {
            if password.is_some() && !cfg!(feature = "zip-aes") {
                // 默认构建里 zip 的 aes-crypto 是开着的，这里只是保险
            }
            let f = fs::File::create(output)?;
            let mut zw = zip::ZipWriter::new(f);
            let mut opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .compression_level(Some(level as i64));
            if let Some(pw) = password {
                opts = opts.with_aes_encryption(zip::AesMode::Aes256, pw);
            }
            for (abs, rel) in &files {
                let data = fs::read(abs)?;
                written += data.len() as u64;
                zw.start_file(rel.as_str(), opts)?;
                use std::io::Write as _;
                zw.write_all(&data)?;
            }
            zw.finish()?;
        }
        _ => {
            if password.is_some() {
                bail!("tar 格式不支持密码。要加密请输出 .zip");
            }
            let f = fs::File::create(output)?;
            if format == "tar.gz" {
                let enc = flate2::write::GzEncoder::new(f, flate2::Compression::new(level));
                let mut b = tar::Builder::new(enc);
                for (abs, rel) in &files {
                    written += fs::metadata(abs).map(|m| m.len()).unwrap_or(0);
                    b.append_path_with_name(abs, rel)?;
                }
                b.into_inner()?.finish()?;
            } else {
                let mut b = tar::Builder::new(f);
                for (abs, rel) in &files {
                    written += fs::metadata(abs).map(|m| m.len()).unwrap_or(0);
                    b.append_path_with_name(abs, rel)?;
                }
                b.finish()?;
            }
        }
    }

    Ok(PackReport {
        archive: output.display().to_string(),
        format: format.to_string(),
        entries: files.len(),
        bytes: written,
        encrypted: password.is_some(),
        seconds: t0.elapsed().as_secs_f64(),
        warnings: {
            let mut w = Vec::new();
            w.extend(check.executables.iter().map(|x| format!("含可执行文件：{x}")));
            w.extend(check.hidden.iter().map(|x| format!("含隐藏文件：{x}")));
            w.extend(check.pii.iter().map(|x| format!("文件名可能含个人信息：{x}")));
            w
        },
        codes: check.codes,
    })
}

fn fast_rand() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)) as u32
}

pub fn kind_of(path: &Path) -> Result<Kind> {
    Ok(sniff::sniff_path(path)?)
}
