//! pak 内核库 —— CLI 和 Tauri 桌面壳共用同一套逻辑。
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

    let (entries, declared, traversal, executables, encrypted, junk, bomb, spoofing, comment, completeness) =
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
            )
        } else {
            (0, 0, vec![], vec![], 0, 0, false, vec![], None, vec![])
        };

    let ratio = if meta.len() > 0 {
        declared as f64 / meta.len() as f64
    } else {
        0.0
    };
    let blocking = !traversal.is_empty()
        || !executables.is_empty()
        || !spoofing.is_empty()
        || bomb
        || kind.is_dangerous();
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
    );

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
) -> (String, String, Vec<String>) {
    if matches!(kind, Kind::Rar | Kind::Rar4) && !cfg!(feature = "rar") {
        return (
            "caution".into(),
            "这个版本不带 RAR 支持".into(),
            vec![
                "它是 RAR 压缩包，但当前构建裁掉了 UnRAR（自由软件版）。".into(),
                "要解它请安装带 rar 特性的构建：cargo install pak --features rar".into(),
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
        return (
            "danger".into(),
            "危险：包里裹着安装程序".into(),
            vec![
                format!("找到了 {} 个可执行内容：{}。", uniq.len(), names.join("、")),
                "「照片包」里出现安装程序，是骗你装软件最常见的套路。如果你没在等这个程序，建议整包删掉。".into(),
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
    let staging = parent.join(format!(".pak-tmp-{}-{}", std::process::id(), fast_rand()));

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
