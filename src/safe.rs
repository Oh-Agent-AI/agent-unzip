//! 安全护栏：路径净化、可执行条目识别、体积/数量上限。

use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Limits {
    /// 单包解压后总字节上限
    pub max_total: u64,
    /// 条目数量上限（防嵌套炸弹）
    pub max_entries: usize,
    /// 压缩比上限（解压后 / 压缩包），超过视为可疑
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_total: 50 * 1024 * 1024 * 1024, // 50 GB
            max_entries: 200_000,
            max_ratio: 500,
        }
    }
}

/// 把压缩包内的相对路径净化成「安全落盘路径」。
///
/// 拒绝：绝对路径、`..` 穿越、盘符、空名。
/// 这就是 Zip Slip 的防线 —— 一道都不写。
pub fn sanitize_name(rel: &str) -> Option<PathBuf> {
    let unified = rel.replace('\\', "/");
    if unified.is_empty() {
        return None;
    }
    // 盘符 C:/ 或 //
    let bytes = unified.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return None;
    }
    let mut out = PathBuf::new();
    for comp in Path::new(&unified).components() {
        match comp {
            Component::Normal(c) => {
                let s = c.to_string_lossy();
                if s == "." || s.is_empty() {
                    continue;
                }
                // 去掉 macOS/Windows 的非法字符
                let cleaned: String = s
                    .chars()
                    .map(|ch| if ch == '\0' || ch == '/' { '_' } else { ch })
                    .collect();
                out.push(cleaned);
            }
            Component::CurDir => continue,
            // 任何一个 .. 直接整条拒绝
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// 可执行 / 安装器类条目。压缩包里的这类文件，是「误导用户安装」的载体。
pub fn executable_kind(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    // App / 安装包：看整条路径里有没有 .app/ 段
    if lower.contains(".app/") || lower.ends_with(".app") {
        return Some("macOS 应用程序 (.app)");
    }
    let ext = base.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext {
        "pkg" => Some("macOS 安装包 (.pkg)"),
        "dmg" => Some("磁盘映像 (.dmg)"),
        "command" => Some("可执行脚本 (.command)"),
        "sh" | "bash" | "zsh" => Some("Shell 脚本"),
        "exe" => Some("Windows 程序 (.exe)"),
        "msi" => Some("Windows 安装包 (.msi)"),
        "bat" | "cmd" => Some("Windows 批处理"),
        "ps1" => Some("PowerShell 脚本"),
        "scr" => Some("屏幕保护程序 (.scr，常被滥用)"),
        "lnk" => Some("Windows 快捷方式 (.lnk，常被滥用)"),
        "js" | "jse" | "vbs" | "vbe" | "wsf" => Some("脚本 (.js/.vbs，常被滥用)"),
        "jar" => Some("Java 程序 (.jar)"),
        "workflow" => Some("Automator 工作流"),
        "applescript" | "scpt" => Some("AppleScript"),
        "url" => Some("网页快捷方式 (.url)"),
        _ => None,
    }
}

/// 文件名欺骗：看不见的字符、双扩展名
pub fn name_spoof(name: &str) -> Option<&'static str> {
    if name.chars().any(|c| c == '\u{202E}' || c == '\u{202D}') {
        return Some("文件名里藏了「从右往左」控制符，能让 .exe 看起来像 .png");
    }
    if name
        .chars()
        .any(|c| ('\u{200B}'..='\u{200F}').contains(&c) || c == '\u{FEFF}' || c == '\u{2060}')
    {
        return Some("文件名里藏了零宽字符，用来把真实扩展名藏起来");
    }
    if name.chars().any(|c| c.is_control()) {
        return Some("文件名里有控制字符，正常打包不会这样");
    }
    let lower = name.to_ascii_lowercase();
    const DOUBLE: [&str; 12] = [
        ".jpg.exe", ".jpeg.exe", ".png.exe", ".pdf.exe", ".doc.exe", ".docx.exe",
        ".mp4.exe", ".jpg.scr", ".png.scr", ".jpg.app", ".png.app", ".jpg.js",
    ];
    if DOUBLE.iter().any(|d| lower.ends_with(d)) {
        return Some("双扩展名：前面的 .jpg/.pdf 是伪装，真正会被执行的是最后一段");
    }
    None
}

/// 垃圾文件：解压后没必要留给用户看
pub fn is_junk(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    // macOS 在 tar 里塞的 AppleDouble 资源叉文件
    if base.starts_with("._") && base.len() > 2 {
        return true;
    }
    if base == ".ds_store" || base == "thumbs.db" || base == "desktop.ini" {
        return true;
    }
    if lower.starts_with("__macosx/") || lower.contains("/__macosx/") {
        return true;
    }
    if base == ".gitkeep" || base == ".keep" {
        return false; // 这个别删，是目录占位
    }
    // Windows RAR 临时残留，如 $R4N6AX5.jpg
    // 注意：必须看原始大小写，不能看小写化之后的 base，否则永远匹配不上
    let raw_base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    if raw_base.starts_with('$')
        && raw_base.contains('.')
        && raw_base
            .chars()
            .skip(1)
            .take(5)
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return true;
    }
    let _ = base;
    false
}

/// 安全检查结果
#[derive(Debug, Default)]
pub struct Risk {
    pub entries: usize,
    pub declared_bytes: u64,
    pub executables: Vec<(String, &'static str)>,
    pub encrypted: usize,
    pub traversal: Vec<String>,
    pub spoofing: Vec<(String, &'static str)>,
    /// 压缩包注释（常含制作方、密码提示、联系方式）
    pub comment: Option<Vec<u8>>,
    /// 顶层目录 / 该目录下文件数
    pub groups: Vec<(String, usize)>,
    /// 内容构成：媒体 / 文档（用来判断「照片包里夹程序」这种不协调）
    pub media: usize,
    pub docs: usize,
    pub junk: usize,
    pub bomb_suspect: bool,
}

impl Risk {
    pub fn has_blocking(&self) -> bool {
        !self.executables.is_empty()
            || !self.traversal.is_empty()
            || !self.spoofing.is_empty()
            || self.bomb_suspect
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_traversal() {
        assert!(sanitize_name("../../etc/passwd").is_none());
        assert!(sanitize_name("/etc/passwd").is_none());
        assert!(sanitize_name("C:/windows/x.dll").is_none());
    }

    #[test]
    fn keeps_normal_names() {
        assert_eq!(
            sanitize_name("谷小姐 底片ac  1/单片/622A5711.jpg").unwrap(),
            PathBuf::from("谷小姐 底片ac  1/单片/622A5711.jpg")
        );
        assert!(sanitize_name("./a/../b").is_none());
    }

    #[test]
    fn detects_executables() {
        assert!(executable_kind("照片查看器.app/Contents/MacOS/applet").is_some());
        assert!(executable_kind("安装看图插件.exe").is_some());
        assert!(executable_kind("622A5711.jpg").is_none());
    }
}
