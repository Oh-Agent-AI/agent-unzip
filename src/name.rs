//! 中文文件名修复。
//!
//! 两类真实问题：
//! 1. Windows 打包的 ZIP 常用 GBK 编码且不写 UTF-8 标志位 → 在 Mac 上乱码
//! 2. 已经乱码的字符串（UTF-8 字节被当成 latin1 解码）→ 二次修复

use encoding_rs::{GB18030, WINDOWS_1252};

fn has_cjk(s: &str) -> bool {
    s.chars().any(|c| {
        ('\u{4e00}'..='\u{9fff}').contains(&c)
            || ('\u{3400}'..='\u{4dbf}').contains(&c)
            || ('\u{3000}'..='\u{303f}').contains(&c)
            || ('\u{ff00}'..='\u{ffef}').contains(&c)
    })
}

/// 把压缩包里的原始文件名字节转成正确的字符串。
pub fn decode_name(raw: &[u8], utf8_flag: bool) -> String {
    if let Ok(s) = std::str::from_utf8(raw) {
        if utf8_flag || !s.is_empty() {
            return s.to_string();
        }
    }
    // 不是合法 UTF-8：先按 GB18030（GBK 的超集）解
    let (cow, _, had_errors) = GB18030.decode(raw);
    if !had_errors && has_cjk(&cow) {
        return cow.into_owned();
    }
    // 再退到 cp1252（西文乱码场景）
    let (cow, _, _) = WINDOWS_1252.decode(raw);
    let s = cow.into_owned();
    repair_mojibake(&s).unwrap_or(s)
}

/// 修复「UTF-8 被当作 latin1/cp1252 解码」造成的乱码，例：`å\u{8d}\u{95}` → `单`
pub fn repair_mojibake(s: &str) -> Option<String> {
    if has_cjk(s) {
        return None; // 已经正常，不动
    }
    // 把字符串按 cp1252 反编码回字节，再按 UTF-8 解释
    let (bytes, _, had_errors) = WINDOWS_1252.encode(s);
    if had_errors || bytes.is_empty() {
        return None;
    }
    let fixed = std::str::from_utf8(&bytes).ok()?;
    if has_cjk(fixed) {
        Some(fixed.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gbk_names() {
        // "谷小姐" 的 GBK 编码
        let gbk: &[u8] = &[0xB9, 0xC8, 0xD0, 0xA1, 0xBD, 0xE3];
        assert_eq!(decode_name(gbk, false), "谷小姐");
    }

    #[test]
    fn utf8_names_untouched() {
        assert_eq!(decode_name("单片".as_bytes(), true), "单片");
    }

    #[test]
    fn mojibake_repaired() {
        // "单" 的 UTF-8 字节 E5 8D 95 被错误地按 cp1252 解码
        let (bad, _, _) = encoding_rs::WINDOWS_1252.decode(&[0xE5, 0x8D, 0x95]);
        assert_eq!(repair_mojibake(&bad).as_deref(), Some("单"));
    }
}
