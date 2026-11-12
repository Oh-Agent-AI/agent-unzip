//! 解压内核：RAR 优先（官方 unrar），顺带支持 ZIP / 7Z / TAR / GZ / BZ2 / XZ。

use crate::name::decode_name;
use crate::safe::{executable_kind, is_junk, sanitize_name, Limits, Risk};
use crate::sniff::Kind;
use anyhow::{anyhow, Context, Result};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct Outcome {
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
    pub junk_skipped: usize,
    pub traversal_blocked: usize,
    pub executables: Vec<(String, &'static str)>,
    pub encrypted: usize,
    pub failed: usize,
    pub note: Option<String>,
}

/// 带限额的落盘器
struct Sink<'a> {
    root: &'a Path,
    limits: &'a Limits,
    out: &'a mut Outcome,
}

impl<'a> Sink<'a> {
    fn new(root: &'a Path, limits: &'a Limits, out: &'a mut Outcome) -> Self {
        Self { root, limits, out }
    }

    fn ensure(&mut self, rel: &str) -> Option<PathBuf> {
        if is_junk(rel) {
            self.out.junk_skipped += 1;
            return None;
        }
        match sanitize_name(rel) {
            Some(p) => {
                if let Some(k) = executable_kind(rel) {
                    self.out.executables.push((rel.to_string(), k));
                }
                Some(self.root.join(p))
            }
            None => {
                self.out.traversal_blocked += 1;
                None
            }
        }
    }

    fn write_stream(&mut self, rel: &str, mut r: impl Read) -> Result<()> {
        let Some(path) = self.ensure(rel) else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("建目录失败: {}", parent.display()))?;
        }
        let mut w = BufWriter::new(File::create(&path).with_context(|| format!("写入失败: {}", path.display()))?);
        let mut buf = vec![0u8; 128 * 1024];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.out.bytes += n as u64;
            if self.out.bytes > self.limits.max_total {
                return Err(anyhow!(
                    "解压后体积超过上限 {} GB，判定为压缩炸弹，已中止",
                    self.limits.max_total / 1024 / 1024 / 1024
                ));
            }
            w.write_all(&buf[..n])?;
        }
        w.flush()?;
        self.out.files += 1;
        Ok(())
    }

    fn ensure_only(&mut self, rel: &str) {
        let _ = self.ensure(rel);
    }

    fn mkdir(&mut self, rel: &str) {
        if let Some(p) = self.ensure(rel) {
            if fs::create_dir_all(&p).is_ok() {
                self.out.dirs += 1;
            }
        }
    }
}

/// 预检（不解压，只读目录/头部）
pub fn scan(kind: Kind, src: &Path, limits: &Limits) -> Result<Risk> {
    match kind {
        #[cfg(feature = "rar")]
        Kind::Rar | Kind::Rar4 => rar_scan(src, limits),
        #[cfg(not(feature = "rar"))]
        Kind::Rar | Kind::Rar4 => Ok(Risk::default()),
        Kind::Zip => zip_scan(src, limits),
        _ => Ok(Risk::default()),
    }
}

fn finish_risk(mut risk: Risk, limits: &Limits, compressed: u64) -> Risk {
    if risk.entries > limits.max_entries {
        risk.bomb_suspect = true;
    }
    if compressed > 0 && risk.declared_bytes / compressed.max(1) > limits.max_ratio {
        risk.bomb_suspect = true;
    }
    risk
}

// ---------------------------------------------------------------- RAR

#[cfg(feature = "rar")]
fn rar_scan(src: &Path, limits: &Limits) -> Result<Risk> {
    let mut risk = Risk::default();
    let mut comment_buf: Vec<u8> = Vec::new();
    {
        let mut archive = unrar::Archive::new(src);
        archive.set_comments(&mut comment_buf);
        let listing = archive
            .open_for_listing()
            .map_err(|e| anyhow!("无法读取 RAR 目录：{e}"))?;
        for header in listing {
        let h = header.map_err(|e| anyhow!("RAR 目录损坏：{e}"))?;
        let name = h.filename.to_string_lossy().to_string();
        risk.entries += 1;
        risk.declared_bytes += h.unpacked_size;
        if h.is_encrypted() {
            risk.encrypted += 1;
        }
        if !h.is_directory() {
            if sanitize_name(&name).is_none() {
                risk.traversal.push(name.clone());
            }
            if let Some(k) = executable_kind(&name) {
                risk.executables.push((name.clone(), k));
            }
            if let Some(h) = crate::safe::name_spoof(&name) {
                risk.spoofing.push((name.clone(), h));
            }
        }
            if is_junk(&name) {
                risk.junk += 1;
            }
            if let Some((top, _)) = name.rsplit_once('/') {
                if !top.is_empty() {
                    match risk.groups.iter_mut().find(|(d, _)| d == top) {
                        Some((_, n)) => *n += 1,
                        None => risk.groups.push((top.to_string(), 1)),
                    }
                }
            }
        }
    }
    if !comment_buf.is_empty() {
        risk.comment = Some(comment_buf);
    }
    let compressed = fs::metadata(src).map(|m| m.len()).unwrap_or(0);
    Ok(finish_risk(risk, limits, compressed))
}

#[cfg(feature = "rar")]
fn rar_extract(src: &Path, dest: &Path, limits: &Limits, password: Option<&str>) -> Result<Outcome> {
    let mut out = Outcome::default();

    let pw_owned = password.unwrap_or("").to_string();
    let mut archive = if password.is_some() {
        unrar::Archive::with_password(src, &pw_owned)
    } else {
        unrar::Archive::new(src)
    };
    // 分卷：无论拖的是哪一卷，都从第一卷开始
    if archive.is_multipart() {
        archive = archive.as_first_part();
    }

    let mut cursor = archive
        .open_for_processing()
        .map_err(|e| anyhow!("打开 RAR 失败：{e}"))?;

    loop {
        let header = match cursor.read_header() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                out.note = Some(format!("RAR 中途读取失败（可能已抢救出前面的文件）：{e}"));
                break;
            }
        };
        let entry = header.entry().clone_info();
        let name = entry.0;
        let size = entry.1;
        let is_dir = entry.2;
        let encrypted = entry.3;

        if encrypted && password.is_none() {
            out.encrypted += 1;
            cursor = header.skip().map_err(|e| anyhow!("{e}"))?;
            continue;
        }

        if is_junk(&name) {
            out.junk_skipped += 1;
            cursor = header.skip().map_err(|e| anyhow!("{e}"))?;
            continue;
        }
        let Some(rel) = sanitize_name(&name) else {
            out.traversal_blocked += 1;
            cursor = header.skip().map_err(|e| anyhow!("{e}"))?;
            continue;
        };
        if let Some(k) = executable_kind(&name) {
            out.executables.push((name.clone(), k));
        }
        let full = dest.join(&rel);

        if is_dir {
            fs::create_dir_all(&full).ok();
            out.dirs += 1;
            cursor = header.skip().map_err(|e| anyhow!("{e}"))?;
            continue;
        }
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        out.bytes += size;
        if out.bytes > limits.max_total {
            return Err(anyhow!("解压后体积超过上限，判定为压缩炸弹，已中止"));
        }
        match header.extract_to(&full) {
            Ok(next) => {
                cursor = next;
                out.files += 1;
            }
            Err(e) => {
                // 单条坏了不等于整包没救：保留已解出的，停在这里
                let _ = fs::remove_file(&full);
                out.failed += 1;
                out.note = Some(format!("第 {} 个条目读取失败，已抢救出前面的 {} 个文件（{e}）", out.files + 1, out.files));
                break;
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- ZIP

fn zip_scan(src: &Path, limits: &Limits) -> Result<Risk> {
    let mut risk = Risk::default();
    let file = File::open(src)?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| anyhow!("无法读取 ZIP：{e}"))?;
    let cmt = zip.comment().to_vec();
    if !cmt.is_empty() {
        risk.comment = Some(cmt);
    }
    for i in 0..zip.len() {
        let f = zip.by_index_raw(i).map_err(|e| anyhow!("ZIP 条目损坏：{e}"))?;
        let name = decode_name(f.name_raw(), true);
        risk.entries += 1;
        risk.declared_bytes += f.size();
        if f.encrypted() {
            risk.encrypted += 1;
        }
        if f.is_dir() {
            continue;
        }
        if sanitize_name(&name).is_none() {
            risk.traversal.push(name.clone());
        }
        if let Some(k) = executable_kind(&name) {
            risk.executables.push((name.clone(), k));
        }
        if let Some(h) = crate::safe::name_spoof(&name) {
            risk.spoofing.push((name.clone(), h));
        }
        if is_junk(&name) {
            risk.junk += 1;
        }
        if let Some((top, _)) = name.rsplit_once('/') {
            if !top.is_empty() {
                match risk.groups.iter_mut().find(|(d, _)| d == top) {
                    Some((_, n)) => *n += 1,
                    None => risk.groups.push((top.to_string(), 1)),
                }
            }
        }
    }
    let compressed = fs::metadata(src).map(|m| m.len()).unwrap_or(0);
    Ok(finish_risk(risk, limits, compressed))
}

fn zip_extract(
    src: &Path,
    dest: &Path,
    limits: &Limits,
    password: Option<&str>,
    out: &mut Outcome,
) -> Result<()> {
    let file = File::open(src)?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| anyhow!("无法读取 ZIP：{e}"))?;
    let n = zip.len();
    for i in 0..n {
        let f = if let Some(pw) = password {
            match zip.by_index_decrypt(i, pw.as_bytes()) {
                Ok(f) => f,
                Err(zip::result::ZipError::InvalidPassword) => {
                    return Err(anyhow!(
                        "密码不对。这个包用了加密（ZIP 常见是 ZipCrypto 或 AES），换一个密码再试"
                    ))
                }
                Err(e) => return Err(anyhow!("解密失败：{e}")),
            }
        } else {
            match zip.by_index(i) {
                Ok(f) => f,
                Err(zip::result::ZipError::UnsupportedArchive(_)) => {
                    out.encrypted += 1;
                    continue;
                }
                Err(e) => return Err(anyhow!("读取条目失败：{e}")),
            }
        };
        let name = decode_name(f.name_raw(), true);
        if f.is_dir() {
            let mut sink = Sink::new(dest, limits, out);
            sink.mkdir(&name);
            continue;
        }
        if f.encrypted() && password.is_none() {
            out.encrypted += 1;
            continue;
        }
        if let Some(mode) = f.unix_mode() {
            if mode & 0o111 != 0 && executable_kind(&name).is_none() {
                out.executables.push((name.clone(), "带可执行权限位的文件 (chmod +x)"));
            }
        }
        let mut sink = Sink::new(dest, limits, out);
        match sink.write_stream(&name, f) {
            Ok(()) => {}
            Err(e) => {
                let msg = format!("{e:#}");
                if msg.contains("password") || msg.contains("Password") || msg.contains("crypto") {
                    return Err(anyhow!("密码不对，或这个包的加密方式不支持"));
                }
                out.failed += 1;
                out.note.get_or_insert_with(|| format!("有 {} 个条目损坏未能解出", out.failed));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- TAR / GZ / BZ2 / XZ

fn reader_for(kind: Kind, src: &Path) -> Result<Box<dyn Read>> {
    let f = BufReader::new(File::open(src)?);
    Ok(match kind {
        Kind::Tar => Box::new(f),
        Kind::Gz => Box::new(flate2::read::GzDecoder::new(f)),
        Kind::Bz2 => Box::new(bzip2_rs::DecoderReader::new(f)),
        Kind::Xz => {
            // 先流式解到临时文件，再当 tar 读（避免整包进内存）
            let tmp = std::env::temp_dir().join(format!("pak-xz-{}.tar", std::process::id()));
            let mut w = BufWriter::new(File::create(&tmp)?);
            let mut r = f;
            lzma_rs::xz_decompress(&mut r, &mut w)?;
            w.flush()?;
            Box::new(BufReader::new(File::open(&tmp)?))
        }
        _ => Box::new(f),
    })
}

fn tar_like_extract(kind: Kind, src: &Path, dest: &Path, limits: &Limits, out: &mut Outcome) -> Result<()> {
    let reader = reader_for(kind, src)?;
    let mut buffered = BufReader::with_capacity(128 * 1024, reader);

    // .gz/.bz2/.xz 既可能是单个文件，也可能是 tar 包 —— 看内容，不看扩展名
    if matches!(kind, Kind::Gz | Kind::Bz2 | Kind::Xz) {
        let is_tar = {
            let buf = buffered.fill_buf()?;
            buf.len() > 262 && &buf[257..262] == b"ustar"
        };
        if !is_tar {
            let name = src
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "output".into());
            let stem = name.rsplit_once('.').map(|(a, _)| a.to_string()).unwrap_or(name);
            let mut sink = Sink::new(dest, limits, out);
            return sink.write_stream(&stem, buffered);
        }
    }

    let mut ar = tar::Archive::new(buffered);
    for entry in ar.entries()? {
        let mut e = entry?;
        let raw = e.path_bytes().to_vec();
        let name = String::from_utf8_lossy(&raw).to_string();
        let is_dir = e.header().entry_type().is_dir();
        // 先跳过垃圾文件，垃圾不该出现在任何清单里
        if is_junk(&name) || is_dir {
            let mut sink = Sink::new(dest, limits, out);
            if is_dir {
                sink.mkdir(&name);
            } else {
                sink.ensure_only(&name);
            }
            continue;
        }
        // 可执行权限位也算可执行内容
        {
            if let Ok(mode) = e.header().mode() {
                if mode & 0o111 != 0 {
                    if let Some(k) = executable_kind(&name) {
                        out.executables.push((name.clone(), k));
                    } else {
                        out.executables.push((name.clone(), "带可执行权限位的文件 (chmod +x)"));
                    }
                } else if let Some(k) = executable_kind(&name) {
                    out.executables.push((name.clone(), k));
                }
            }
        }
        let mut sink = Sink::new(dest, limits, out);
        if is_dir {
            sink.mkdir(&name);
        } else {
            sink.write_stream(&name, &mut e)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- 7Z

fn sevenz_extract(src: &Path, dest: &Path, limits: &Limits, password: Option<&str>, out: &mut Outcome) -> Result<()> {
    let pw = match password {
        Some(p) => sevenz_rust2::Password::new(p),
        None => sevenz_rust2::Password::empty(),
    };
    let mut reader = sevenz_rust2::ArchiveReader::open(src, pw).map_err(|e| anyhow!("打开 7Z 失败：{e}"))?;

    let mut failure: Option<anyhow::Error> = None;
    let root = dest.to_path_buf();
    let lim = limits.clone();
    let mut local = Outcome::default();

    let res = reader.for_each_entries(|entry, r| {
        if entry.is_directory {
            let mut sink = Sink::new(&root, &lim, &mut local);
            sink.mkdir(&entry.name);
            return Ok(true);
        }
        let mut sink = Sink::new(&root, &lim, &mut local);
        match sink.write_stream(&entry.name, r) {
            Ok(()) => Ok(true),
            Err(e) => {
                failure = Some(e);
                Ok(false)
            }
        }
    });

    out.files += local.files;
    out.dirs += local.dirs;
    out.bytes += local.bytes;
    out.junk_skipped += local.junk_skipped;
    out.traversal_blocked += local.traversal_blocked;
    out.executables.extend(local.executables);

    if let Some(e) = failure {
        return Err(e);
    }
    res.map_err(|e| anyhow!("7Z 解压失败：{e}"))?;
    Ok(())
}

// ---------------------------------------------------------------- 入口

pub fn extract(
    kind: Kind,
    src: &Path,
    dest: &Path,
    limits: &Limits,
    password: Option<&str>,
    _force: bool,
) -> Result<Outcome> {
    fs::create_dir_all(dest)?;
    match kind {
        #[cfg(feature = "rar")]
        Kind::Rar | Kind::Rar4 => rar_extract(src, dest, limits, password),
        #[cfg(not(feature = "rar"))]
        Kind::Rar | Kind::Rar4 => Err(anyhow!(
            "这个构建没有编入 RAR 支持（去掉 UnRAR 的自由软件版）。\
             装带 rar 特性的构建即可：cargo install --features rar"
        )),
        Kind::Zip => {
            let mut out = Outcome::default();
            zip_extract(src, dest, limits, password, &mut out)?;
            Ok(out)
        }
        Kind::SevenZ => {
            let mut out = Outcome::default();
            sevenz_extract(src, dest, limits, password, &mut out)?;
            Ok(out)
        }
        Kind::Tar | Kind::Gz | Kind::Bz2 | Kind::Xz => {
            let mut out = Outcome::default();
            tar_like_extract(kind, src, dest, limits, &mut out)?;
            Ok(out)
        }
        _ => Err(anyhow!("这个格式暂不支持解压：{}", kind.label())),
    }
}

/// unrar 的 FileHeader 里我们需要的最小字段
#[cfg(feature = "rar")]
trait CloneInfo {
    fn clone_info(&self) -> (String, u64, bool, bool);
}

#[cfg(feature = "rar")]
impl CloneInfo for unrar::FileHeader {
    fn clone_info(&self) -> (String, u64, bool, bool) {
        (
            self.filename.to_string_lossy().to_string(),
            self.unpacked_size,
            self.is_directory(),
            self.is_encrypted(),
        )
    }
}
