//! pak 桌面壳 —— 窗口 + 三个命令，逻辑全部复用 `pak` 库。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};

/// 拍照体检：不解压，只读头部与目录
#[tauri::command]
fn inspect(path: String) -> Result<pak::Inspection, String> {
    pak::inspect(Path::new(&path)).map_err(|e| format!("{e:#}"))
}

/// 真正解压，返回结果卡片需要的一切
#[tauri::command]
fn unpack(
    path: String,
    dest: Option<String>,
    password: Option<String>,
    force: bool,
) -> Result<pak::Report, String> {
    let d = dest.map(PathBuf::from);
    pak::unpack(
        Path::new(&path),
        d.as_deref(),
        password.as_deref(),
        force,
    )
    .map_err(|e| format!("{e:#}"))
}

/// 在系统文件管理器里定位结果目录
#[tauri::command]
fn reveal(path: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(&path);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("explorer");
        c.arg(&path);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(&path);
        c
    };
    cmd.spawn().map_err(|e| e.to_string())?;
    Ok(())
}

/// 默认的“解到哪”：压缩包旁边的同名文件夹
#[tauri::command]
fn default_dest(path: String) -> String {
    let p = Path::new(&path);
    p.parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![inspect, unpack, reveal, default_dest])
        .run(tauri::generate_context!())
        .expect("pak 启动失败");
}
