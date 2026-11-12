//! aunzip 桌面壳 —— 窗口 + 三个命令，逻辑全部复用 `agent_unzip` 库。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};

/// 拍照体检：不解压，只读头部与目录
#[tauri::command]
fn inspect(path: String) -> Result<agent_unzip::Inspection, String> {
    agent_unzip::inspect(Path::new(&path)).map_err(|e| format!("{e:#}"))
}

/// 真正解压，返回结果卡片需要的一切
#[tauri::command]
fn unpack(
    path: String,
    dest: Option<String>,
    password: Option<String>,
    force: bool,
) -> Result<agent_unzip::Report, String> {
    let d = dest.map(PathBuf::from);
    agent_unzip::unpack(
        Path::new(&path),
        d.as_deref(),
        password.as_deref(),
        force,
    )
    .map_err(|e| format!("{e:#}"))
}

/// 在系统文件管理器里定位结果目录
///
/// 不使用 fork 子进程：App Sandbox 下 `exec` 会被直接拒绝。
/// macOS 走 NSWorkspace（进程内调用），Windows 走 explorer /select。
#[tauri::command]
fn reveal(path: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use objc2_app_kit::NSWorkspace;
        use objc2_foundation::{NSArray, NSString, NSURL};

        let p = NSString::from_str(&path);
        let url = NSURL::fileURLWithPath(&p);
        let urls = NSArray::from_retained_slice(&[url]);
        let ws = unsafe { NSWorkspace::sharedWorkspace() };

        // 路径不存在时退化成打开父目录
        if !std::path::Path::new(&path).exists() {
            let parent = std::path::Path::new(&path)
                .parent()
                .map(|d| d.display().to_string())
                .unwrap_or_else(|| path.clone());
            let p2 = NSString::from_str(&parent);
            let url2 = NSURL::fileURLWithPath(&p2);
            unsafe { ws.openURL(&url2) };
            return Ok(());
        }

        unsafe { ws.activateFileViewerSelectingURLs(&urls) };
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg("/select,")
            .arg(&path)
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(&path)
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
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
        .expect("aunzip 启动失败");
}
