//! 链接期修补：unrar_sys 在 Windows 上会调用注册表与 CryptoAPI，
//! 但它的 build script 没有声明这些系统库，导致 MSVC 链接失败（LNK2019）。
//! 这里替它补上，用户 cargo install 时也不需要额外配置。
fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "windows" {
        println!("cargo:rustc-link-lib=advapi32"); // Reg* / OpenProcessToken
        println!("cargo:rustc-link-lib=crypt32"); // CryptAcquireContextW / CryptGenRandom
    }
}
