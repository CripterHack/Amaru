#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

// Resolve WaitOnAddress and WakeByAddress* from the Windows SDK before Tauri 1's
// transitive windows 0.37/0.39 import libraries can bind them to the enclave DLL.
#[cfg(windows)]
#[link(name = "synchronization")]
unsafe extern "system" {}

#[cfg(windows)]
mod desktop;
#[cfg(any(windows, test))]
mod session;

#[cfg(windows)]
fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--scheduled-quick-scan"))
    {
        if let Err(error) = desktop::run_scheduled() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    desktop::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Amaru Desktop requires Windows 11 x64.");
    std::process::exit(1);
}
