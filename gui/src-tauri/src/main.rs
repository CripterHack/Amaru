#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

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
