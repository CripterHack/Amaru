use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    
    // Check if radare2 is installed
    let r2_path = find_radare2();
    if let Some(path) = r2_path {
        println!("cargo:rustc-env=RADARE2_PATH={}", path.to_string_lossy());
        println!("cargo:warning=Found radare2 at: {}", path.to_string_lossy());
    } else {
        println!("cargo:warning=radare2 not found. Analysis functionality will be limited.");
    }
}

fn find_radare2() -> Option<PathBuf> {
    // First check environment variable
    if let Ok(path) = env::var("AMARU_RADARE2_PATH") {
        let p = PathBuf::from(path).join("r2.exe");
        if p.exists() {
            return Some(p);
        }
    }
    
    // Check PATH
    if let Ok(output) = Command::new("where").arg("r2").output() {
        if output.status.success() {
            if let Ok(path) = String::from_utf8(output.stdout) {
                let path = path.trim().to_string();
                return Some(PathBuf::from(path));
            }
        }
    }
    
    // Fallback to common locations
    let common_locations = [
        r"C:\Program Files\radare2\bin\r2.exe",
        r"C:\radare2\bin\r2.exe",
    ];
    
    for location in common_locations.iter() {
        let path = PathBuf::from(location);
        if path.exists() {
            return Some(path);
        }
    }
    
    None
} 