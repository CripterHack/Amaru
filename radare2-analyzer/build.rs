use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Verificar si r2 está instalado
    if !is_radare2_installed() {
        println!("cargo:warning=Radare2 no parece estar instalado. El analizador puede no funcionar correctamente.");
        println!("cargo:warning=Por favor instale Radare2 desde: https://github.com/radareorg/radare2/releases");
        
        // En Windows, podemos sugerir la descarga automática
        if cfg!(windows) {
            println!("cargo:warning=En Windows, ejecute: cargo:warning=curl.exe -L -o radare2_installer.exe https://github.com/radareorg/radare2/releases/download/5.8.8/radare2_installer-msvc_64.exe");
            println!("cargo:warning=Y luego ejecute el instalador descargado.");
        }
    } else {
        println!("cargo:warning=Radare2 encontrado correctamente.");
    }
}

fn is_radare2_installed() -> bool {
    let check_command = if cfg!(windows) {
        Command::new("where")
            .arg("r2")
            .output()
    } else {
        Command::new("which")
            .arg("r2")
            .output()
    };

    match check_command {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
} 