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
            println!("cargo:warning=En Windows, ejecute los siguientes comandos:");
            println!("cargo:warning=1. curl.exe -L -o radare2_installer.exe https://github.com/radareorg/radare2/releases/download/5.8.8/radare2_installer-msvc_64.exe");
            println!("cargo:warning=2. Ejecute radare2_installer.exe");
            println!("cargo:warning=3. Agregue C:\\Program Files\\radare2 al PATH del sistema");
        } else {
            println!("cargo:warning=En Linux/macOS, use el gestor de paquetes de su sistema o compile desde el código fuente.");
        }
    } else {
        // Verificar la versión de r2
        match get_radare2_version() {
            Ok(version) => {
                println!("cargo:warning=Radare2 versión {} encontrada.", version);
                if !is_version_compatible(&version) {
                    println!("cargo:warning=Se recomienda Radare2 versión 5.8.0 o superior.");
                }
            }
            Err(e) => {
                println!("cargo:warning=No se pudo determinar la versión de Radare2: {}", e);
            }
        }
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

fn get_radare2_version() -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("r2")
        .arg("-v")
        .output()?;
        
    if !output.status.success() {
        return Err("Failed to execute r2 -v".into());
    }
    
    let version_str = String::from_utf8(output.stdout)?;
    let version = version_str
        .lines()
        .next()
        .ok_or("No version output")?
        .trim()
        .to_string();
        
    Ok(version)
}

fn is_version_compatible(version: &str) -> bool {
    // Extraer el número de versión (asumiendo formato x.y.z)
    let version_parts: Vec<&str> = version.split('.').collect();
    if version_parts.len() < 2 {
        return false;
    }
    
    // Convertir a números
    if let (Ok(major), Ok(minor)) = (
        version_parts[0].parse::<u32>(),
        version_parts[1].parse::<u32>(),
    ) {
        // Requerir 5.8.0 o superior
        major > 5 || (major == 5 && minor >= 8)
    } else {
        false
    }
} 