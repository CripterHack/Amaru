use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Verificar si r2 está instalado
    if !is_radare2_installed() {
        println!("cargo:warning=Radare2 no parece estar instalado. El analizador puede no funcionar correctamente.");
        println!("cargo:warning=Por favor instale Radare2 desde: https://github.com/radareorg/radare2/releases");
        
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
    let number = version.split_ascii_whitespace().nth(1).unwrap_or_default();
    let version_parts: Vec<&str> = number.split('.').collect();
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