use std::process::Command;
use std::env;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::Write;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let target = env::var("TARGET").unwrap();
    
    // Determinar la arquitectura de destino
    let arch = if target.contains("x86_64") {
        println!("cargo:rustc-cfg=target_arch=\"x64\"");
        "x64"
    } else {
        println!("cargo:rustc-cfg=target_arch=\"x86\"");
        "x86"
    };
    
    // Generar recursos según arquitectura
    compile_resources(arch);
    
    // Preparar estructura para el instalador
    prepare_installer_structure(arch);
    
    // Generar .env para desarrollo si no existe
    generate_dev_env();
    
    // Verificar y registrar iconos
    register_resources();
}

fn compile_resources(arch: &str) {
    let dist_dir = Path::new("dist").join(arch);
    create_dir_if_not_exists(&dist_dir);
    
    // Copiar DLLs y dependencias
    copy_dependencies(&dist_dir, arch);
}

fn copy_dependencies(dist_dir: &Path, arch: &str) {
    // Lista de dependencias potenciales basada en los módulos
    let deps = vec![
        format!("yara-{}.dll", arch),
        format!("radare2-{}.dll", arch),
        "libcrypto.dll",
        "libssl.dll",
    ];
    
    // Posibles ubicaciones de las dependencias
    let search_paths = vec![
        format!("deps/{}", arch),
        format!("yara-engine/deps/{}", arch),
        format!("radare2-analyzer/deps/{}", arch),
        format!("C:/Program Files/YARA/bin"),
        format!("C:/Program Files (x86)/YARA/bin"),
        format!("C:/Program Files/radare2/bin"),
        format!("C:/Program Files (x86)/radare2/bin"),
    ];
    
    // Buscar y copiar cada dependencia
    for dep in deps {
        let mut found = false;
        
        for search_path in &search_paths {
            let source_path = Path::new(&search_path).join(&dep);
            if source_path.exists() {
                let dest_path = dist_dir.join(&dep);
                println!("cargo:warning=Copiando {} a {:?}", dep, dest_path);
                
                match fs::copy(&source_path, &dest_path) {
                    Ok(_) => {
                        found = true;
                        break;
                    },
                    Err(e) => println!("cargo:warning=Error al copiar {}: {}", dep, e),
                }
            }
        }
        
        if !found {
            println!("cargo:warning=No se encontró la dependencia: {}", dep);
        }
    }
}

fn prepare_installer_structure(arch: &str) {
    // Definir directorios
    let installer_dir = Path::new("installer");
    let modules_dir = installer_dir.join("modules");
    let signatures_dir = installer_dir.join("signatures");
    
    // Crear estructura de directorios para el instalador
    create_dir_if_not_exists(installer_dir);
    create_dir_if_not_exists(&modules_dir);
    create_dir_if_not_exists(&signatures_dir);
    
    // Crear directorios de módulos
    let modules = vec![
        "yara-engine",
        "radare2-analyzer",
        "realtime-monitor"
    ];
    
    for module in modules {
        create_dir_if_not_exists(&modules_dir.join(module));
    }
    
    // Copiar módulos y dependencias al directorio del instalador
    let dist_dir = Path::new("dist").join(arch);
    
    if dist_dir.exists() {
        for entry in fs::read_dir(dist_dir).unwrap() {
            if let Ok(entry) = entry {
                let filename = entry.file_name();
                let filename_str = filename.to_string_lossy();
                
                // Determinar el directorio de destino según el nombre del archivo
                let dest_dir = if filename_str.contains("yara") {
                    modules_dir.join("yara-engine")
                } else if filename_str.contains("radare2") {
                    modules_dir.join("radare2-analyzer")
                } else {
                    modules_dir.clone()
                };
                
                let source_path = entry.path();
                let dest_path = dest_dir.join(filename);
                
                // Copiar el archivo
                if let Err(e) = fs::copy(&source_path, &dest_path) {
                    println!("cargo:warning=Error al copiar {:?} a {:?}: {}", source_path, dest_path, e);
                }
            }
        }
    }
    
    // Copiar reglas YARA de ejemplo
    let signatures_src_dir = Path::new("signatures");
    if signatures_src_dir.exists() {
        copy_directory_contents(signatures_src_dir, &signatures_dir);
    }
    
    // Generar archivo de configuración para el instalador si no existe
    let module_config_path = installer_dir.join("module-config.json");
    if !module_config_path.exists() {
        generate_module_config(&module_config_path, arch);
    }
}

fn generate_dev_env() {
    let env_path = Path::new(".env");
    
    if !env_path.exists() {
        let env_example_path = Path::new(".env.example");
        
        if env_example_path.exists() {
            if let Err(e) = fs::copy(env_example_path, env_path) {
                println!("cargo:warning=Error al crear .env desde .env.example: {}", e);
            }
        } else {
            // Crear .env con valores por defecto
            if let Ok(mut file) = File::create(env_path) {
                let content = r#"# Archivo de entorno para desarrollo
AMARU_ROOT=.
YARA_RULES_PATH=./signatures
QUARANTINE_PATH=./quarantine
LOGS_PATH=./logs
ENABLE_REALTIME_PROTECTION=true
ENABLE_HEURISTIC_ANALYSIS=true
LOW_RESOURCE_MODE=false
"#;
                if let Err(e) = file.write_all(content.as_bytes()) {
                    println!("cargo:warning=Error al escribir .env: {}", e);
                }
            }
        }
    }
}

fn register_resources() {
    // Convertir SVG a ICO si se encuentra un archivo SVG y no existe el ICO
    let icons = [
        ("assets/Amaru-logo.svg", "installer/amaru-app.ico"),
        ("Amaru-logo.svg", "amaru-app.ico"),
        ("Amaru-isotipo-white.svg", "amaru-isotipo-white.ico")
    ];
    
    for (source, target) in &icons {
        let source_path = Path::new(source);
        let target_path = Path::new(target);
        
        if source_path.exists() && !target_path.exists() {
            // Intentar convertir con ImageMagick si está disponible
            let result = Command::new("magick")
                .args(&[
                    "convert",
                    source,
                    "-define",
                    "icon:auto-resize=256,128,64,48,32,16",
                    target
                ])
                .status();
                
            match result {
                Ok(status) if status.success() => {
                    println!("cargo:warning=Convertido {} a {}", source, target);
                },
                _ => {
                    println!("cargo:warning=No se pudo convertir {} a {} (ImageMagick no disponible)", source, target);
                }
            }
        }
    }
}

fn create_dir_if_not_exists(path: &Path) {
    if !path.exists() {
        if let Err(e) = fs::create_dir_all(path) {
            println!("cargo:warning=Error al crear directorio {:?}: {}", path, e);
        }
    }
}

fn copy_directory_contents(src: &Path, dst: &Path) {
    if !dst.exists() {
        create_dir_if_not_exists(dst);
    }
    
    if let Ok(entries) = fs::read_dir(src) {
        for entry in entries {
            if let Ok(entry) = entry {
                let src_path = entry.path();
                let dst_path = dst.join(entry.file_name());
                
                if src_path.is_file() {
                    if let Err(e) = fs::copy(&src_path, &dst_path) {
                        println!("cargo:warning=Error al copiar {:?} a {:?}: {}", src_path, dst_path, e);
                    }
                } else if src_path.is_dir() {
                    copy_directory_contents(&src_path, &dst_path);
                }
            }
        }
    }
}

fn generate_module_config(path: &Path, arch: &str) {
    let config = format!(r#"{{
  "modules": {{
    "yara-engine": {{
      "version": "1.0.0",
      "description": "Motor de reglas YARA para detección basada en patrones",
      "dependencies": [
        "yara-{0}.dll",
        "libyara.dll"
      ],
      "source_path": "yara-engine",
      "install_path": "modules/yara-engine",
      "data_paths": [
        "signatures/official",
        "signatures/custom"
      ]
    }},
    "radare2-analyzer": {{
      "version": "1.0.0",
      "description": "Analizador estático con Radare2 para inspección de binarios",
      "dependencies": [
        "radare2-{0}.dll",
        "r_core.dll"
      ],
      "source_path": "radare2-analyzer",
      "install_path": "modules/radare2-analyzer",
      "data_paths": []
    }},
    "realtime-monitor": {{
      "version": "1.0.0",
      "description": "Monitor en tiempo real para protección continua del sistema",
      "dependencies": [],
      "source_path": "realtime-monitor",
      "install_path": "modules/realtime-monitor",
      "data_paths": []
    }},
    "heuristic-analyzer": {{
      "version": "1.0.0",
      "description": "Analizador heurístico para detección avanzada de amenazas",
      "dependencies": [],
      "source_path": "yara-engine/src/heuristic.rs",
      "install_path": "modules/yara-engine",
      "data_paths": []
    }}
  }},
  "paths": {{
    "config": "config.toml",
    "logs": "logs",
    "quarantine": "quarantine",
    "signatures": "signatures",
    "temp": "temp",
    "service": "service"
  }},
  "environment_variables": {{
    "AMARU_ROOT": "%INSTALLDIR%",
    "YARA_RULES_PATH": "%INSTALLDIR%\\signatures",
    "QUARANTINE_PATH": "%INSTALLDIR%\\quarantine",
    "LOGS_PATH": "%INSTALLDIR%\\logs",
    "ENABLE_REALTIME_PROTECTION": "true",
    "ENABLE_HEURISTIC_ANALYSIS": "true",
    "LOW_RESOURCE_MODE": "false"
  }}
}}"#, arch);

    if let Ok(mut file) = File::create(path) {
        if let Err(e) = file.write_all(config.as_bytes()) {
            println!("cargo:warning=Error al crear module-config.json: {}", e);
        }
    }
} 