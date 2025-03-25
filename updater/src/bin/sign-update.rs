use std::path::{Path, PathBuf};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use ed25519_dalek::{SigningKey, Signer};
use sha2::{Sha256, Digest};
use serde_json::json;
use amaru_updater::{RuleUpdate, RuleFile, Signature};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("Uso: sign-update <directorio-reglas> <version> <url-base> <clave-privada>");
        std::process::exit(1);
    }

    let rules_dir = PathBuf::from(&args[1]);
    let version = &args[2];
    let base_url = &args[3];
    let private_key_file = &args[4];

    // Cargar clave privada
    let private_key_bytes = fs::read(private_key_file).expect("Error al leer clave privada");
    let signing_key = SigningKey::from_bytes(&private_key_bytes.try_into().unwrap())
        .expect("Clave privada inválida");

    // Recolectar archivos de reglas
    let mut rules = Vec::new();
    let mut signatures = Vec::new();
    collect_rules(&rules_dir, &rules_dir, &mut rules, &mut signatures, &signing_key, base_url);

    // Crear actualización
    let update = RuleUpdate {
        version: version.clone(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        rules,
        signatures,
        rollback_version: None,
    };

    // Guardar actualización
    let update_json = serde_json::to_string_pretty(&update).expect("Error al serializar actualización");
    fs::write("update.json", update_json).expect("Error al guardar actualización");

    // Crear manifiesto
    let manifest = json!({
        "current_version": version,
        "available_version": version,
        "update_url": format!("{}/update.json", base_url),
        "public_key": hex::encode(signing_key.verifying_key().as_bytes())
    });

    let manifest_json = serde_json::to_string_pretty(&manifest).expect("Error al serializar manifiesto");
    fs::write("manifest.json", manifest_json).expect("Error al guardar manifiesto");

    println!("✅ Actualización firmada correctamente");
    println!("📦 Archivos generados:");
    println!("   - update.json");
    println!("   - manifest.json");
}

fn collect_rules(
    base_dir: &Path,
    current_dir: &Path,
    rules: &mut Vec<RuleFile>,
    signatures: &mut Vec<Signature>,
    signing_key: &SigningKey,
    base_url: &str,
) {
    let entries = fs::read_dir(current_dir).expect("Error al leer directorio");
    
    for entry in entries {
        let entry = entry.expect("Error al leer entrada");
        let path = entry.path();
        
        if path.is_dir() {
            collect_rules(base_dir, &path, rules, signatures, signing_key, base_url);
            continue;
        }

        // Solo procesar archivos .yar
        if path.extension().map_or(false, |ext| ext == "yar") {
            let relative_path = path.strip_prefix(base_dir).unwrap();
            let content = fs::read(&path).expect("Error al leer archivo");
            
            // Calcular hash
            let mut hasher = Sha256::new();
            hasher.update(&content);
            let hash = format!("{:x}", hasher.finalize());
            
            // Firmar contenido
            let signature = signing_key.sign(&content);
            
            rules.push(RuleFile {
                path: relative_path.to_string_lossy().into_owned(),
                hash,
                url: format!("{}/rules/{}", base_url, relative_path.to_string_lossy()),
            });

            signatures.push(Signature {
                file_path: relative_path.to_string_lossy().into_owned(),
                signature: signature.to_bytes().to_vec(),
            });
        }
    }
} 