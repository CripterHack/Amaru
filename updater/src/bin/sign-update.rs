use ed25519_dalek::{Signer, SigningKey};
use reqwest::Url;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use updater::{RuleFile, RuleUpdate, Signature};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "Uso: sign-update <directorio-reglas> <version> <url-base> <clave-privada>".into(),
        );
    }
    let dir = Path::new(&args[1]);
    let version = &args[2];
    semver::Version::parse(version)?;
    let base = Url::parse(&format!("{}/", args[3].trim_end_matches('/')))?;
    let private_key = fs::read(&args[4])?;
    let seed = private_key
        .as_slice()
        .try_into()
        .map_err(|_| "Se requieren 32 bytes de clave privada")?;
    let key = SigningKey::from_bytes(seed);

    let mut update = RuleUpdate {
        version: version.clone(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        rules: Vec::new(),
        signatures: Vec::new(),
        rollback_version: None,
    };
    let mut pending = vec![dir.to_owned()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && matches!(
                    path.extension().and_then(|v| v.to_str()),
                    Some("yar" | "yara")
                )
            {
                let name = path
                    .strip_prefix(dir)?
                    .to_str()
                    .ok_or("Ruta de regla no UTF-8")?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                let content = fs::read(path)?;
                let mut url = base.clone();
                url.path_segments_mut()
                    .map_err(|_| "URL de base inválida")?
                    .pop_if_empty()
                    .push("rules")
                    .extend(name.split('/'));
                update.rules.push(RuleFile {
                    path: name.clone(),
                    hash: hex::encode(Sha256::digest(&content)),
                    url: url.into(),
                });
                update.signatures.push(Signature {
                    file_path: name,
                    signature: key.sign(&content).to_bytes().to_vec(),
                });
            }
        }
    }
    update.validate_structure()?;
    let manifest = json!({
        "current_version": version,
        "available_version": version,
        "update_url": base.join("update.json")?.as_str(),
        "public_key": hex::encode(key.verifying_key().as_bytes())
    });
    fs::write("update.json", serde_json::to_vec_pretty(&update)?)?;
    fs::write("manifest.json", serde_json::to_vec_pretty(&manifest)?)?;
    println!("Actualización firmada: update.json y manifest.json");
    Ok(())
}
