use std::path::{Path, PathBuf};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use tokio::fs as tokio_fs;
use ed25519_dalek::{Verifier, VerifyingKey};
use sha2::{Sha256, Digest};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UpdateError {
    #[error("Error de red: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Error de firma: {0}")]
    Signature(String),
    #[error("Error de sistema de archivos: {0}")]
    Filesystem(#[from] std::io::Error),
    #[error("Error de deserialización: {0}")]
    Deserialize(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleUpdate {
    version: String,
    timestamp: u64,
    rules: Vec<RuleFile>,
    signatures: Vec<Signature>,
    rollback_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleFile {
    path: String,
    hash: String,
    url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    file_path: String,
    signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateManifest {
    current_version: String,
    available_version: String,
    update_url: String,
    public_key: String,
}

pub struct Updater {
    rules_dir: PathBuf,
    backup_dir: PathBuf,
    public_key: VerifyingKey,
    client: reqwest::Client,
}

impl Updater {
    pub fn new(rules_dir: impl Into<PathBuf>, backup_dir: impl Into<PathBuf>, public_key: &[u8]) -> Result<Self, UpdateError> {
        let public_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| UpdateError::Signature(e.to_string()))?;
        
        Ok(Self {
            rules_dir: rules_dir.into(),
            backup_dir: backup_dir.into(),
            public_key,
            client: reqwest::Client::new(),
        })
    }

    pub async fn check_updates(&self, manifest_url: &str) -> Result<Option<RuleUpdate>, UpdateError> {
        let manifest: UpdateManifest = self.client
            .get(manifest_url)
            .send()
            .await?
            .json()
            .await?;

        let current_version = self.get_current_version()?;
        if manifest.available_version <= current_version {
            return Ok(None);
        }

        let update: RuleUpdate = self.client
            .get(&manifest.update_url)
            .send()
            .await?
            .json()
            .await?;

        Ok(Some(update))
    }

    pub async fn apply_update(&self, update: RuleUpdate) -> Result<(), UpdateError> {
        // Crear backup antes de actualizar
        let backup_path = self.create_backup().await?;

        // Verificar firmas
        self.verify_signatures(&update)?;

        // Descargar y aplicar nuevas reglas
        for rule in &update.rules {
            let content = self.client
                .get(&rule.url)
                .send()
                .await?
                .bytes()
                .await?;

            // Verificar hash
            let mut hasher = Sha256::new();
            hasher.update(&content);
            let hash = format!("{:x}", hasher.finalize());
            if hash != rule.hash {
                self.rollback(backup_path).await?;
                return Err(UpdateError::Signature("Hash no coincide".into()));
            }

            let rule_path = self.rules_dir.join(&rule.path);
            if let Some(parent) = rule_path.parent() {
                tokio_fs::create_dir_all(parent).await?;
            }
            tokio_fs::write(rule_path, content).await?;
        }

        // Actualizar versión
        self.save_version(&update.version)?;

        Ok(())
    }

    async fn create_backup(&self) -> Result<PathBuf, UpdateError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let backup_path = self.backup_dir.join(format!("backup_{}", timestamp));
        tokio_fs::create_dir_all(&backup_path).await?;
        
        let mut stack = vec![self.rules_dir.clone()];
        while let Some(dir) = stack.pop() {
            let entries = fs::read_dir(dir)?;
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                let relative = path.strip_prefix(&self.rules_dir).unwrap();
                let backup_file = backup_path.join(relative);

                if path.is_dir() {
                    stack.push(path);
                    tokio_fs::create_dir_all(backup_file).await?;
                } else {
                    tokio_fs::copy(&path, backup_file).await?;
                }
            }
        }

        Ok(backup_path)
    }

    async fn rollback(&self, backup_path: PathBuf) -> Result<(), UpdateError> {
        // Limpiar directorio actual
        let mut stack = vec![self.rules_dir.clone()];
        while let Some(dir) = stack.pop() {
            let entries = fs::read_dir(dir)?;
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path.clone());
                }
                tokio_fs::remove_file(path).await?;
            }
        }

        // Restaurar desde backup
        let mut stack = vec![backup_path.clone()];
        while let Some(dir) = stack.pop() {
            let entries = fs::read_dir(dir)?;
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                let relative = path.strip_prefix(&backup_path).unwrap();
                let restore_path = self.rules_dir.join(relative);

                if path.is_dir() {
                    stack.push(path);
                    tokio_fs::create_dir_all(restore_path).await?;
                } else {
                    tokio_fs::copy(&path, restore_path).await?;
                }
            }
        }

        Ok(())
    }

    fn verify_signatures(&self, update: &RuleUpdate) -> Result<(), UpdateError> {
        for signature in &update.signatures {
            let file_path = self.rules_dir.join(&signature.file_path);
            let content = fs::read(&file_path)?;
            
            self.public_key
                .verify(&content, &signature.signature.as_slice().try_into().unwrap())
                .map_err(|e| UpdateError::Signature(e.to_string()))?;
        }
        Ok(())
    }

    fn get_current_version(&self) -> Result<String, UpdateError> {
        let version_file = self.rules_dir.join("version.txt");
        if !version_file.exists() {
            return Ok("0.0.0".to_string());
        }
        Ok(fs::read_to_string(version_file)?.trim().to_string())
    }

    fn save_version(&self, version: &str) -> Result<(), UpdateError> {
        let version_file = self.rules_dir.join("version.txt");
        fs::write(version_file, version)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio;

    #[tokio::test]
    async fn test_backup_and_rollback() -> Result<(), UpdateError> {
        let rules_dir = tempdir()?;
        let backup_dir = tempdir()?;
        let test_file = rules_dir.path().join("test.yar");
        
        fs::write(&test_file, "rule test {}")?;

        let public_key = [0u8; 32];
        let updater = Updater::new(
            rules_dir.path(),
            backup_dir.path(),
            &public_key
        )?;

        let backup_path = updater.create_backup().await?;
        fs::remove_file(&test_file)?;
        updater.rollback(backup_path).await?;

        assert!(test_file.exists());
        assert_eq!(fs::read_to_string(&test_file)?, "rule test {}");

        Ok(())
    }
} 