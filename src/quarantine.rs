use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::{Builder, NamedTempFile};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QuarantineError {
    #[error("Error de E/S: {0}")]
    Io(#[from] io::Error),

    #[error("Error de cifrado: {0}")]
    Encryption(String),

    #[error("Error de descifrado: {0}")]
    Decryption(String),

    #[error("Archivo no encontrado en cuarentena: {0}")]
    NotFound(String),

    #[error("Espacio insuficiente en cuarentena")]
    InsufficientSpace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Ruta original del archivo
    pub original_path: PathBuf,

    /// Nombre del archivo en cuarentena
    pub quarantine_name: String,

    /// Fecha de cuarentena
    pub quarantine_date: DateTime<Utc>,

    /// Hash del archivo original
    pub original_hash: String,

    /// Tamaño del archivo
    pub file_size: u64,

    /// Razón de la cuarentena
    pub reason: String,
}

#[derive(Clone)]
pub struct Quarantine {
    path: PathBuf,
    max_size: u64,
    retention_days: u32,
    encryption_key: [u8; 32],
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = NamedTempFile::new_in(path.parent().expect("file in quarantine directory"))?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)?;
    Ok(())
}

impl Quarantine {
    pub fn new<P: AsRef<Path>>(path: P, max_size: u64, retention_days: u32) -> io::Result<Self> {
        fs::create_dir_all(&path)?;
        let path = fs::canonicalize(path)?;
        let _lock = Self::lock_dir(&path)?;
        let key_path = path.join(".key");
        let encryption_key = match fs::read(&key_path) {
            Ok(bytes) => bytes.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid quarantine key")
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if path.join("metadata.json").exists()
                    || fs::read_dir(&path)?.any(|e| {
                        e.is_ok_and(|e| e.path().extension().is_some_and(|ext| ext == "quar"))
                    })
                {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "Missing key for existing quarantine",
                    ));
                }
                let key = rand::random::<[u8; 32]>();
                atomic_write(&key_path, &key)?;
                key
            }
            Err(e) => return Err(e),
        };
        Ok(Self {
            path,
            max_size,
            retention_days,
            encryption_key,
        })
    }

    fn lock_dir(path: &Path) -> io::Result<File> {
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.join(".lock"))?;
        file.lock()?;
        Ok(file)
    }

    pub fn quarantine_file<P: AsRef<Path>>(
        &self,
        path: P,
        reason: &str,
    ) -> Result<QuarantineEntry, QuarantineError> {
        self.capture(path.as_ref(), reason, None)
    }

    pub fn quarantine_if_unchanged<P: AsRef<Path>>(
        &self,
        path: P,
        reason: &str,
        sha256: &str,
    ) -> Result<QuarantineEntry, QuarantineError> {
        self.capture(path.as_ref(), reason, Some(sha256))
    }

    fn capture(
        &self,
        path: &Path,
        reason: &str,
        expected_hash: Option<&str>,
    ) -> Result<QuarantineEntry, QuarantineError> {
        let _lock = Self::lock_dir(&self.path)?;
        if !fs::symlink_metadata(path)?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Only regular files can be quarantined",
            )
            .into());
        }
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("Missing filename"))?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let original = fs::canonicalize(parent)?.join(name);
        if original.starts_with(&self.path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot quarantine the quarantine store",
            )
            .into());
        }
        let mut entries = self.list_entries()?;
        let used = entries
            .iter()
            .fold(0u64, |size, entry| size.saturating_add(entry.file_size));
        let available = self.max_size.saturating_sub(used);
        if original.metadata()?.len() > available {
            return Err(QuarantineError::InsufficientSpace);
        }

        // Claim the directory entry on its own volume. Never unlink a new file that
        // has appeared at the scanned path while the evidence was being processed.
        let parent = original
            .parent()
            .ok_or_else(|| io::Error::other("Missing parent directory"))?;
        let staging = Builder::new()
            .prefix(".amaru-quarantine-")
            .tempdir_in(parent)?;
        let pending = staging.path().join("pending");
        fs::rename(&original, &pending)?;
        let result = (|| {
            if !fs::symlink_metadata(&pending)?.is_file() {
                return Err(io::Error::other("File changed before quarantine").into());
            }
            let mut bytes = Vec::new();
            File::open(&pending)?
                .take(available.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > available {
                return Err(QuarantineError::InsufficientSpace);
            }
            let hash = Sha256::digest(&bytes);
            if expected_hash
                .is_some_and(|expected| !expected.eq_ignore_ascii_case(&hex::encode(hash)))
            {
                return Err(io::Error::other("File changed since analysis").into());
            }
            let entry = QuarantineEntry {
                original_path: original.clone(),
                quarantine_name: format!("v2-{:032x}.quar", rand::random::<u128>()),
                quarantine_date: Utc::now(),
                original_hash: BASE64.encode(hash),
                file_size: bytes.len() as u64,
                reason: reason.to_owned(),
            };
            let aad = serde_json::to_vec(&entry).map_err(io::Error::other)?;
            let nonce = rand::random::<[u8; 12]>();
            let cipher = Aes256Gcm::new((&self.encryption_key).into());
            let sealed = cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &bytes,
                        aad: &aad,
                    },
                )
                .map_err(|_| QuarantineError::Encryption("AES-GCM failed".into()))?;
            let mut blob = NamedTempFile::new_in(&self.path)?;
            blob.write_all(&nonce)?;
            blob.write_all(&sealed)?;
            blob.as_file().sync_all()?;
            let target = self.path.join(&entry.quarantine_name);
            blob.persist_noclobber(&target).map_err(|err| err.error)?;
            entries.push(entry.clone());
            if let Err(err) = self.store(&entries) {
                fs::remove_file(target)?;
                return Err(err.into());
            }
            Ok(entry)
        })();
        if let Err(err) = result {
            // Recovery uses a no-clobber link. Keep the private staging directory
            // if the original name is already occupied or the filesystem rejects links.
            if let Err(recovery) = fs::hard_link(&pending, &original) {
                let saved = staging.into_path();
                return Err(io::Error::other(format!(
                    "{err}. Original retained at {}: {recovery}",
                    saved.join("pending").display()
                ))
                .into());
            }
            return Err(err);
        }
        fs::remove_file(&pending)?;
        result
    }

    pub fn restore_file(&self, entry: &QuarantineEntry) -> Result<(), QuarantineError> {
        self.restore_file_by_id(&entry.quarantine_name).map(|_| ())
    }

    pub fn restore_file_by_id(&self, id: &str) -> Result<PathBuf, QuarantineError> {
        let _lock = Self::lock_dir(&self.path)?;
        let entries = self.list_entries()?;
        let entry = entries
            .iter()
            .find(|e| e.quarantine_name == id)
            .ok_or_else(|| QuarantineError::NotFound(id.to_owned()))?;
        let path = self.path.join(id);
        let sealed = fs::read(&path)?;
        if sealed.len() < 28 {
            return Err(QuarantineError::Decryption(
                "Truncated quarantine file".into(),
            ));
        }
        let (nonce, ciphertext) = sealed.split_at(12);
        let aad = if id.starts_with("v2-") {
            serde_json::to_vec(entry).map_err(io::Error::other)?
        } else {
            Vec::new()
        };
        let cipher = Aes256Gcm::new((&self.encryption_key).into());
        let bytes = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| QuarantineError::Decryption("Authentication failed".into()))?;
        if BASE64.encode(Sha256::digest(&bytes)) != entry.original_hash {
            return Err(QuarantineError::Decryption(
                "Hash verification failed".into(),
            ));
        }
        let dest = entry.original_path.clone();
        let parent = dest
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let mut file = NamedTempFile::new_in(parent)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(&dest).map_err(|err| err.error)?;
        self.discard(entries, id)?;
        Ok(dest)
    }

    pub fn delete_file(&self, entry: &QuarantineEntry) -> Result<(), QuarantineError> {
        self.delete_file_by_id(&entry.quarantine_name)
    }

    pub fn delete_file_by_id(&self, id: &str) -> Result<(), QuarantineError> {
        let _lock = Self::lock_dir(&self.path)?;
        self.discard(self.list_entries()?, id)
    }

    fn discard(&self, mut entries: Vec<QuarantineEntry>, id: &str) -> Result<(), QuarantineError> {
        let index = entries
            .iter()
            .position(|e| e.quarantine_name == id)
            .ok_or_else(|| QuarantineError::NotFound(id.to_owned()))?;
        entries.remove(index);
        self.store(&entries)?;
        fs::remove_file(self.path.join(id))?;
        Ok(())
    }

    pub fn cleanup(&self) -> io::Result<()> {
        let _lock = Self::lock_dir(&self.path)?;
        let now = Utc::now();
        let mut entries = self.list_entries()?;
        let mut expired = Vec::new();
        entries.retain(|entry| {
            if (now - entry.quarantine_date).num_days() >= i64::from(self.retention_days) {
                expired.push(entry.quarantine_name.clone());
                false
            } else {
                true
            }
        });
        if !expired.is_empty() {
            self.store(&entries)?;
            for id in expired {
                fs::remove_file(self.path.join(id))?;
            }
        }
        Ok(())
    }

    pub fn list_entries(&self) -> io::Result<Vec<QuarantineEntry>> {
        let bytes = match fs::read(self.path.join("metadata.json")) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };
        let entries: Vec<QuarantineEntry> = serde_json::from_slice(&bytes)?;
        for entry in &entries {
            let id = &entry.quarantine_name;
            if !id.ends_with(".quar")
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid quarantine identifier",
                ));
            }
        }
        Ok(entries)
    }

    fn store(&self, entries: &[QuarantineEntry]) -> io::Result<()> {
        atomic_write(
            &self.path.join("metadata.json"),
            &serde_json::to_vec_pretty(entries)?,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_quarantine_file() -> Result<(), QuarantineError> {
        let temp_dir = tempdir()?;
        let quarantine = Quarantine::new(
            temp_dir.path().join("quarantine"),
            1024 * 1024, // 1MB
            30,
        )?;

        // Crear archivo de prueba
        let test_file = temp_dir.path().join("test.txt");
        let content = b"Test content";
        File::create(&test_file)?.write_all(content)?;

        // Poner en cuarentena
        let entry = quarantine.quarantine_file(&test_file, "Test reason")?;

        // Verificar que el archivo original fue eliminado
        assert!(!test_file.exists());

        // Verificar que el archivo está en cuarentena
        assert!(quarantine.path.join(&entry.quarantine_name).exists());

        // Restaurar archivo
        quarantine.restore_file(&entry)?;

        // Verificar que el archivo fue restaurado correctamente
        assert!(test_file.exists());
        let restored_content = fs::read(&test_file)?;
        assert_eq!(restored_content, content);

        Ok(())
    }

    #[test]
    fn captured_content_and_restore_destination_are_verified() -> Result<(), QuarantineError> {
        let dir = tempdir()?;
        let store = Quarantine::new(dir.path().join("q"), 10_000, 30)?;
        let target = dir.path().join("sample.txt");
        fs::write(&target, b"updated since scan")?;
        assert!(store
            .quarantine_if_unchanged(&target, "match", "stale")
            .is_err());
        assert_eq!(fs::read(&target)?, b"updated since scan");
        assert!(store.list_entries()?.is_empty());
        let hash = hex::encode(Sha256::digest(b"updated since scan"));
        let entry = store.quarantine_if_unchanged(&target, "match", &hash)?;
        fs::write(&target, b"replacement")?;
        assert!(store.restore_file_by_id(&entry.quarantine_name).is_err());
        assert_eq!(fs::read(&target)?, b"replacement");
        assert_eq!(store.list_entries()?.len(), 1);
        fs::remove_file(&target)?;
        store.restore_file_by_id(&entry.quarantine_name)?;
        assert_eq!(fs::read(target)?, b"updated since scan");
        Ok(())
    }

    #[test]
    fn test_cleanup() -> Result<(), QuarantineError> {
        let temp_dir = tempdir()?;
        let quarantine = Quarantine::new(
            temp_dir.path().join("quarantine"),
            1024 * 1024,
            0, // Retención de 0 días para prueba
        )?;

        // Crear archivo de prueba
        let test_file = temp_dir.path().join("test.txt");
        File::create(&test_file)?.write_all(b"Test content")?;

        // Poner en cuarentena
        let entry = quarantine.quarantine_file(&test_file, "Test reason")?;

        // Ejecutar limpieza
        quarantine.cleanup()?;

        // Verificar que el archivo fue eliminado
        assert!(!quarantine.path.join(&entry.quarantine_name).exists());

        Ok(())
    }
}
