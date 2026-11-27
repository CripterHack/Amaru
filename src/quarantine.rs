use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
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
    sync_dir(parent_of(path))
}

const JOURNAL_AAD: &[u8] = b"Amaru quarantine transaction v1";

#[derive(Serialize, Deserialize)]
enum Transaction {
    Capture {
        entry: QuarantineEntry,
        pending: PathBuf,
    },
    Restore {
        entry: QuarantineEntry,
        staged: PathBuf,
    },
    Discard {
        id: String,
    },
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn link_metadata(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        other => other.map(Some),
    }
}

fn matches_content(path: &Path, entry: &QuarantineEntry) -> io::Result<bool> {
    let Some(metadata) = link_metadata(path)? else {
        return Ok(false);
    };
    if !metadata.is_file() || metadata.len() != entry.file_size {
        return Ok(false);
    }
    let mut hash = Sha256::new();
    io::copy(
        &mut File::open(path)?.take(entry.file_size.saturating_add(1)),
        &mut hash,
    )?;
    Ok(BASE64.encode(hash.finalize()) == entry.original_hash)
}

fn return_original(pending: &Path, original: &Path) -> io::Result<()> {
    fs::hard_link(pending, original).map_err(|e| {
        io::Error::other(format!(
            "Original retained at {}. Could not recover {} without overwriting: {e}",
            pending.display(),
            original.display()
        ))
    })?;
    sync_dir(parent_of(original))?;
    fs::remove_file(pending)
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
        let store = Self {
            path,
            max_size,
            retention_days,
            encryption_key,
        };
        store.recover()?;
        store.check_catalog()?;
        Ok(store)
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
        let _lock = self.lock_and_recover()?;
        if !fs::symlink_metadata(path)?.is_file() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "Expected a regular file").into(),
            );
        }
        let original = fs::canonicalize(parent_of(path))?.join(
            path.file_name()
                .ok_or_else(|| io::Error::other("Missing filename"))?,
        );
        if original.starts_with(&self.path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot quarantine the quarantine store",
            )
            .into());
        }
        let mut entries = self.read_entries()?;
        let used = entries
            .iter()
            .fold(0u64, |sum, e| sum.saturating_add(e.file_size));
        let limit = self.max_size.saturating_sub(used);
        let file = File::open(&original)?;
        if file.metadata()?.len() > limit {
            return Err(QuarantineError::InsufficientSpace);
        }
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(QuarantineError::InsufficientSpace);
        }
        let digest = Sha256::digest(&bytes);
        if expected_hash.is_some_and(|hash| !hash.eq_ignore_ascii_case(&hex::encode(digest))) {
            return Err(io::Error::other("File changed since analysis").into());
        }
        let entry = QuarantineEntry {
            original_path: original.clone(),
            quarantine_name: format!("v2-{:032x}.quar", rand::random::<u128>()),
            quarantine_date: Utc::now(),
            original_hash: BASE64.encode(digest),
            file_size: bytes.len() as u64,
            reason: reason.to_owned(),
        };
        let aad = serde_json::to_vec(&entry).map_err(io::Error::other)?;
        let sealed = self.seal(&bytes, &aad)?;
        drop(bytes);

        // A durable index and ciphertext exist before we take ownership of the source name.
        // The journal identifies exactly one private staging path, even across processes.
        if entries.is_empty() {
            self.store(&entries)?;
        }
        let mut builder = Builder::new();
        builder.prefix(".amaru-quarantine-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let directory = builder.tempdir_in(parent_of(&original))?;
        let pending = directory.path().join("pending");
        self.write_transaction(&Transaction::Capture {
            entry: entry.clone(),
            pending: pending.clone(),
        })?;
        // A TempDir's destructor must never recursively delete an unverified original.
        let staging = directory.into_path();
        let mut blob = NamedTempFile::new_in(&self.path)?;
        blob.write_all(&sealed)?;
        blob.as_file().sync_all()?;
        blob.persist_noclobber(self.path.join(&entry.quarantine_name))
            .map_err(|e| e.error)?;
        sync_dir(&self.path)?;
        entries.push(entry.clone());
        self.store(&entries)?;
        if let Err(err) = fs::rename(&original, &pending) {
            fs::remove_dir(staging)?;
            self.start_discard(&entry.quarantine_name)?;
            return Err(err.into());
        }
        sync_dir(parent_of(&original))?;
        sync_dir(parent_of(&pending))?;
        if !matches_content(&pending, &entry)? {
            return_original(&pending, &original)?;
            fs::remove_dir(staging)?;
            self.start_discard(&entry.quarantine_name)?;
            return Err(io::Error::other("File changed during quarantine").into());
        }
        fs::remove_file(&pending)?;
        fs::remove_dir(staging)?;
        sync_dir(parent_of(&original))?;
        self.clear_transaction()?;
        Ok(entry)
    }

    pub fn restore_file(&self, entry: &QuarantineEntry) -> Result<(), QuarantineError> {
        self.restore_file_by_id(&entry.quarantine_name).map(|_| ())
    }

    pub fn restore_file_by_id(&self, id: &str) -> Result<PathBuf, QuarantineError> {
        let _lock = self.lock_and_recover()?;
        let entry = self
            .read_entries()?
            .into_iter()
            .find(|e| e.quarantine_name == id)
            .ok_or_else(|| QuarantineError::NotFound(id.to_owned()))?;
        let bytes = self.read_archive(&entry)?;
        let dest = entry.original_path.clone();
        if link_metadata(&dest)?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Restore destination already exists",
            )
            .into());
        }
        let parent = parent_of(&dest);
        fs::create_dir_all(parent)?;
        if fs::canonicalize(parent)?.starts_with(&self.path) {
            return Err(io::Error::other("Cannot restore into the quarantine store").into());
        }
        let mut file = Builder::new()
            .prefix(".amaru-restore-")
            .tempfile_in(parent)?;
        self.write_transaction(&Transaction::Restore {
            entry: entry.clone(),
            staged: file.path().to_owned(),
        })?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        if let Err(err) = file.persist_noclobber(&dest) {
            let io = err.error;
            drop(err.file);
            self.clear_transaction()?;
            return Err(io.into());
        }
        sync_dir(parent)?;
        self.start_discard(id)?;
        Ok(dest)
    }

    pub fn delete_file(&self, entry: &QuarantineEntry) -> Result<(), QuarantineError> {
        self.delete_file_by_id(&entry.quarantine_name)
    }

    pub fn delete_file_by_id(&self, id: &str) -> Result<(), QuarantineError> {
        let _lock = self.lock_and_recover()?;
        if !self.read_entries()?.iter().any(|e| e.quarantine_name == id) {
            return Err(QuarantineError::NotFound(id.to_owned()));
        }
        self.start_discard(id)?;
        Ok(())
    }

    fn start_discard(&self, id: &str) -> io::Result<()> {
        self.write_transaction(&Transaction::Discard { id: id.to_owned() })?;
        self.finish_discard(id)
    }

    fn finish_discard(&self, id: &str) -> io::Result<()> {
        let mut entries = self.read_entries()?;
        remove_if_present(&self.path.join(id))?;
        sync_dir(&self.path)?;
        entries.retain(|e| e.quarantine_name != id);
        self.store(&entries)?;
        self.clear_transaction()
    }

    pub fn cleanup(&self) -> io::Result<()> {
        let _lock = self.lock_and_recover()?;
        let now = Utc::now();
        for entry in self.read_entries()? {
            if (now - entry.quarantine_date).num_days() >= i64::from(self.retention_days) {
                self.start_discard(&entry.quarantine_name)?;
            }
        }
        Ok(())
    }

    fn lock_and_recover(&self) -> io::Result<File> {
        let lock = Self::lock_dir(&self.path)?;
        self.recover()?;
        self.check_catalog()?;
        Ok(lock)
    }

    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = rand::random::<[u8; 12]>();
        let cipher = Aes256Gcm::new((&self.encryption_key).into());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| io::Error::other("AES-GCM encryption failed"))?;
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend(ciphertext);
        Ok(result)
    }

    fn open_sealed(&self, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, QuarantineError> {
        if blob.len() < 28 {
            return Err(QuarantineError::Decryption("Truncated ciphertext".into()));
        }
        Aes256Gcm::new((&self.encryption_key).into())
            .decrypt(
                Nonce::from_slice(&blob[..12]),
                Payload {
                    msg: &blob[12..],
                    aad,
                },
            )
            .map_err(|_| QuarantineError::Decryption("Authentication failed".into()))
    }

    fn read_archive(&self, entry: &QuarantineEntry) -> Result<Vec<u8>, QuarantineError> {
        let sealed = fs::read(self.path.join(&entry.quarantine_name))?;
        let aad = if entry.quarantine_name.starts_with("v2-") {
            serde_json::to_vec(entry).map_err(io::Error::other)?
        } else {
            Vec::new()
        };
        let data = self.open_sealed(&sealed, &aad)?;
        if data.len() as u64 != entry.file_size
            || BASE64.encode(Sha256::digest(&data)) != entry.original_hash
        {
            return Err(QuarantineError::Decryption(
                "Hash verification failed".into(),
            ));
        }
        Ok(data)
    }

    fn write_transaction(&self, transaction: &Transaction) -> io::Result<()> {
        let bytes = serde_json::to_vec(transaction).map_err(io::Error::other)?;
        atomic_write(
            &self.path.join(".transaction"),
            &self.seal(&bytes, JOURNAL_AAD)?,
        )
    }

    fn clear_transaction(&self) -> io::Result<()> {
        remove_if_present(&self.path.join(".transaction"))?;
        sync_dir(&self.path)
    }

    fn read_transaction(&self) -> io::Result<Option<Transaction>> {
        let journal = match fs::read(self.path.join(".transaction")) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            other => other?,
        };
        let raw = self
            .open_sealed(&journal, JOURNAL_AAD)
            .map_err(io::Error::other)?;
        Ok(Some(serde_json::from_slice(&raw)?))
    }

    fn recover(&self) -> io::Result<()> {
        match self.read_transaction()? {
            None => Ok(()),
            Some(Transaction::Discard { id }) => self.finish_discard(&id),
            Some(Transaction::Restore { entry, staged }) => {
                if staged.try_exists()? {
                    // A no-clobber publish was not completed. Preserve the archive for a retry.
                    remove_if_present(&staged)?;
                    sync_dir(parent_of(&staged))?;
                } else if matches_content(&entry.original_path, &entry)? {
                    return self.start_discard(&entry.quarantine_name);
                }
                self.clear_transaction()
            }
            Some(Transaction::Capture { entry, pending }) => {
                let indexed = self
                    .read_entries()?
                    .iter()
                    .any(|e| e.quarantine_name == entry.quarantine_name);
                if link_metadata(&pending)?.is_some() {
                    // Retire a claimed original only when its authenticated copy is readable.
                    if indexed
                        && matches_content(&pending, &entry)?
                        && self.read_archive(&entry).is_ok()
                    {
                        fs::remove_file(&pending)?;
                    } else {
                        return_original(&pending, &entry.original_path)?;
                        fs::remove_dir(parent_of(&pending))?;
                        return self.start_discard(&entry.quarantine_name);
                    }
                }
                if parent_of(&pending).try_exists()? {
                    fs::remove_dir(parent_of(&pending))?;
                }
                sync_dir(parent_of(&entry.original_path))?;
                if !indexed {
                    // A crash before publishing the index left the original in place.
                    remove_if_present(&self.path.join(&entry.quarantine_name))?;
                }
                self.clear_transaction()
            }
        }
    }

    pub fn list_entries(&self) -> io::Result<Vec<QuarantineEntry>> {
        let _lock = self.lock_and_recover()?;
        self.read_entries()
    }

    fn read_entries(&self) -> io::Result<Vec<QuarantineEntry>> {
        let bytes = match fs::read(self.path.join("metadata.json")) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if self.path_has_blobs()? {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Missing index for existing quarantine archives",
                    ));
                }
                return Ok(Vec::new());
            }
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

    fn check_catalog(&self) -> io::Result<()> {
        let mut expected: HashSet<_> = self
            .read_entries()?
            .into_iter()
            .map(|e| e.quarantine_name)
            .collect();
        for file in fs::read_dir(&self.path)? {
            let file = file?;
            if file.path().extension().is_some_and(|ext| ext == "quar") {
                let name = file.file_name();
                if !name.to_str().is_some_and(|id| expected.remove(id))
                    || !file.file_type()?.is_file()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Unindexed or invalid quarantine archive: {}",
                            file.path().display()
                        ),
                    ));
                }
            }
        }
        if let Some(id) = expected.into_iter().next() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Missing quarantine archive {id}"),
            ));
        }
        Ok(())
    }

    /// Ignore only artifacts named in our current authenticated transaction.
    pub(crate) fn is_staging_path(&self, path: &Path) -> bool {
        let looks_internal = path.file_name().is_some_and(|name| {
            name.to_string_lossy().starts_with(".amaru-restore-")
                || (name == "pending"
                    && parent_of(path)
                        .file_name()
                        .is_some_and(|p| p.to_string_lossy().starts_with(".amaru-quarantine-")))
        });
        looks_internal
            && match self.read_transaction() {
                Ok(Some(Transaction::Capture { pending, .. })) => pending == path,
                Ok(Some(Transaction::Restore { staged, .. })) => staged == path,
                _ => false,
            }
    }

    fn path_has_blobs(&self) -> io::Result<bool> {
        for entry in fs::read_dir(&self.path)? {
            if entry?.path().extension().is_some_and(|ext| ext == "quar") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn store(&self, entries: &[QuarantineEntry]) -> io::Result<()> {
        atomic_write(
            &self.path.join("metadata.json"),
            &serde_json::to_vec_pretty(entries)?,
        )
    }
}
#[cfg(test)]
mod recovery_tests;

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
    fn legacy_ciphertext_restores_without_overwriting_a_replacement() -> Result<(), QuarantineError>
    {
        let root = tempdir()?;
        let store_path = root.path().join("quarantine");
        fs::create_dir(&store_path)?;
        let original = root.path().join("legacy.txt");
        let key = [0x21; 32];
        let nonce = [0x17; 12];
        let content = b"archived before v2";
        // V1 stored the raw key and nonce + ciphertext/tag, with no associated data.
        fs::write(store_path.join(".key"), key)?;
        let ciphertext = Aes256Gcm::new((&key).into())
            .encrypt((&nonce).into(), content.as_slice())
            .unwrap();
        let mut blob = nonce.to_vec();
        blob.extend(ciphertext);
        let id = "1735689600.quar";
        fs::write(store_path.join(id), blob)?;
        let record = serde_json::json!([{
            "original_path": original, "quarantine_name": id, "quarantine_date": "2025-01-01T00:00:00Z",
            "original_hash": BASE64.encode(Sha256::digest(content)), "file_size": content.len(), "reason": "legacy"
        }]);
        fs::write(
            store_path.join("metadata.json"),
            serde_json::to_vec(&record).unwrap(),
        )?;

        let reopened = Quarantine::new(&store_path, 1024, 30)?;
        fs::write(&original, b"a replacement")?;
        let err = reopened.restore_file_by_id(id).unwrap_err();
        assert!(
            matches!(err, QuarantineError::Io(ref io) if io.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(&original)?, b"a replacement");
        assert!(store_path.join(id).is_file());
        assert_eq!(reopened.list_entries()?.len(), 1);
        fs::remove_file(&original)?;
        assert_eq!(reopened.restore_file_by_id(id)?, original);
        assert_eq!(fs::read(original)?, content);
        assert!(reopened.list_entries()?.is_empty());
        Ok(())
    }

    #[test]
    fn missing_or_empty_index_never_hides_existing_archives() -> Result<(), QuarantineError> {
        let root = tempdir()?;
        let directory = root.path().join("q");
        let source = root.path().join("sample");
        fs::write(&source, b"saved")?;
        let store = Quarantine::new(&directory, 1024, 30)?;
        let entry = store.quarantine_file(&source, "fixture")?;
        let metadata = directory.join("metadata.json");
        let saved = fs::read(&metadata)?;
        fs::remove_file(&metadata)?;
        assert!(store.list_entries().is_err());
        fs::write(&metadata, "[]")?;
        assert!(Quarantine::new(&directory, 1024, 30).is_err());
        fs::write(metadata, saved)?;
        assert_eq!(
            Quarantine::new(&directory, 1024, 30)?.restore_file_by_id(&entry.quarantine_name)?,
            entry.original_path
        );
        Ok(())
    }

    #[test]
    fn interrupted_restore_proves_publication_before_discarding_ciphertext(
    ) -> Result<(), QuarantineError> {
        let root = tempdir()?;
        let directory = root.path().join("q");
        let store = Quarantine::new(&directory, 1024, 30)?;
        let source = root.path().join("sample");
        let staged = root.path().join(".amaru-restore-fixture");
        fs::write(&source, b"saved")?;
        let entry = store.quarantine_file(&source, "fixture")?;
        fs::write(&staged, b"saved")?;
        fs::write(&source, b"a new file")?;
        let journal = Transaction::Restore {
            entry: entry.clone(),
            staged: staged.clone(),
        };
        store.write_transaction(&journal)?;
        assert_eq!(store.list_entries()?.len(), 1);
        assert!(!staged.exists());
        assert_eq!(fs::read(&source)?, b"a new file");
        // Simulate a completed no-clobber publish before deletion of the archive.
        fs::remove_file(&source)?;
        fs::write(&source, b"saved")?;
        store.write_transaction(&journal)?;
        assert!(Quarantine::new(&directory, 1024, 30)?
            .list_entries()?
            .is_empty());
        assert_eq!(fs::read(source)?, b"saved");
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
