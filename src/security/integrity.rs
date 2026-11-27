use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use log::{error, info};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{task, time};

/// Error relacionado con la verificación de integridad
#[derive(Error, Debug)]
pub enum IntegrityError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    #[error("Hash mismatch for file {0}: expected {1}, got {2}")]
    HashMismatch(String, String, String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Failed to serialize/deserialize data: {0}")]
    SerializationError(String),

    #[error("File has been tampered: {0}")]
    TamperedFile(String),

    #[error("Internal integrity check error: {0}")]
    InternalError(String),
}

/// Represents the result of an integrity check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    /// The file is valid and matches the expected hash
    Valid,
    /// The file was not found during the check
    Missing,
    /// The file hash does not match the expected hash
    Tampered,
    /// The file was not previously registered
    Unknown,
}

/// Contains integrity data for a single file
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIntegrityData {
    /// SHA-256 hash of the file
    pub hash: String,
    /// Size of the file in bytes
    pub size: u64,
    /// Last modified timestamp of the file
    pub last_modified: SystemTime,
    /// Whether the file is critical for the application
    pub is_critical: bool,
}

/// Database of file integrity data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityDatabase {
    /// Map of file paths to their integrity data
    pub files: HashMap<String, FileIntegrityData>,
    /// When the database was last updated
    pub last_updated: SystemTime,
    /// Version of the database schema
    pub version: String,
}

impl IntegrityDatabase {
    pub fn new() -> Self {
        IntegrityDatabase {
            files: HashMap::new(),
            last_updated: SystemTime::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl Default for IntegrityDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrityDatabase {
    fn load(path: &Path) -> Result<Self, IntegrityError> {
        let file = File::open(path)?;
        serde_json::from_reader(BufReader::new(file))
            .map_err(|e| IntegrityError::SerializationError(e.to_string()))
    }

    // Publish a whole, flushed database on the same volume. The caller holds the
    // writer lock from before loading the previous generation through replacement.
    fn save(&self, path: &Path) -> Result<(), IntegrityError> {
        let serialized = serde_json::to_vec_pretty(self)
            .map_err(|e| IntegrityError::SerializationError(e.to_string()))?;
        let temporary = path.with_extension(format!("json.{:016x}.tmp", rand::random::<u64>()));
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result = (|| {
            file.write_all(&serialized)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        Ok(result?)
    }
}

struct PeriodicCheck {
    handle: task::JoinHandle<()>,
    critical_only: bool,
    interval: Duration,
}

struct IntegrityState {
    database_path: PathBuf,
    baselines: RwLock<HashMap<String, FileIntegrityData>>,
    critical_files: Mutex<HashSet<PathBuf>>,
    interval: Mutex<Duration>,
    periodic: Mutex<Option<PeriodicCheck>>,
}

impl Drop for IntegrityState {
    fn drop(&mut self) {
        if let Some(check) = self.periodic.get_mut().take() {
            check.handle.abort();
        }
    }
}

/// Manages the SHA-256 baselines in `security/integrity.json`.
#[derive(Clone)]
pub struct IntegrityManager {
    state: Arc<IntegrityState>,
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, IntegrityError> + Send + 'static,
) -> Result<T, IntegrityError> {
    task::spawn_blocking(work)
        .await
        .map_err(|e| IntegrityError::InternalError(e.to_string()))?
}

fn lock_writer(path: &Path) -> io::Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path.with_extension("lock"))?;
    lock.lock()?;
    Ok(lock)
}

fn file_data(path: &Path, is_critical: bool) -> Result<FileIntegrityData, IntegrityError> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Expected a regular file").into());
    }
    let mut hasher = Sha256::new();
    let size = io::copy(&mut file, &mut hasher)?;
    let after = file.metadata()?;
    let last_modified = after.modified()?;
    if before.len() != size || after.len() != size || before.modified()? != last_modified {
        return Err(IntegrityError::InternalError(format!(
            "File changed while calculating SHA-256: {}",
            path.display()
        )));
    }
    Ok(FileIntegrityData {
        hash: format!("{:x}", hasher.finalize()),
        size,
        last_modified,
        is_critical,
    })
}

fn path_key(path: &Path) -> Result<&str, IntegrityError> {
    path.to_str().ok_or_else(|| {
        IntegrityError::InternalError(format!(
            "Path cannot be represented in the integrity database: {:?}",
            path
        ))
    })
}

fn verify(
    path: &Path,
    expected: Option<&FileIntegrityData>,
) -> Result<IntegrityStatus, IntegrityError> {
    let Some(expected) = expected else {
        return Ok(if path.try_exists()? {
            IntegrityStatus::Unknown
        } else {
            IntegrityStatus::Missing
        });
    };
    match file_data(path, expected.is_critical) {
        Ok(actual) if actual.hash == expected.hash => Ok(IntegrityStatus::Valid),
        Ok(_) => Ok(IntegrityStatus::Tampered),
        Err(IntegrityError::IoError(e)) if e.kind() == io::ErrorKind::NotFound => {
            Ok(IntegrityStatus::Missing)
        }
        Err(error) => Err(error),
    }
}

impl IntegrityManager {
    /// Opens the existing baseline or creates an empty database for a new installation.
    pub async fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self, IntegrityError> {
        let directory = base_dir.as_ref().join("security");
        let (database_path, baselines) = blocking(move || {
            fs::create_dir_all(&directory)?;
            let path = directory.join("integrity.json");
            let _writer = lock_writer(&path)?;
            let database = match IntegrityDatabase::load(&path) {
                Err(IntegrityError::IoError(e)) if e.kind() == io::ErrorKind::NotFound => {
                    let empty = IntegrityDatabase::new();
                    empty.save(&path)?;
                    empty
                }
                result => result?,
            };
            Ok((path, database.files))
        })
        .await?;
        Ok(Self {
            state: Arc::new(IntegrityState {
                database_path,
                baselines: RwLock::new(baselines),
                critical_files: Mutex::new(HashSet::new()),
                interval: Mutex::new(Duration::from_secs(3600)),
                periodic: Mutex::new(None),
            }),
        })
    }

    /// Sets the interval used on the next call to `start_periodic_check`.
    pub fn set_check_interval(&mut self, interval: Duration) {
        *self.state.interval.lock() = interval;
    }

    /// Includes the path in critical checks even if a baseline is still missing.
    pub fn add_critical_file<P: AsRef<Path>>(&mut self, path: P) {
        self.state
            .critical_files
            .lock()
            .insert(path.as_ref().to_owned());
    }

    pub async fn calculate_file_hash<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<String, IntegrityError> {
        let path = path.as_ref().to_owned();
        blocking(move || Ok(file_data(&path, false)?.hash)).await
    }

    pub async fn register_file<P: AsRef<Path>>(
        &self,
        path: P,
        is_critical: bool,
    ) -> Result<(), IntegrityError> {
        let path = path.as_ref().to_owned();
        let state = self.state.clone();
        blocking(move || {
            let _writer = lock_writer(&state.database_path)?;
            let mut database = IntegrityDatabase::load(&state.database_path)?;
            // Another manager may register new paths. Changes to previously
            // trusted baselines require reopening before this manager can write.
            if state
                .baselines
                .read()
                .iter()
                .any(|(name, old)| database.files.get(name) != Some(old))
            {
                return Err(IntegrityError::TamperedFile(
                    state.database_path.display().to_string(),
                ));
            }
            let data = match file_data(&path, is_critical) {
                Err(IntegrityError::IoError(e)) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(IntegrityError::FileNotFound(path.display().to_string()));
                }
                other => other?,
            };
            let name = path_key(&path)?.to_owned();
            database.files.insert(name.clone(), data.clone());
            database.last_updated = SystemTime::now();
            database.save(&state.database_path)?;
            state.baselines.write().insert(name, data);
            info!(
                "Registered file for integrity monitoring: {}",
                path.display()
            );
            Ok(())
        })
        .await
    }

    pub async fn verify_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<IntegrityStatus, IntegrityError> {
        let path = path.as_ref().to_owned();
        let expected = self.state.baselines.read().get(path_key(&path)?).cloned();
        blocking(move || verify(&path, expected.as_ref())).await
    }

    pub async fn verify_all_files(
        &self,
    ) -> HashMap<String, Result<IntegrityStatus, IntegrityError>> {
        self.verify_files(false).await
    }

    pub async fn verify_critical_files(
        &self,
    ) -> HashMap<String, Result<IntegrityStatus, IntegrityError>> {
        self.verify_files(true).await
    }

    async fn verify_files(
        &self,
        critical_only: bool,
    ) -> HashMap<String, Result<IntegrityStatus, IntegrityError>> {
        let state = self.state.clone();
        let mut paths = self.state.critical_files.lock().clone();
        let result = blocking(move || {
            let baselines = state.baselines.read().clone();
            paths.extend(
                baselines
                    .iter()
                    .filter(|(_, data)| !critical_only || data.is_critical)
                    .map(|(name, _)| PathBuf::from(name)),
            );
            let mut results = HashMap::new();
            for path in paths {
                let name = path_key(&path)?;
                results.insert(name.to_owned(), verify(&path, baselines.get(name)));
            }
            Ok(results)
        })
        .await;
        result.unwrap_or_else(|err| {
            HashMap::from([(self.state.database_path.display().to_string(), Err(err))])
        })
    }

    pub async fn start_periodic_check(&self, critical_only: bool) -> Result<(), IntegrityError> {
        let duration = *self.state.interval.lock();
        if duration.is_zero() {
            return Err(IntegrityError::InternalError(
                "Integrity check interval must be positive".into(),
            ));
        }
        let mut periodic = self.state.periodic.lock();
        if let Some(running) = periodic.as_ref() {
            if !running.handle.is_finished()
                && running.critical_only == critical_only
                && running.interval == duration
            {
                return Ok(());
            }
            running.handle.abort();
        }
        let weak = Arc::downgrade(&self.state);
        let handle = task::spawn(async move {
            let mut ticks = time::interval(duration);
            ticks.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
            loop {
                ticks.tick().await;
                let Some(state) = weak.upgrade() else { break };
                let results = Self { state }.verify_files(critical_only).await;
                for (path, result) in results {
                    match result {
                        Ok(IntegrityStatus::Valid) => {}
                        Ok(status) => error!("Integrity check for {path}: {status:?}"),
                        Err(err) => error!("Error checking integrity of {path}: {err}"),
                    }
                }
            }
        });
        *periodic = Some(PeriodicCheck {
            handle,
            critical_only,
            interval: duration,
        });
        Ok(())
    }

    pub fn stop_periodic_check(&self) {
        if let Some(running) = self.state.periodic.lock().take() {
            running.handle.abort();
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_calculate_hash() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");

        fs::write(&file_path, "test content").unwrap();

        let manager = IntegrityManager::new(temp_dir.path()).await.unwrap();
        let hash = manager.calculate_file_hash(&file_path).await.unwrap();

        // The expected hash for "test content"
        let expected_hash = "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72";

        assert_eq!(hash, expected_hash);
    }

    #[tokio::test]
    async fn test_register_and_verify_file() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");

        fs::write(&file_path, "test content").unwrap();

        let manager = IntegrityManager::new(temp_dir.path()).await.unwrap();
        manager.register_file(&file_path, true).await.unwrap();

        let status = manager.verify_file(&file_path).await.unwrap();
        assert_eq!(status, IntegrityStatus::Valid);

        // Modify the file
        fs::write(&file_path, "modified content").unwrap();

        let status = manager.verify_file(&file_path).await.unwrap();
        assert_eq!(status, IntegrityStatus::Tampered);
    }

    #[tokio::test]
    async fn concurrent_registrations_survive_reopening() {
        let dir = tempdir().unwrap();
        let first = IntegrityManager::new(dir.path()).await.unwrap();
        let second = IntegrityManager::new(dir.path()).await.unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        fs::write(&a, b"first").unwrap();
        fs::write(&b, b"second").unwrap();
        let (x, y) = tokio::join!(
            first.register_file(&a, true),
            second.register_file(&b, false)
        );
        x.unwrap();
        y.unwrap();
        let reopened = IntegrityManager::new(dir.path()).await.unwrap();
        assert_eq!(
            reopened.verify_file(&a).await.unwrap(),
            IntegrityStatus::Valid
        );
        assert_eq!(
            reopened.verify_file(&b).await.unwrap(),
            IntegrityStatus::Valid
        );
        assert_eq!(reopened.verify_critical_files().await.len(), 1);
    }

    #[tokio::test]
    async fn corrupted_database_cannot_replace_trusted_baseline() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("original.txt");
        fs::write(&path, "original").unwrap();
        let manager = IntegrityManager::new(dir.path()).await.unwrap();
        manager.register_file(&path, true).await.unwrap();
        fs::write(&path, "changed").unwrap();
        let database = dir.path().join("security/integrity.json");
        fs::write(&database, "{ incomplete").unwrap();
        assert!(manager.register_file(&path, true).await.is_err());
        assert_eq!(
            manager.verify_file(&path).await.unwrap(),
            IntegrityStatus::Tampered
        );
        assert!(IntegrityManager::new(dir.path()).await.is_err());
        assert_eq!(fs::read_to_string(&database).unwrap(), "{ incomplete");
    }

    #[tokio::test]
    async fn clones_share_one_periodic_task() {
        let dir = tempdir().unwrap();
        let manager = IntegrityManager::new(dir.path()).await.unwrap();
        let mut cloned = manager.clone();
        manager.start_periodic_check(true).await.unwrap();
        let task_id = manager.state.periodic.lock().as_ref().unwrap().handle.id();
        cloned.start_periodic_check(true).await.unwrap();
        assert_eq!(
            cloned.state.periodic.lock().as_ref().unwrap().handle.id(),
            task_id
        );
        cloned.stop_periodic_check();
        assert!(manager.state.periodic.lock().is_none());
        cloned.set_check_interval(Duration::ZERO);
        assert!(manager.start_periodic_check(true).await.is_err());
    }
}
