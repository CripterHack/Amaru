use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{self, Read, BufReader};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use log::{error, info, warn, debug};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use tokio::sync::Mutex;
use thiserror::Error;
use tokio::time;

use crate::AmaruError;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Manages file integrity verification
pub struct IntegrityManager {
    /// Base directory for the application
    base_dir: PathBuf,
    /// Database of file integrity information
    database: Arc<Mutex<IntegrityDatabase>>,
    /// Path to the integrity database file
    database_path: PathBuf,
    /// Whether periodic checks are enabled
    periodic_checks_enabled: bool,
    /// Interval between periodic checks
    check_interval: Duration,
    /// List of critical files to monitor
    critical_files: Vec<PathBuf>,
}

impl IntegrityManager {
    /// Creates a new integrity manager
    pub async fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self, IntegrityError> {
        let base_dir = base_dir.as_ref().to_path_buf();
        let database_dir = base_dir.join("security");
        let database_path = database_dir.join("integrity.json");
        
        // Ensure the security directory exists
        std::fs::create_dir_all(&database_dir)
            .map_err(|e| IntegrityError::IoError(e))?;
        
        // Try to load the existing database or create a new one
        let database = if database_path.exists() {
            let file = File::open(&database_path)
                .map_err(|e| IntegrityError::IoError(e))?;
            let reader = BufReader::new(file);
            serde_json::from_reader(reader)
                .map_err(|e| IntegrityError::SerializationError(e.to_string()))?
        } else {
            IntegrityDatabase::new()
        };
        
        Ok(IntegrityManager {
            base_dir,
            database: Arc::new(Mutex::new(database)),
            database_path,
            periodic_checks_enabled: false,
            check_interval: Duration::from_secs(3600), // Default: check every hour
            critical_files: Vec::new(),
        })
    }
    
    /// Sets the interval for periodic integrity checks
    pub fn set_check_interval(&mut self, interval: Duration) {
        self.check_interval = interval;
    }
    
    /// Adds a file to the critical files list
    pub fn add_critical_file<P: AsRef<Path>>(&mut self, path: P) {
        self.critical_files.push(path.as_ref().to_path_buf());
    }
    
    /// Calculates the SHA-256 hash of a file
    pub async fn calculate_file_hash<P: AsRef<Path>>(&self, path: P) -> Result<String, IntegrityError> {
        let path = path.as_ref();
        let mut file = File::open(path)
            .map_err(|e| IntegrityError::IoError(e))?;
        
        let mut hasher = Sha256::new();
        let mut buffer = [0; 1024 * 1024]; // 1MB buffer
        
        loop {
            let bytes_read = file.read(&mut buffer)
                .map_err(|e| IntegrityError::IoError(e))?;
            
            if bytes_read == 0 {
                break;
            }
            
            hasher.update(&buffer[..bytes_read]);
        }
        
        let hash = hasher.finalize();
        Ok(format!("{:x}", hash))
    }
    
    /// Registers a file for integrity monitoring
    pub async fn register_file<P: AsRef<Path>>(&self, path: P, is_critical: bool) -> Result<(), IntegrityError> {
        let path = path.as_ref();
        
        // Ensure the file exists
        if !path.exists() {
            return Err(IntegrityError::FileNotFound(
                path.to_string_lossy().to_string()
            ));
        }
        
        let metadata = path.metadata()
            .map_err(|e| IntegrityError::IoError(e))?;
        
        let hash = self.calculate_file_hash(path).await?;
        let size = metadata.len();
        let last_modified = metadata.modified()
            .map_err(|e| IntegrityError::IoError(e))?;
        
        let integrity_data = FileIntegrityData {
            hash,
            size,
            last_modified,
            is_critical,
        };
        
        // Update the database
        let path_str = path.to_string_lossy().to_string();
        
        {
            let mut db = self.database.lock().await;
            db.files.insert(path_str.clone(), integrity_data);
            db.last_updated = SystemTime::now();
        }
        
        self.save_database().await?;
        
        info!("Registered file for integrity monitoring: {}", path_str);
        Ok(())
    }
    
    /// Verifies the integrity of a single file
    pub async fn verify_file<P: AsRef<Path>>(&self, path: P) -> Result<IntegrityStatus, IntegrityError> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();
        
        // Check if the file exists
        if !path.exists() {
            return Ok(IntegrityStatus::Missing);
        }
        
        // Check if we have a record for this file
        let expected_hash = {
            let db = self.database.lock().await;
            match db.files.get(&path_str) {
                Some(data) => data.hash.clone(),
                None => return Ok(IntegrityStatus::Unknown),
            }
        };
        
        // Calculate the current hash
        let current_hash = self.calculate_file_hash(path).await?;
        
        // Compare hashes
        if current_hash == expected_hash {
            debug!("Integrity check passed for file: {}", path_str);
            Ok(IntegrityStatus::Valid)
        } else {
            warn!("Integrity check failed for file: {}. Hash mismatch!", path_str);
            Ok(IntegrityStatus::Tampered)
        }
    }
    
    /// Verifies the integrity of all registered files
    pub async fn verify_all_files(&self) -> HashMap<String, Result<IntegrityStatus, IntegrityError>> {
        let mut results = HashMap::new();
        
        let file_paths = {
            let db = self.database.lock().await;
            db.files.keys().cloned().collect::<Vec<_>>()
        };
        
        for path in file_paths {
            let result = self.verify_file(&path).await;
            results.insert(path, result);
        }
        
        results
    }
    
    /// Verifies only critical files
    pub async fn verify_critical_files(&self) -> HashMap<String, Result<IntegrityStatus, IntegrityError>> {
        let mut results = HashMap::new();
        
        let file_paths = {
            let db = self.database.lock().await;
            db.files.iter()
                .filter(|(_, data)| data.is_critical)
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>()
        };
        
        for path in file_paths {
            let result = self.verify_file(&path).await;
            results.insert(path, result);
        }
        
        results
    }
    
    /// Saves the integrity database to disk
    async fn save_database(&self) -> Result<(), IntegrityError> {
        let db = self.database.lock().await;
        let json = serde_json::to_string_pretty(&*db)
            .map_err(|e| IntegrityError::SerializationError(e.to_string()))?;
        
        std::fs::write(&self.database_path, json)
            .map_err(|e| IntegrityError::IoError(e))?;
        
        Ok(())
    }
    
    /// Starts periodic integrity checks in the background
    pub async fn start_periodic_check(&mut self, critical_only: bool) -> Result<(), IntegrityError> {
        self.periodic_checks_enabled = true;
        
        let database = Arc::clone(&self.database);
        let check_interval = self.check_interval;
        let manager = self.clone();
        
        tokio::spawn(async move {
            let mut interval = time::interval(check_interval);
            
            loop {
                interval.tick().await;
                
                if !manager.periodic_checks_enabled {
                    break;
                }
                
                info!("Running periodic integrity check");
                
                let results = if critical_only {
                    manager.verify_critical_files().await
                } else {
                    manager.verify_all_files().await
                };
                
                // Log any issues found
                for (path, result) in &results {
                    match result {
                        Ok(IntegrityStatus::Tampered) => {
                            error!("INTEGRITY VIOLATION: File has been tampered: {}", path);
                            // Here you could trigger alerts or other protective actions
                        },
                        Ok(IntegrityStatus::Missing) => {
                            error!("INTEGRITY VIOLATION: Critical file is missing: {}", path);
                            // Here you could trigger alerts or other protective actions
                        },
                        Err(e) => {
                            error!("Error checking integrity of {}: {}", path, e);
                        },
                        _ => {} // Valid or Unknown statuses don't need special handling
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Stops periodic integrity checks
    pub fn stop_periodic_check(&mut self) {
        self.periodic_checks_enabled = false;
    }
    
    /// Creates a clone of self that can be moved to a different thread
    pub fn clone(&self) -> Self {
        IntegrityManager {
            base_dir: self.base_dir.clone(),
            database: Arc::clone(&self.database),
            database_path: self.database_path.clone(),
            periodic_checks_enabled: self.periodic_checks_enabled,
            check_interval: self.check_interval,
            critical_files: self.critical_files.clone(),
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
} 