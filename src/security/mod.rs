// Security module for Amaru Antivirus
// Provides security features for the application, including:
// - File integrity verification
// - Digital signature verification
// - Tamper protection for files and config
// - Secure logging with integrity verification

// Export submodules
pub mod integrity;
pub mod digital_signature;
pub mod tamper_protection;
pub mod secure_logging;

// Re-export key types and errors
pub use integrity::{IntegrityManager, IntegrityError, IntegrityStatus};
pub use digital_signature::{DigitalSignature, SignatureError, SignatureInfo};
pub use tamper_protection::{TamperProtection, TamperProtectionError, FileStatus, ImportanceLevel};
pub use secure_logging::{SecureLogger, SecureLoggingError, SensitivityLevel};

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::collections::HashMap;
use thiserror::Error;
use log::{info, warn, error};

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Integrity error: {0}")]
    IntegrityError(#[from] integrity::IntegrityError),
    
    #[error("Signature error: {0}")]
    SignatureError(#[from] digital_signature::SignatureError),
    
    #[error("Tamper protection error: {0}")]
    TamperProtectionError(#[from] tamper_protection::TamperProtectionError),
    
    #[error("Secure logging error: {0}")]
    LoggingError(#[from] secure_logging::SecureLoggingError),
    
    #[error("Internal security error: {0}")]
    InternalError(String),
}

/// Results of a security check
#[derive(Debug, Clone)]
pub struct SecurityCheckResult {
    /// Whether the integrity check passed
    pub integrity_check_passed: bool,
    /// Whether the tamper protection check passed
    pub tamper_check_passed: bool,
    /// Whether the log integrity check passed
    pub log_integrity_passed: bool,
    /// Files that failed integrity check
    pub integrity_failures: Vec<String>,
    /// Files that failed tamper protection check
    pub tamper_failures: Vec<String>,
    /// Log files that failed integrity check
    pub log_integrity_failures: Vec<String>,
}

/// Security manager for the application
pub struct SecurityManager {
    /// Integrity manager
    integrity_manager: integrity::IntegrityManager,
    /// Tamper protection
    tamper_protection: tamper_protection::TamperProtection,
    /// Secure logger
    secure_logger: secure_logging::SecureLogger,
    /// Base directory
    base_dir: PathBuf,
}

impl SecurityManager {
    /// Creates a new security manager
    pub async fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self, SecurityError> {
        let base_dir = base_dir.as_ref().to_path_buf();
        
        // Create necessary directories
        let integrity_dir = base_dir.join("security/integrity");
        let security_dir = base_dir.join("security");
        let logs_dir = base_dir.join("logs");
        
        std::fs::create_dir_all(&integrity_dir)
            .map_err(|e| SecurityError::InternalError(format!("Failed to create integrity directory: {}", e)))?;
        
        std::fs::create_dir_all(&security_dir)
            .map_err(|e| SecurityError::InternalError(format!("Failed to create security directory: {}", e)))?;
        
        std::fs::create_dir_all(&logs_dir)
            .map_err(|e| SecurityError::InternalError(format!("Failed to create logs directory: {}", e)))?;
        
        // Initialize components
        let integrity_manager = integrity::IntegrityManager::new(&base_dir).await
            .map_err(|e| SecurityError::IntegrityError(e))?;
        
        let tamper_protection = tamper_protection::TamperProtection::new(&base_dir).await
            .map_err(|e| SecurityError::TamperProtectionError(e))?;
        
        let secure_logger = secure_logging::SecureLogger::new(&base_dir, None).await
            .map_err(|e| SecurityError::LoggingError(e))?;
        
        Ok(SecurityManager {
            integrity_manager,
            tamper_protection,
            secure_logger,
            base_dir,
        })
    }
    
    /// Verifies the integrity of a file
    pub async fn verify_file_integrity<P: AsRef<Path>>(&self, path: P) -> Result<integrity::IntegrityStatus, SecurityError> {
        self.integrity_manager.verify_file(path).await
            .map_err(|e| SecurityError::IntegrityError(e))
    }
    
    /// Verifies the digital signature of a file
    pub fn verify_file_signature<P: AsRef<Path>>(&self, path: P) -> Result<bool, SecurityError> {
        let signature = digital_signature::DigitalSignature::new();
        signature.verify_signature(path)
            .map_err(|e| SecurityError::SignatureError(e))
    }
    
    /// Registers a file for tamper protection
    pub async fn protect_file<P: AsRef<Path>>(&self, path: P, importance: tamper_protection::ImportanceLevel) -> Result<(), SecurityError> {
        self.tamper_protection.protect_file(path, importance).await
            .map_err(|e| SecurityError::TamperProtectionError(e))
    }
    
    /// Registers a file for integrity monitoring
    pub async fn register_file_for_integrity<P: AsRef<Path>>(&self, path: P, is_critical: bool) -> Result<(), SecurityError> {
        self.integrity_manager.register_file(path, is_critical).await
            .map_err(|e| SecurityError::IntegrityError(e))
    }
    
    /// Logs a secure message with integrity protection
    pub async fn log_secure_message(
        &self,
        level: log::Level,
        message: &str,
        module: &str,
        location: &str,
        sensitivity: secure_logging::SensitivityLevel,
    ) -> Result<(), SecurityError> {
        self.secure_logger.log(level, message, module, location, sensitivity).await
            .map_err(|e| SecurityError::LoggingError(e))
    }
    
    /// Starts security services
    pub async fn start_security_services(&mut self) -> Result<(), SecurityError> {
        // Start integrity checks
        let mut integrity_manager = self.integrity_manager.clone();
        integrity_manager.start_periodic_check(true).await
            .map_err(|e| SecurityError::IntegrityError(e))?;
        
        // Start tamper protection
        self.tamper_protection.start_protection().await
            .map_err(|e| SecurityError::TamperProtectionError(e))?;
        
        Ok(())
    }
    
    /// Performs a full security check
    pub async fn perform_security_check(&self) -> Result<SecurityCheckResult, SecurityError> {
        let mut result = SecurityCheckResult {
            integrity_check_passed: true,
            tamper_check_passed: true,
            log_integrity_passed: true,
            integrity_failures: Vec::new(),
            tamper_failures: Vec::new(),
            log_integrity_failures: Vec::new(),
        };
        
        // Check critical files integrity
        let integrity_results = self.integrity_manager.verify_critical_files().await;
        
        for (path, check_result) in integrity_results {
            match check_result {
                Ok(integrity::IntegrityStatus::Valid) => {}
                Ok(integrity::IntegrityStatus::Tampered) => {
                    result.integrity_check_passed = false;
                    result.integrity_failures.push(path);
                }
                Ok(integrity::IntegrityStatus::Missing) => {
                    result.integrity_check_passed = false;
                    result.integrity_failures.push(path);
                }
                _ => {}
            }
        }
        
        // Check tamper protection
        let tamper_results = self.tamper_protection.verify_all_files().await;
        
        for (path, check_result) in tamper_results {
            match check_result {
                Ok(tamper_protection::FileStatus::Valid) | Ok(tamper_protection::FileStatus::Modified) => {}
                Ok(tamper_protection::FileStatus::Tampered) => {
                    result.tamper_check_passed = false;
                    result.tamper_failures.push(path);
                }
                Ok(tamper_protection::FileStatus::Missing) => {
                    result.tamper_check_passed = false;
                    result.tamper_failures.push(path);
                }
                Err(_) => {
                    result.tamper_check_passed = false;
                    result.tamper_failures.push(path);
                }
            }
        }
        
        // Check log integrity
        let log_integrity = self.secure_logger.verify_log_integrity(&self.secure_logger.current_log_file).await
            .map_err(|e| SecurityError::LoggingError(e))?;
        
        if !log_integrity {
            result.log_integrity_passed = false;
            result.log_integrity_failures.push(
                self.secure_logger.current_log_file.to_string_lossy().to_string()
            );
        }
        
        Ok(result)
    }
    
    /// Gets a reference to the secure logger
    pub fn secure_logger(&self) -> &secure_logging::SecureLogger {
        &self.secure_logger
    }
    
    /// Gets a reference to the integrity manager
    pub fn integrity_manager(&self) -> &integrity::IntegrityManager {
        &self.integrity_manager
    }
    
    /// Gets a reference to the tamper protection
    pub fn tamper_protection(&self) -> &tamper_protection::TamperProtection {
        &self.tamper_protection
    }
} 