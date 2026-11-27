// Security module for Amaru Antivirus
// Provides security features for the application, including:
// - File integrity verification
// - Digital signature verification
// - Tamper protection for files and config
// - Secure logging with integrity verification

// Export submodules
pub mod digital_signature;
pub mod integrity;
pub mod secure_logging;
pub mod tamper_protection;

// Re-export key types and errors
pub use digital_signature::{DigitalSignature, SignatureError, SignatureInfo};
pub use integrity::{IntegrityError, IntegrityManager, IntegrityStatus};
pub use secure_logging::{SecureLogger, SecureLoggingError, SensitivityLevel};
pub use tamper_protection::{FileStatus, ImportanceLevel, TamperProtection, TamperProtectionError};

use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

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
    integrity_manager: Arc<integrity::IntegrityManager>,
    /// Tamper protection
    tamper_protection: tamper_protection::TamperProtection,
    /// Secure logger
    secure_logger: secure_logging::SecureLogger,
}

impl SecurityManager {
    /// Creates a new security manager
    pub async fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self, SecurityError> {
        let base_dir = base_dir.as_ref().to_path_buf();

        let security_dir = base_dir.join("security");
        let integrity_manager = Arc::new(integrity::IntegrityManager::new(&base_dir).await?);
        let tamper_protection = tamper_protection::TamperProtection::new(
            Arc::clone(&integrity_manager),
            &security_dir,
            Some(security_dir.join("tamper.key")),
        )
        .await?;
        let secure_logger = secure_logging::SecureLogger::new(&base_dir, None).await?;

        Ok(SecurityManager {
            integrity_manager,
            tamper_protection,
            secure_logger,
        })
    }

    /// Verifies the integrity of a file
    pub async fn verify_file_integrity<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<integrity::IntegrityStatus, SecurityError> {
        self.integrity_manager
            .verify_file(path)
            .await
            .map_err(SecurityError::IntegrityError)
    }

    /// Verifies the digital signature of a file
    pub fn verify_file_signature<P: AsRef<Path>>(&self, path: P) -> Result<bool, SecurityError> {
        let signature = digital_signature::DigitalSignature::new();
        signature
            .verify_signature(path)
            .map_err(SecurityError::SignatureError)
    }

    /// Registers a file for tamper protection
    pub async fn protect_file<P: AsRef<Path>>(
        &self,
        path: P,
        importance: tamper_protection::ImportanceLevel,
    ) -> Result<(), SecurityError> {
        self.tamper_protection
            .protect_file(path, importance)
            .await
            .map_err(SecurityError::TamperProtectionError)
    }

    /// Registers a file for integrity monitoring
    pub async fn register_file_for_integrity<P: AsRef<Path>>(
        &self,
        path: P,
        is_critical: bool,
    ) -> Result<(), SecurityError> {
        self.integrity_manager
            .register_file(path, is_critical)
            .await
            .map_err(SecurityError::IntegrityError)
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
        self.secure_logger
            .log(level, message, module, location, sensitivity)
            .await
            .map_err(SecurityError::LoggingError)
    }

    /// Starts security services
    pub async fn start_security_services(&mut self) -> Result<(), SecurityError> {
        // Start integrity checks
        self.integrity_manager
            .start_periodic_check(true)
            .await
            .map_err(SecurityError::IntegrityError)?;

        // Start tamper protection
        self.tamper_protection
            .start()
            .await
            .map_err(SecurityError::TamperProtectionError)?;

        Ok(())
    }

    pub async fn stop_security_services(&self) -> Result<(), SecurityError> {
        self.integrity_manager.stop_periodic_check();
        self.tamper_protection.stop().await?;
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
            if !matches!(check_result, Ok(integrity::IntegrityStatus::Valid)) {
                result.integrity_check_passed = false;
                result.integrity_failures.push(path);
            }
        }

        for (path, status) in self.tamper_protection.verify_all_files().await {
            if !matches!(status, Ok(FileStatus::Valid | FileStatus::Modified)) {
                result.tamper_check_passed = false;
                result.tamper_failures.push(path);
            }
        }

        // Check log integrity
        for (path, valid) in self.secure_logger.verify_all_logs().await? {
            if !valid {
                result.log_integrity_passed = false;
                result
                    .log_integrity_failures
                    .push(path.display().to_string());
            }
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
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn persistent_protection_reports_changes_until_explicitly_registered() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("protected.bin");
        std::fs::write(&file, b"approved").unwrap();
        let mut manager = SecurityManager::new(dir.path()).await.unwrap();
        manager.protect_file(&file, 95).await.unwrap();
        manager.start_security_services().await.unwrap();
        manager.start_security_services().await.unwrap();
        manager.stop_security_services().await.unwrap();
        drop(manager);

        let manager = SecurityManager::new(dir.path()).await.unwrap();
        std::fs::write(&file, b"modified").unwrap();
        for _ in 0..2 {
            let check = manager.perform_security_check().await.unwrap();
            assert!(!check.integrity_check_passed);
            assert!(!check.tamper_check_passed);
            assert!(check.log_integrity_passed);
        }
        manager.protect_file(&file, 95).await.unwrap();
        assert!(
            manager
                .perform_security_check()
                .await
                .unwrap()
                .tamper_check_passed
        );
        std::fs::remove_file(&file).unwrap();
        assert_eq!(
            manager
                .tamper_protection()
                .verify_file(&file)
                .await
                .unwrap(),
            FileStatus::Missing
        );
    }
}
