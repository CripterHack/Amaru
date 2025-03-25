use std::path::{Path, PathBuf};
use std::io::{self, Read, Write};
use std::fs::File;
use thiserror::Error;
use log::{error, info, warn, debug};
use std::time::SystemTime;

#[cfg(windows)]
use winapi::um::wintrust::{WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO};
#[cfg(windows)]
use winapi::shared::winerror::TRUST_E_SUBJECT_NOT_TRUSTED;
#[cfg(windows)]
use winapi::um::softpub::WINTRUST_ACTION_GENERIC_VERIFY_V2;
#[cfg(windows)]
use winapi::um::wincrypt::CERT_CONTEXT;
#[cfg(windows)]
use winapi::shared::guiddef::GUID;
#[cfg(windows)]
use std::ptr;
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

/// Errores relacionados con la firma digital
#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Error de E/S: {0}")]
    IoError(#[from] io::Error),
    
    #[error("El archivo no está firmado digitalmente")]
    NotSigned,
    
    #[error("La firma digital no es válida")]
    InvalidSignature,
    
    #[error("La firma digital ha expirado")]
    ExpiredSignature,
    
    #[error("El certificado no es de confianza")]
    UntrustedCertificate(String),
    
    #[error("Error al verificar la firma: {0}")]
    VerificationFailed(String),
    
    #[error("Error de sistema: {0}")]
    SystemError(String),
    
    #[error("Esta función solo está disponible en Windows")]
    PlatformNotSupported,
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Contains information about a digital signature
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    /// Subject name in the certificate
    pub subject: String,
    /// Issuer name in the certificate
    pub issuer: String,
    /// Validity start date
    pub valid_from: SystemTime,
    /// Validity end date
    pub valid_until: SystemTime,
    /// Certificate thumbprint (SHA-1 hash)
    pub thumbprint: String,
    /// Whether the signature is timestamped
    pub is_timestamped: bool,
    /// Timestamp of the signature
    pub timestamp: Option<SystemTime>,
    /// Signature algorithm
    pub algorithm: String,
}

/// Manages digital signature verification
pub struct DigitalSignature;

impl DigitalSignature {
    /// Creates a new digital signature verifier
    pub fn new() -> Self {
        DigitalSignature
    }
    
    /// Verifies if a file is digitally signed and the signature is valid
    pub fn verify_signature<P: AsRef<Path>>(&self, path: P) -> Result<bool, SignatureError> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();
        
        if !path.exists() {
            return Err(SignatureError::IoError(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {}", path_str)
            )));
        }

        #[cfg(target_os = "windows")]
        {
            use std::ptr;
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStrExt;
            use std::ffi::OsStr;
            use winapi::um::wintrust::{
                WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO,
                WTD_CHOICE_FILE, WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE,
                WTD_REVOKE_NONE, WTD_UI_NONE,
            };
            use winapi::shared::winerror::TRUST_E_SUBJECT_NOT_TRUSTED;
            use winapi::shared::guiddef::GUID;
            use winapi::um::wincrypt::WINTRUST_ACTION_GENERIC_VERIFY_V2;

            // Convert path to wide string
            let path_wide: Vec<u16> = OsString::from(path)
                .encode_wide()
                .chain(Some(0))
                .collect();

            let mut file_info = WINTRUST_FILE_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
                pcwszFilePath: path_wide.as_ptr(),
                hFile: ptr::null_mut(),
                pgKnownSubject: ptr::null_mut(),
            };

            let mut trust_data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                pPolicyCallbackData: ptr::null_mut(),
                pSIPClientData: ptr::null_mut(),
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_FILE,
                union1: unsafe { std::mem::zeroed() },
                dwStateAction: WTD_STATEACTION_VERIFY,
                hWVTStateData: ptr::null_mut(),
                pwszURLReference: ptr::null_mut(),
                dwProvFlags: 0,
                dwUIContext: 0,
                pSignatureSettings: ptr::null_mut(),
            };

            unsafe {
                // Set the file info in the union
                *trust_data.union1.pFile_mut() = &mut file_info;

                // Get GUID for action
                let action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

                // Verify trust
                let status = WinVerifyTrust(
                    0,
                    &action_guid,
                    &mut trust_data as *mut _ as *mut _,
                );

                // Reset state
                trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(
                    0,
                    &action_guid,
                    &mut trust_data as *mut _ as *mut _,
                );

                if status == 0 {
                    debug!("Digital signature verification passed for: {}", path_str);
                    Ok(true)
                } else if status == TRUST_E_SUBJECT_NOT_TRUSTED as i32 {
                    warn!("Digital signature not trusted for: {}", path_str);
                    Err(SignatureError::UntrustedCertificate(path_str))
                } else {
                    warn!("Digital signature verification failed for: {} with status: {}", path_str, status);
                    Err(SignatureError::VerificationFailed(format!(
                        "Verification failed with status code: {}", status
                    )))
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // For non-Windows platforms, we'd need to implement alternative verification methods
            // For example, using OpenSSL or other platform-specific APIs
            warn!("Digital signature verification not implemented for this platform");
            Err(SignatureError::PlatformNotSupported)
        }
    }
    
    /// Wrapper for verifying installer signatures
    pub fn verify_installer_signature<P: AsRef<Path>>(&self, path: P) -> Result<bool, SignatureError> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();
        
        info!("Verifying digital signature of installer: {}", path_str);
        match self.verify_signature(path) {
            Ok(true) => {
                info!("Installer signature verification passed: {}", path_str);
                Ok(true)
            },
            Ok(false) => {
                warn!("Installer signature verification failed: {}", path_str);
                Ok(false)
            },
            Err(e) => {
                error!("Error verifying installer signature: {}", e);
                Err(e)
            }
        }
    }
    
    /// Gets information about the digital signature
    pub fn get_signature_info<P: AsRef<Path>>(&self, path: P) -> Result<SignatureInfo, SignatureError> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();
        
        if !path.exists() {
            return Err(SignatureError::IoError(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {}", path_str)
            )));
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows, we would implement this using WinCrypt API or other Windows-specific APIs
            // This is a placeholder and would need to be implemented with actual Windows API calls
            warn!("Get signature info is not fully implemented yet");
            Ok(SignatureInfo {
                subject: "Unknown".to_string(),
                issuer: "Unknown".to_string(),
                valid_from: SystemTime::now(),
                valid_until: SystemTime::now(),
                thumbprint: "0000000000000000000000000000000000000000".to_string(),
                is_timestamped: false,
                timestamp: None,
                algorithm: "SHA256".to_string(),
            })
        }

        #[cfg(not(target_os = "windows"))]
        {
            warn!("Digital signature information retrieval not implemented for this platform");
            Err(SignatureError::PlatformNotSupported)
        }
    }
}

impl Default for DigitalSignature {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_verify_unsigned_file() {
        // This test will create a temporary file that is obviously not signed
        // and checks that the verification correctly identifies it as unsigned
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let path = temp_file.path();
        
        let signature = DigitalSignature::new();
        
        // Depending on platform, this test might behave differently
        if cfg!(target_os = "windows") {
            // On Windows it should return an error indicating untrusted certificate
            // or verification failed, since the file is not signed
            match signature.verify_signature(path) {
                Err(SignatureError::UntrustedCertificate(_)) => {},
                Err(SignatureError::VerificationFailed(_)) => {},
                other => panic!("Expected UntrustedCertificate or VerificationFailed error, got: {:?}", other),
            }
        } else {
            // On other platforms it should return UnsupportedPlatform error
            match signature.verify_signature(path) {
                Err(SignatureError::PlatformNotSupported) => {},
                other => panic!("Expected PlatformNotSupported error, got: {:?}", other),
            }
        }
    }
    
    #[test]
    #[cfg(target_os = "windows")]
    fn test_verify_system_file() {
        // This test tries to verify a known signed Windows system file
        // This should only run on Windows
        let system32_path = PathBuf::from(r"C:\Windows\System32\ntdll.dll");
        
        if system32_path.exists() {
            let signature = DigitalSignature::new();
            let result = signature.verify_signature(&system32_path);
            
            // The file should be properly signed
            assert!(result.is_ok() && result.unwrap());
        } else {
            // If we can't find the file, we'll skip the test
            println!("Skipping test_verify_system_file as system file not found");
        }
    }
} 