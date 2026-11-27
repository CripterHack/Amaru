use std::{io, path::Path, time::SystemTime};
use thiserror::Error;

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

    /// Checks the embedded Authenticode signature or the installed system catalog.
    pub fn verify_signature<P: AsRef<Path>>(&self, path: P) -> Result<bool, SignatureError> {
        let file = std::fs::File::open(path.as_ref())?;
        #[cfg(windows)]
        {
            native::with_verified_file(&file, path.as_ref(), |_| Ok(true))
        }
        #[cfg(not(windows))]
        {
            drop(file);
            Err(SignatureError::PlatformNotSupported)
        }
    }

    pub fn verify_installer_signature<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<bool, SignatureError> {
        log::info!("Verifying installer signature: {}", path.as_ref().display());
        self.verify_signature(path)
    }

    /// Returns the certificate of the signer accepted by the Windows trust provider.
    pub fn get_signature_info<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<SignatureInfo, SignatureError> {
        let file = std::fs::File::open(path.as_ref())?;
        #[cfg(windows)]
        {
            native::with_verified_file(&file, path.as_ref(), native::signer_info)
        }
        #[cfg(not(windows))]
        {
            drop(file);
            Err(SignatureError::PlatformNotSupported)
        }
    }
}

impl Default for DigitalSignature {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        ffi::CStr,
        fs::File,
        mem::{size_of, zeroed},
        os::windows::{ffi::OsStrExt, io::AsRawHandle},
        ptr,
        time::{Duration, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        Foundation::{
            CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_REVOKED, CERT_E_UNTRUSTEDROOT,
            CERT_E_WRONG_USAGE, CRYPT_E_NOT_FOUND, ERROR_NOT_FOUND, FILETIME, HANDLE,
            TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE,
            TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_SUBJECT_NOT_TRUSTED,
        },
        Security::{
            Cryptography::{
                Catalog::*, CertGetCertificateContextProperty, CertGetNameStringW, CERT_CONTEXT,
                CERT_NAME_ISSUER_FLAG, CERT_NAME_RDN_TYPE, CERT_SHA1_HASH_PROP_ID,
            },
            WinTrust::*,
        },
    };

    // WINTRUST_DATA, FILE_INFO and CATALOG_INFO have optional pointer fields whose ABI default is NULL.
    // All pointers remain live for both the verification and the matching state close.
    fn inspect<T>(
        choice: u32,
        subject: WINTRUST_DATA_0,
        read: fn(HANDLE) -> Result<T, SignatureError>,
    ) -> Result<T, SignatureError> {
        unsafe {
            let mut data = WINTRUST_DATA {
                cbStruct: size_of::<WINTRUST_DATA>() as u32,
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
                dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4,
                dwUnionChoice: choice,
                Anonymous: subject,
                dwStateAction: WTD_STATEACTION_VERIFY,
                ..zeroed()
            };
            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let status = WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            );
            let result = match status {
                0 => read(data.hWVTStateData),
                TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
                    Err(SignatureError::NotSigned)
                }
                TRUST_E_BAD_DIGEST => Err(SignatureError::InvalidSignature),
                CERT_E_EXPIRED => Err(SignatureError::ExpiredSignature),
                TRUST_E_SUBJECT_NOT_TRUSTED
                | TRUST_E_EXPLICIT_DISTRUST
                | CERT_E_CHAINING
                | CERT_E_UNTRUSTEDROOT
                | CERT_E_WRONG_USAGE
                | CERT_E_REVOKED => Err(SignatureError::UntrustedCertificate(format!(
                    "HRESULT {status:#010x}"
                ))),
                _ => Err(SignatureError::VerificationFailed(format!(
                    "WinVerifyTrust HRESULT {status:#010x}"
                ))),
            };
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            );
            result
        }
    }

    pub(super) fn with_verified_file<T>(
        file: &File,
        path: &Path,
        read: fn(HANDLE) -> Result<T, SignatureError>,
    ) -> Result<T, SignatureError> {
        let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path.as_ptr(),
            hFile: file.as_raw_handle(),
            pgKnownSubject: ptr::null_mut(),
        };
        match inspect(WTD_CHOICE_FILE, WINTRUST_DATA_0 { pFile: &mut info }, read) {
            Err(SignatureError::NotSigned) => {}
            result => return result,
        }
        // Windows distributes many inbox executables as catalog-signed members.
        for algorithm in ["SHA256", "SHA1"] {
            match verify_catalog(file, &path, algorithm, read) {
                Err(SignatureError::NotSigned) => {}
                result => return result,
            }
        }
        Err(SignatureError::NotSigned)
    }

    struct Catalog {
        admin: isize,
        catalog: isize,
    }
    impl Drop for Catalog {
        fn drop(&mut self) {
            unsafe {
                if self.catalog != 0 {
                    CryptCATAdminReleaseCatalogContext(self.admin, self.catalog, 0);
                }
                CryptCATAdminReleaseContext(self.admin, 0);
            }
        }
    }

    fn verify_catalog<T>(
        file: &File,
        path: &[u16],
        algorithm: &str,
        read: fn(HANDLE) -> Result<T, SignatureError>,
    ) -> Result<T, SignatureError> {
        let algorithm: Vec<_> = algorithm.encode_utf16().chain(Some(0)).collect();
        let mut admin = 0;
        // Each catalog lookup hashes the same open file handle passed to WinVerifyTrust.
        unsafe {
            if CryptCATAdminAcquireContext2(
                &mut admin,
                ptr::null(),
                algorithm.as_ptr(),
                ptr::null(),
                0,
            ) == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            let mut guard = Catalog { admin, catalog: 0 };
            let mut size = 0;
            if CryptCATAdminCalcHashFromFileHandle2(
                admin,
                file.as_raw_handle(),
                &mut size,
                ptr::null_mut(),
                0,
            ) == 0
                || size == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            let mut hash = vec![0; size as usize];
            if CryptCATAdminCalcHashFromFileHandle2(
                admin,
                file.as_raw_handle(),
                &mut size,
                hash.as_mut_ptr(),
                0,
            ) == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            hash.truncate(size as usize);
            guard.catalog =
                CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), size, 0, ptr::null_mut());
            if guard.catalog == 0 {
                let err = io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(code) if code == ERROR_NOT_FOUND as i32 || code == CRYPT_E_NOT_FOUND => {
                        Err(SignatureError::NotSigned)
                    }
                    _ => Err(err.into()),
                };
            }
            let mut catalog = CATALOG_INFO {
                cbStruct: size_of::<CATALOG_INFO>() as u32,
                ..zeroed()
            };
            if CryptCATCatalogInfoFromContext(guard.catalog, &mut catalog, 0) == 0 {
                return Err(io::Error::last_os_error().into());
            }
            let tag: Vec<_> = hex(&hash).encode_utf16().chain(Some(0)).collect();
            let mut info = WINTRUST_CATALOG_INFO {
                cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                pcwszCatalogFilePath: catalog.wszCatalogFile.as_ptr(),
                pcwszMemberTag: tag.as_ptr(),
                pcwszMemberFilePath: path.as_ptr(),
                hMemberFile: file.as_raw_handle(),
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: size,
                hCatAdmin: admin,
                ..zeroed()
            };
            inspect(
                WTD_CHOICE_CATALOG,
                WINTRUST_DATA_0 {
                    pCatalog: &mut info,
                },
                read,
            )
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    fn cert_name(cert: &CERT_CONTEXT, flags: u32) -> Result<String, SignatureError> {
        unsafe {
            let count = CertGetNameStringW(
                cert,
                CERT_NAME_RDN_TYPE,
                flags,
                ptr::null(),
                ptr::null_mut(),
                0,
            );
            if count <= 1 {
                return Err(SignatureError::VerificationFailed(
                    "Empty certificate name".into(),
                ));
            }
            let mut text = vec![0u16; count as usize];
            if CertGetNameStringW(
                cert,
                CERT_NAME_RDN_TYPE,
                flags,
                ptr::null(),
                text.as_mut_ptr(),
                count,
            ) != count
            {
                return Err(io::Error::last_os_error().into());
            }
            String::from_utf16(&text[..count as usize - 1])
                .map_err(|err| SignatureError::VerificationFailed(err.to_string()))
        }
    }

    fn system_time(t: FILETIME) -> Result<SystemTime, SignatureError> {
        // FILETIME counts 100 ns intervals since 1601-01-01.
        const EPOCH: u64 = 116_444_736_000_000_000;
        let value = (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
        let ticks = value.abs_diff(EPOCH);
        let delta = Duration::new(ticks / 10_000_000, ((ticks % 10_000_000) * 100) as u32);
        (if value >= EPOCH {
            UNIX_EPOCH.checked_add(delta)
        } else {
            UNIX_EPOCH.checked_sub(delta)
        })
        .ok_or_else(|| SignatureError::VerificationFailed("Invalid certificate time".into()))
    }

    pub(super) fn signer_info(state: HANDLE) -> Result<SignatureInfo, SignatureError> {
        let missing = || {
            SignatureError::VerificationFailed(
                "Windows trust provider returned incomplete signer information".into(),
            )
        };
        // Provider-owned pointers are valid until WTD_STATEACTION_CLOSE in inspect.
        unsafe {
            let provider = WTHelperProvDataFromStateData(state);
            if provider.is_null() {
                return Err(missing());
            }
            let signer = WTHelperGetProvSignerFromChain(provider, 0, 0, 0);
            let signer_ref = signer.as_ref().ok_or_else(missing)?;
            let leaf = WTHelperGetProvCertFromChain(signer, 0)
                .as_ref()
                .ok_or_else(missing)?;
            let cert = leaf.pCert.as_ref().ok_or_else(missing)?;
            let info = cert.pCertInfo.as_ref().ok_or_else(missing)?;
            let signer_info = signer_ref.psSigner.as_ref().ok_or_else(missing)?;
            let oid = signer_info.HashAlgorithm.pszObjId;
            if oid.is_null() {
                return Err(missing());
            }
            let algorithm = CStr::from_ptr(oid.cast())
                .to_str()
                .map_err(|_| missing())?
                .to_owned();
            let mut digest = [0u8; 20];
            let mut len = digest.len() as u32;
            if CertGetCertificateContextProperty(
                cert,
                CERT_SHA1_HASH_PROP_ID,
                digest.as_mut_ptr().cast(),
                &mut len,
            ) == 0
                || len != digest.len() as u32
            {
                return Err(io::Error::last_os_error().into());
            }
            let timestamp = if signer_ref.csCounterSigners > 0 {
                let counter = WTHelperGetProvSignerFromChain(provider, 0, 1, 0)
                    .as_ref()
                    .ok_or_else(missing)?;
                if counter.dwError == 0 {
                    Some(system_time(signer_ref.sftVerifyAsOf)?)
                } else {
                    None
                }
            } else {
                None
            };
            Ok(SignatureInfo {
                subject: cert_name(cert, 0)?,
                issuer: cert_name(cert, CERT_NAME_ISSUER_FLAG)?,
                valid_from: system_time(info.NotBefore)?,
                valid_until: system_time(info.NotAfter)?,
                thumbprint: hex(&digest),
                is_timestamped: timestamp.is_some(),
                timestamp,
                algorithm,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_and_metadata_reject_unsigned_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsigned.txt");
        std::fs::write(&path, b"Amaru unsigned signature control").unwrap();
        let verifier = DigitalSignature::new();
        assert!(verifier.verify_signature(&path).is_err());
        assert!(verifier.get_signature_info(&path).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn reads_the_verified_certificate_of_a_windows_system_file() {
        let windows = std::env::var_os("SystemRoot").unwrap();
        let path = Path::new(&windows).join("System32").join("ntdll.dll");
        let verifier = DigitalSignature::new();
        assert!(verifier.verify_installer_signature(&path).unwrap());
        let info = verifier.get_signature_info(path).unwrap();
        assert!(!info.subject.is_empty() && !info.issuer.is_empty());
        assert!(info.valid_from < info.valid_until);
        assert_eq!(info.thumbprint.len(), 40);
        assert!(info.thumbprint.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(info.thumbprint.chars().any(|c| c != '0'));
        assert_eq!(info.is_timestamped, info.timestamp.is_some());
        assert!(!info.algorithm.is_empty());
    }

    #[test]
    fn missing_files_return_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            matches!(DigitalSignature::new().verify_signature(dir.path().join("missing")),Err(SignatureError::IoError(e)) if e.kind()==io::ErrorKind::NotFound)
        );
    }
}
