use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use log::{error, warn};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use super::integrity::IntegrityManager;

/// Errores relacionados con la protección contra manipulación
#[derive(Error, Debug)]
pub enum TamperProtectionError {
    #[error("Error de E/S: {0}")]
    Io(#[from] io::Error),

    #[error("Error de encriptación: {0}")]
    EncryptionError(String),

    #[error("Error de desencriptación: {0}")]
    DecryptionError(String),

    #[error("Archivo protegido modificado: {0}")]
    FileModified(String),

    #[error("Configuración comprometida: {0}")]
    ConfigCompromised(String),

    #[error("Clave de protección no encontrada")]
    KeyNotFound,

    #[error("Error al verificar permisos: {0}")]
    PermissionError(String),

    #[error("Error interno de protección: {0}")]
    InternalError(String),

    #[error("Error de serialización: {0}")]
    SerializationError(String),

    #[error("Error de generación de clave: {0}")]
    KeyGenerationError(String),

    #[error("Alerta de modificación de archivo: {0}")]
    FileModificationAlert(String),

    #[error("Alerta de archivo faltante: {0}")]
    MissingFileAlert(String),

    #[error("Estado inválido: {0}")]
    InvalidState(String),
}

/// Estado de un archivo monitoreado
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileStatus {
    /// El archivo es válido y no ha sido modificado
    Valid,

    /// El archivo ha sido modificado pero no es crítico
    Modified,

    /// El archivo ha sido manipulado y es crítico
    Tampered,

    /// El archivo ha sido eliminado
    Missing,
}

/// Información de un archivo protegido
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedFileInfo {
    /// Ruta al archivo
    pub path: String,

    /// Hash de verificación
    pub hash: String,

    /// Tamaño original del archivo
    pub size: u64,

    /// Timestamp de la última verificación
    pub last_check: u64,

    /// Estado actual del archivo
    pub status: FileStatus,

    /// Nivel de importancia (0-100)
    pub importance: u8,
}

/// Importancia registrada entre 0 y 100. A partir de 90 el archivo es crítico.
pub type ImportanceLevel = u8;

/// Gestor de protección contra manipulación
pub struct TamperProtection {
    /// Gestor de integridad de archivos
    integrity_manager: Arc<IntegrityManager>,

    /// Lista de archivos protegidos
    protected_files: Arc<Mutex<HashMap<String, ProtectedFileInfo>>>,

    /// Clave de encriptación para datos sensibles
    encryption_key: [u8; 32],

    // Con clave persistente, restaurar el catálogo autenticado después de reiniciar.
    catalog: Option<PathBuf>,
    _catalog_lock: Option<File>,
    task: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl TamperProtection {
    /// Crea una nueva instancia de protección contra manipulación
    pub async fn new(
        integrity_manager: Arc<IntegrityManager>,
        work_dir: impl AsRef<Path>,
        key_file: Option<impl AsRef<Path>>,
    ) -> Result<Self, TamperProtectionError> {
        let work_dir = work_dir.as_ref().to_path_buf();

        // Asegurar que exista el directorio de trabajo
        fs::create_dir_all(&work_dir)?;

        let catalog = key_file
            .as_ref()
            .map(|_| work_dir.join("protected-files.aes"));
        let catalog_lock = if catalog.is_some() {
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(work_dir.join("protected-files.lock"))?;
            lock.try_lock()
                .map_err(|err| io::Error::other(err.to_string()))?;
            Some(lock)
        } else {
            None
        };
        let encryption_key = match key_file {
            Some(path) => {
                if !path.as_ref().try_exists()?
                    && work_dir.join("protected-files.aes").try_exists()?
                {
                    return Err(TamperProtectionError::KeyNotFound);
                }
                Self::load_or_create_key(path)?
            }
            None => thread_rng().gen(),
        };
        let instance = Self {
            integrity_manager,
            protected_files: Default::default(),
            encryption_key,
            catalog,
            _catalog_lock: catalog_lock,
            task: Default::default(),
        };
        if let Some(path) = &instance.catalog {
            match fs::read(path) {
                Ok(bytes) => {
                    let plaintext = instance.decrypt_data(&bytes)?;
                    *instance.protected_files.lock().await = serde_json::from_slice(&plaintext)
                        .map_err(|err| TamperProtectionError::ConfigCompromised(err.to_string()))?;
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(instance)
    }

    fn private_file(path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)
    }

    fn replace_file(path: &Path, data: &[u8]) -> io::Result<()> {
        let tmp = path.with_file_name(format!(".amaru-{:032x}.tmp", thread_rng().gen::<u128>()));
        let mut file = Self::private_file(&tmp)?;
        let result = (|| -> io::Result<()> {
            file.write_all(data)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    fn load_or_create_key(key_file: impl AsRef<Path>) -> Result<[u8; 32], TamperProtectionError> {
        let path = key_file.as_ref();
        match fs::read_to_string(path) {
            Ok(text) => BASE64
                .decode(text.trim())
                .map_err(|err| TamperProtectionError::DecryptionError(err.to_string()))?
                .try_into()
                .map_err(|_| {
                    TamperProtectionError::DecryptionError("Longitud de clave incorrecta".into())
                }),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let key: [u8; 32] = thread_rng().gen();
                let mut file = Self::private_file(path)?;
                file.write_all(BASE64.encode(key).as_bytes())?;
                file.sync_all()?;
                Ok(key)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Encripta datos sensibles usando la clave de protección
    pub fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, TamperProtectionError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);

        // Generar nonce aleatorio
        let nonce_val = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce = nonce_val.as_slice();

        // Encriptar datos
        let ciphertext = cipher
            .encrypt(&nonce_val, data)
            .map_err(|e| TamperProtectionError::EncryptionError(e.to_string()))?;

        // Formato: [nonce (12 bytes)][ciphertext]
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Desencripta datos usando la clave de protección
    pub fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, TamperProtectionError> {
        if encrypted_data.len() < 12 {
            return Err(TamperProtectionError::DecryptionError(
                "Datos encriptados inválidos".to_string(),
            ));
        }

        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| TamperProtectionError::DecryptionError(e.to_string()))?;

        Ok(plaintext)
    }

    /// Encripta un archivo y lo guarda en la ubicación especificada
    pub fn encrypt_file(
        &self,
        source: impl AsRef<Path>,
        dest: impl AsRef<Path>,
    ) -> Result<(), TamperProtectionError> {
        let source = source.as_ref();
        let dest = dest.as_ref();

        // Leer archivo
        let encrypted = self.encrypt_data(&fs::read(source)?)?;
        Self::replace_file(dest, &encrypted)?;
        Ok(())
    }

    /// Desencripta un archivo y lo guarda en la ubicación especificada
    pub fn decrypt_file(
        &self,
        source: impl AsRef<Path>,
        dest: impl AsRef<Path>,
    ) -> Result<(), TamperProtectionError> {
        let source = source.as_ref();
        let dest = dest.as_ref();

        // Leer archivo encriptado
        let decrypted = self.decrypt_data(&fs::read(source)?)?;
        Self::replace_file(dest, &decrypted)?;
        Ok(())
    }

    fn persist_catalog(
        &self,
        files: &HashMap<String, ProtectedFileInfo>,
    ) -> Result<(), TamperProtectionError> {
        if let Some(catalog) = &self.catalog {
            let bytes = serde_json::to_vec(files)
                .map_err(|err| TamperProtectionError::SerializationError(err.to_string()))?;
            Self::replace_file(catalog, &self.encrypt_data(&bytes)?)?;
        }
        Ok(())
    }

    /// Registra un archivo para protección contra manipulación
    pub async fn protect_file(
        &self,
        path: impl AsRef<Path>,
        importance: u8,
    ) -> Result<(), TamperProtectionError> {
        let path = path.as_ref();
        let path_str = path
            .to_str()
            .ok_or_else(|| {
                TamperProtectionError::InvalidState(
                    "La ruta no se puede representar en UTF-8".into(),
                )
            })?
            .to_string();

        if importance > 100 {
            return Err(TamperProtectionError::InvalidState(
                "La importancia debe estar entre 0 y 100".into(),
            ));
        }
        let mut protected_files = self.protected_files.lock().await;
        let metadata = fs::metadata(path)?;
        let hash = self
            .integrity_manager
            .calculate_file_hash(path)
            .await
            .map_err(|err| TamperProtectionError::InternalError(err.to_string()))?;
        // Timestamp actual
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Crear información del archivo protegido
        let file_info = ProtectedFileInfo {
            path: path_str.clone(),
            hash,
            size: metadata.len(),
            last_check: now,
            status: FileStatus::Valid,
            importance,
        };

        let mut candidate = protected_files.clone();
        candidate.insert(path_str, file_info);
        self.persist_catalog(&candidate)?;
        if importance >= 70 {
            if let Err(err) = self
                .integrity_manager
                .register_file(path, importance >= 90)
                .await
            {
                self.persist_catalog(&protected_files)?;
                return Err(TamperProtectionError::InternalError(err.to_string()));
            }
        }
        *protected_files = candidate;
        Ok(())
    }

    /// Verifica un archivo protegido
    pub async fn verify_file(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<FileStatus, TamperProtectionError> {
        Self::verify_registered(
            &self.integrity_manager,
            &self.protected_files,
            path.as_ref(),
        )
        .await
    }

    async fn verify_registered(
        integrity: &IntegrityManager,
        files: &Mutex<HashMap<String, ProtectedFileInfo>>,
        path: &Path,
    ) -> Result<FileStatus, TamperProtectionError> {
        let name = path.to_str().ok_or_else(|| {
            TamperProtectionError::InvalidState("La ruta no se puede representar en UTF-8".into())
        })?;
        let mut files = files.lock().await;
        let entry = files.get_mut(name).ok_or_else(|| {
            TamperProtectionError::InvalidState(format!(
                "Archivo no registrado para protección: {name}"
            ))
        })?;
        let status = match fs::metadata(path) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => FileStatus::Missing,
            Err(err) => return Err(err.into()),
            Ok(metadata) => {
                let hash = integrity
                    .calculate_file_hash(path)
                    .await
                    .map_err(|err| TamperProtectionError::InternalError(err.to_string()))?;
                if hash == entry.hash && metadata.len() == entry.size {
                    FileStatus::Valid
                } else if entry.importance >= 90 {
                    FileStatus::Tampered
                } else {
                    FileStatus::Modified
                }
            }
        };
        // La referencia aprobada solo cambia al registrar el archivo de forma explícita.
        entry.status = status;
        entry.last_check = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(status)
    }

    /// Comprueba periódicamente los archivos de importancia alta o crítica.
    pub async fn start(&self) -> Result<(), TamperProtectionError> {
        let mut task = self
            .task
            .lock()
            .map_err(|err| TamperProtectionError::InternalError(err.to_string()))?;
        if task.as_ref().is_some_and(|t| !t.is_finished()) {
            return Ok(());
        }
        let files = Arc::clone(&self.protected_files);
        let integrity = Arc::clone(&self.integrity_manager);
        *task = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let paths: Vec<_> = files
                    .lock()
                    .await
                    .values()
                    .filter(|f| f.importance >= 70)
                    .map(|f| f.path.clone())
                    .collect();
                for path in paths {
                    match Self::verify_registered(&integrity, &files, Path::new(&path)).await {
                        Ok(FileStatus::Valid) => {}
                        Ok(status) => warn!("Archivo protegido {path}: {status:?}"),
                        Err(err) => error!("Error al verificar {path}: {err}"),
                    }
                }
            }
        }));
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), TamperProtectionError> {
        let task = self
            .task
            .lock()
            .map_err(|err| TamperProtectionError::InternalError(err.to_string()))?
            .take();
        if let Some(task) = task {
            task.abort();
            match task.await {
                Ok(()) => {}
                Err(err) if err.is_cancelled() => {}
                Err(err) => return Err(TamperProtectionError::InternalError(err.to_string())),
            }
        }
        Ok(())
    }

    /// Verifica todos los archivos protegidos
    pub async fn verify_all(&self) -> Result<HashMap<String, FileStatus>, TamperProtectionError> {
        self.verify_all_files()
            .await
            .into_iter()
            .map(|(path, status)| Ok((path, status?)))
            .collect()
    }

    pub async fn verify_all_files(
        &self,
    ) -> HashMap<String, Result<FileStatus, TamperProtectionError>> {
        let paths: Vec<_> = self.protected_files.lock().await.keys().cloned().collect();
        let mut results = HashMap::new();
        for path in paths {
            let status = self.verify_file(&path).await;
            results.insert(path, status);
        }
        results
    }
}

impl Drop for TamperProtection {
    fn drop(&mut self) {
        if let Some(task) = self
            .task
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_encryption_decryption() {
        let dir = tempdir().unwrap();

        // Crear gestor de integridad
        let integrity_manager = Arc::new(IntegrityManager::new(dir.path()).await.unwrap());

        // Crear protección contra manipulación
        let tamper_protection =
            TamperProtection::new(integrity_manager, dir.path(), None as Option<&Path>)
                .await
                .unwrap();

        // Probar encriptación/desencriptación
        let original_data = b"Datos secretos para prueba";
        let encrypted = tamper_protection.encrypt_data(original_data).unwrap();
        let decrypted = tamper_protection.decrypt_data(&encrypted).unwrap();

        assert_eq!(original_data, decrypted.as_slice());
        assert_ne!(original_data, encrypted.as_slice());
    }

    #[tokio::test]
    async fn test_file_protection() {
        let dir = tempdir().unwrap();

        // Crear gestor de integridad
        let integrity_manager = Arc::new(IntegrityManager::new(dir.path()).await.unwrap());

        // Crear protección contra manipulación
        let tamper_protection = TamperProtection::new(
            integrity_manager,
            dir.path(),
            Some(dir.path().join("key.dat")),
        )
        .await
        .unwrap();

        // Crear archivo de prueba
        let test_file = dir.path().join("test.txt");
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "Contenido de prueba para protección").unwrap();
        file.flush().unwrap();

        // Proteger archivo
        tamper_protection
            .protect_file(&test_file, 80)
            .await
            .unwrap();

        // Verificar archivo (debe ser válido)
        let status = tamper_protection.verify_file(&test_file).await.unwrap();
        assert!(matches!(status, FileStatus::Valid));

        // Modificar archivo
        let mut file = OpenOptions::new().append(true).open(&test_file).unwrap();
        writeln!(file, "Contenido adicional no autorizado").unwrap();
        file.flush().unwrap();

        // Verificar archivo (debe detectar modificación)
        let status = tamper_protection.verify_file(&test_file).await.unwrap();
        assert!(matches!(status, FileStatus::Modified));
    }
    #[tokio::test]
    async fn damaged_catalog_and_missing_key_fail_closed() {
        let dir = tempdir().unwrap();
        let integrity = Arc::new(IntegrityManager::new(dir.path()).await.unwrap());
        let key = dir.path().join("key.dat");
        let data = dir.path().join("data");
        fs::write(&data, b"approved").unwrap();
        let protector = TamperProtection::new(integrity.clone(), dir.path(), Some(&key))
            .await
            .unwrap();
        protector.protect_file(&data, 99).await.unwrap();
        drop(protector);
        let catalog = dir.path().join("protected-files.aes");
        let mut bytes = fs::read(&catalog).unwrap();
        bytes[0] ^= 1;
        fs::write(&catalog, bytes).unwrap();
        assert!(
            TamperProtection::new(integrity.clone(), dir.path(), Some(&key))
                .await
                .is_err()
        );
        fs::remove_file(&key).unwrap();
        assert!(matches!(
            TamperProtection::new(integrity, dir.path(), Some(&key)).await,
            Err(TamperProtectionError::KeyNotFound)
        ));
        assert!(!key.exists());
    }
}
