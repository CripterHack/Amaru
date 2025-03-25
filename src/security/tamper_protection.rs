use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::collections::HashMap;

use log::{error, info, warn};
use tokio::sync::Mutex;
use tokio::time::sleep;
use thiserror::Error;
use serde::{Serialize, Deserialize};
use rand::{Rng, thread_rng};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Sha256, Digest};

use crate::AmaruError;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Gestor de protección contra manipulación
pub struct TamperProtection {
    /// Gestor de integridad de archivos
    integrity_manager: Arc<IntegrityManager>,
    
    /// Lista de archivos protegidos
    protected_files: Arc<Mutex<HashMap<String, ProtectedFileInfo>>>,
    
    /// Clave de encriptación para datos sensibles
    encryption_key: [u8; 32],
    
    /// Directorio de trabajo
    work_dir: PathBuf,
    
    /// Flag para indicar si la protección está activa
    active: Arc<Mutex<bool>>,
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
        if !work_dir.exists() {
            fs::create_dir_all(&work_dir)
                .map_err(|e| TamperProtectionError::Io(e))?;
        }
        
        // Generar o cargar clave de encriptación
        let encryption_key = if let Some(key_file) = key_file {
            Self::load_or_create_key(key_file)?
        } else {
            // Usar una clave aleatoria en memoria (no persistente)
            let mut key = [0u8; 32];
            thread_rng().fill(&mut key);
            key
        };
        
        let instance = Self {
            integrity_manager,
            protected_files: Arc::new(Mutex::new(HashMap::new())),
            encryption_key,
            work_dir,
            active: Arc::new(Mutex::new(false)),
        };
        
        Ok(instance)
    }
    
    /// Carga o crea una clave de encriptación en disco
    fn load_or_create_key(key_file: impl AsRef<Path>) -> Result<[u8; 32], TamperProtectionError> {
        let key_file = key_file.as_ref();
        
        if key_file.exists() {
            // Cargar clave existente
            let mut file = File::open(key_file)
                .map_err(|e| TamperProtectionError::Io(e))?;
            
            let mut encoded_key = String::new();
            file.read_to_string(&mut encoded_key)
                .map_err(|e| TamperProtectionError::Io(e))?;
            
            // Decodificar la clave
            let key_bytes = BASE64.decode(encoded_key.trim())
                .map_err(|e| TamperProtectionError::DecryptionError(e.to_string()))?;
            
            if key_bytes.len() != 32 {
                return Err(TamperProtectionError::DecryptionError(
                    "Longitud de clave incorrecta".to_string()
                ));
            }
            
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            Ok(key)
        } else {
            // Crear nueva clave
            let mut key = [0u8; 32];
            thread_rng().fill(&mut key);
            
            // Crear directorio padre si no existe
            if let Some(parent) = key_file.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)
                        .map_err(|e| TamperProtectionError::Io(e))?;
                }
            }
            
            // Guardar clave encriptada
            let encoded_key = BASE64.encode(&key);
            let mut file = File::create(key_file)
                .map_err(|e| TamperProtectionError::Io(e))?;
            
            // Establecer permisos restrictivos
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = fs::Permissions::from_mode(0o600); // solo lectura/escritura para el propietario
                fs::set_permissions(key_file, perms)
                    .map_err(|e| TamperProtectionError::PermissionError(e.to_string()))?;
            }
            
            file.write_all(encoded_key.as_bytes())
                .map_err(|e| TamperProtectionError::Io(e))?;
            
            info!("Nueva clave de protección generada y almacenada en: {}", key_file.display());
            Ok(key)
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
        let ciphertext = cipher.encrypt(&nonce_val, data)
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
                "Datos encriptados inválidos".to_string()
            ));
        }
        
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);
        
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| TamperProtectionError::DecryptionError(e.to_string()))?;
        
        Ok(plaintext)
    }
    
    /// Encripta un archivo y lo guarda en la ubicación especificada
    pub fn encrypt_file(&self, source: impl AsRef<Path>, dest: impl AsRef<Path>) -> Result<(), TamperProtectionError> {
        let source = source.as_ref();
        let dest = dest.as_ref();
        
        // Leer archivo
        let mut file = File::open(source)
            .map_err(|e| TamperProtectionError::Io(e))?;
        
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|e| TamperProtectionError::Io(e))?;
        
        // Encriptar contenido
        let encrypted = self.encrypt_data(&contents)?;
        
        // Guardar archivo encriptado
        let mut output = File::create(dest)
            .map_err(|e| TamperProtectionError::Io(e))?;
        
        output.write_all(&encrypted)
            .map_err(|e| TamperProtectionError::Io(e))?;
        
        Ok(())
    }
    
    /// Desencripta un archivo y lo guarda en la ubicación especificada
    pub fn decrypt_file(&self, source: impl AsRef<Path>, dest: impl AsRef<Path>) -> Result<(), TamperProtectionError> {
        let source = source.as_ref();
        let dest = dest.as_ref();
        
        // Leer archivo encriptado
        let mut file = File::open(source)
            .map_err(|e| TamperProtectionError::Io(e))?;
        
        let mut encrypted = Vec::new();
        file.read_to_end(&mut encrypted)
            .map_err(|e| TamperProtectionError::Io(e))?;
        
        // Desencriptar contenido
        let decrypted = self.decrypt_data(&encrypted)?;
        
        // Guardar archivo desencriptado
        let mut output = File::create(dest)
            .map_err(|e| TamperProtectionError::Io(e))?;
        
        output.write_all(&decrypted)
            .map_err(|e| TamperProtectionError::Io(e))?;
        
        Ok(())
    }
    
    /// Registra un archivo para protección contra manipulación
    pub async fn protect_file(&self, path: impl AsRef<Path>, importance: u8) -> Result<(), TamperProtectionError> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();
        
        // Verificar que el archivo existe
        if !path.exists() {
            return Err(TamperProtectionError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Archivo no encontrado: {}", path_str)
            )));
        }
        
        // Obtener información del archivo
        let metadata = fs::metadata(path)
            .map_err(|e| TamperProtectionError::Io(e))?;
        
        // Calcular hash del archivo
        let hash = match self.integrity_manager.calculate_file_hash(path) {
            Ok(hash) => hash,
            Err(e) => return Err(TamperProtectionError::InternalError(format!(
                "Error al calcular hash: {}", e
            ))),
        };
        
        // Registrar el archivo en el gestor de integridad si es importante
        if importance >= 70 {
            match self.integrity_manager.register_file(path, importance >= 90).await {
                Ok(_) => {},
                Err(e) => warn!("No se pudo registrar archivo en gestor de integridad: {}", e),
            }
        }
        
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
        
        // Registrar archivo
        let mut protected_files = self.protected_files.lock().await;
        protected_files.insert(path_str, file_info);
        
        Ok(())
    }
    
    /// Verifica un archivo protegido
    pub async fn verify_file(&self, path: impl AsRef<Path>) -> Result<FileStatus, TamperProtectionError> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();
        
        // Obtener información del archivo
        let protected_files = self.protected_files.lock().await;
        let file_info = match protected_files.get(&path_str) {
            Some(info) => info.clone(),
            None => return Err(TamperProtectionError::InternalError(format!(
                "Archivo no registrado para protección: {}", path_str
            ))),
        };
        drop(protected_files); // Liberar el lock
        
        // Verificar existencia
        if !path.exists() {
            let mut protected_files = self.protected_files.lock().await;
            if let Some(info) = protected_files.get_mut(&path_str) {
                info.status = FileStatus::Missing;
            }
            return Ok(FileStatus::Missing);
        }
        
        // Calcular hash actual
        let current_hash = match self.integrity_manager.calculate_file_hash(path) {
            Ok(hash) => hash,
            Err(e) => return Err(TamperProtectionError::InternalError(format!(
                "Error al calcular hash: {}", e
            ))),
        };
        
        // Verificar tamaño
        let metadata = fs::metadata(path)
            .map_err(|e| TamperProtectionError::Io(e))?;
        
        // Actualizar estado
        let status = if current_hash != file_info.hash {
            if file_info.importance >= 90 {
                FileStatus::Tampered
            } else {
                FileStatus::Modified
            }
        } else if metadata.len() != file_info.size {
            if file_info.importance >= 90 {
                FileStatus::Tampered
            } else {
                FileStatus::Modified
            }
        } else {
            FileStatus::Valid
        };
        
        // Actualizar información
        let mut protected_files = self.protected_files.lock().await;
        if let Some(info) = protected_files.get_mut(&path_str) {
            info.hash = current_hash;
            info.size = metadata.len();
            info.status = status.clone();
            info.last_check = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        
        Ok(status)
    }
    
    /// Inicia la protección contra manipulación
    pub async fn start(&self) -> Result<(), TamperProtectionError> {
        let mut active = self.active.lock().await;
        if *active {
            return Ok(());
        }
        
        *active = true;
        drop(active);
        
        let protected_files_clone = self.protected_files.clone();
        let active_clone = self.active.clone();
        let integrity_manager_clone = Arc::clone(&self.integrity_manager);
        
        // Iniciar tarea de verificación periódica
        tokio::spawn(async move {
            // Iniciar verificación periódica de archivos críticos
            let _ = integrity_manager_clone.start_periodic_check().await;
            
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Verificar cada 5 minutos
            
            loop {
                interval.tick().await;
                
                // Verificar si la protección sigue activa
                let active = active_clone.lock().await;
                if !*active {
                    break;
                }
                drop(active);
                
                // Obtener lista de archivos protegidos
                let protected_files = protected_files_clone.lock().await;
                let files: Vec<String> = protected_files.keys().cloned().collect();
                drop(protected_files);
                
                // Verificar cada archivo
                for path_str in files {
                    let path = PathBuf::from(&path_str);
                    if path.exists() {
                        // Realizar verificación
                        let protected_files = protected_files_clone.lock().await;
                        if let Some(info) = protected_files.get(&path_str) {
                            // Solo verificar archivos importantes regularmente
                            if info.importance >= 70 {
                                drop(protected_files);
                                
                                // Calcular hash actual
                                match integrity_manager_clone.calculate_file_hash(&path) {
                                    Ok(current_hash) => {
                                        let mut protected_files = protected_files_clone.lock().await;
                                        if let Some(info) = protected_files.get_mut(&path_str) {
                                            let old_hash = info.hash.clone();
                                            
                                            // Verificar cambio de hash
                                            if current_hash != old_hash {
                                                if info.importance >= 90 {
                                                    error!("ALERTA DE SEGURIDAD: Archivo crítico manipulado: {}", path_str);
                                                    info.status = FileStatus::Tampered;
                                                    // Aquí se podría implementar una acción adicional
                                                } else {
                                                    warn!("Archivo protegido ha sido modificado: {}", path_str);
                                                    info.status = FileStatus::Modified;
                                                }
                                            }
                                            
                                            // Actualizar información
                                            info.hash = current_hash;
                                            info.last_check = SystemTime::now()
                                                .duration_since(SystemTime::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs();
                                        }
                                    },
                                    Err(e) => {
                                        error!("Error al verificar hash de archivo protegido {}: {}", path_str, e);
                                    }
                                }
                            } else {
                                drop(protected_files);
                            }
                        } else {
                            drop(protected_files);
                        }
                    } else {
                        // Archivo faltante
                        let mut protected_files = protected_files_clone.lock().await;
                        if let Some(info) = protected_files.get_mut(&path_str) {
                            if info.status != FileStatus::Missing {
                                info.status = FileStatus::Missing;
                                if info.importance >= 90 {
                                    error!("ALERTA DE SEGURIDAD: Archivo crítico eliminado: {}", path_str);
                                    // Aquí se podría implementar una acción adicional
                                } else {
                                    warn!("Archivo protegido ha sido eliminado: {}", path_str);
                                }
                            }
                        }
                    }
                }
                
                // Esperar un poco entre cada verificación para no sobrecargar el sistema
                sleep(Duration::from_millis(100)).await;
            }
        });
        
        Ok(())
    }
    
    /// Detiene la protección contra manipulación
    pub async fn stop(&self) -> Result<(), TamperProtectionError> {
        let mut active = self.active.lock().await;
        *active = false;
        Ok(())
    }
    
    /// Verifica todos los archivos protegidos
    pub async fn verify_all(&self) -> Result<HashMap<String, FileStatus>, TamperProtectionError> {
        let protected_files = self.protected_files.lock().await;
        let files: Vec<String> = protected_files.keys().cloned().collect();
        drop(protected_files);
        
        let mut results = HashMap::new();
        
        for path_str in files {
            let path = PathBuf::from(&path_str);
            let status = self.verify_file(&path).await?;
            results.insert(path_str, status);
        }
        
        Ok(results)
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
        let integrity_manager = Arc::new(
            IntegrityManager::new(dir.path().join("integrity.json"), 3600).await.unwrap()
        );
        
        // Crear protección contra manipulación
        let tamper_protection = TamperProtection::new(
            integrity_manager,
            dir.path(),
            None as Option<&Path>,
        ).await.unwrap();
        
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
        let integrity_manager = Arc::new(
            IntegrityManager::new(dir.path().join("integrity.json"), 3600).await.unwrap()
        );
        
        // Crear protección contra manipulación
        let tamper_protection = TamperProtection::new(
            integrity_manager,
            dir.path(),
            Some(dir.path().join("key.dat")),
        ).await.unwrap();
        
        // Crear archivo de prueba
        let test_file = dir.path().join("test.txt");
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "Contenido de prueba para protección").unwrap();
        file.flush().unwrap();
        
        // Proteger archivo
        tamper_protection.protect_file(&test_file, 80).await.unwrap();
        
        // Verificar archivo (debe ser válido)
        let status = tamper_protection.verify_file(&test_file).await.unwrap();
        assert!(matches!(status, FileStatus::Valid));
        
        // Modificar archivo
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&test_file)
            .unwrap();
        writeln!(file, "Contenido adicional no autorizado").unwrap();
        file.flush().unwrap();
        
        // Verificar archivo (debe detectar modificación)
        let status = tamper_protection.verify_file(&test_file).await.unwrap();
        assert!(matches!(status, FileStatus::Modified));
    }
} 