use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{thread_rng, RngCore};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
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

pub struct Quarantine {
    /// Ruta del directorio de cuarentena
    path: PathBuf,
    
    /// Tamaño máximo de la cuarentena
    max_size: u64,
    
    /// Días de retención
    retention_days: u32,
    
    /// Clave de cifrado
    encryption_key: [u8; 32],
}

impl Quarantine {
    pub fn new<P: AsRef<Path>>(path: P, max_size: u64, retention_days: u32) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        
        // Generar o cargar clave de cifrado
        let key_path = path.join(".key");
        let encryption_key = if key_path.exists() {
            let mut key = [0u8; 32];
            File::open(key_path)?.read_exact(&mut key)?;
            key
        } else {
            let mut key = [0u8; 32];
            thread_rng().fill_bytes(&mut key);
            File::create(key_path)?.write_all(&key)?;
            key
        };
        
        Ok(Self {
            path,
            max_size,
            retention_days,
            encryption_key,
        })
    }
    
    /// Mover archivo a cuarentena
    pub fn quarantine_file<P: AsRef<Path>>(&self, file_path: P, reason: &str) -> Result<QuarantineEntry, QuarantineError> {
        let file_path = file_path.as_ref();
        
        // Verificar espacio disponible
        let file_size = file_path.metadata()?.len();
        let current_size = self.get_current_size()?;
        if current_size + file_size > self.max_size {
            return Err(QuarantineError::InsufficientSpace);
        }
        
        // Generar nombre único
        let quarantine_name = format!("{}.quar", SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs());
        
        // Leer archivo original
        let mut content = Vec::new();
        File::open(file_path)?.read_to_end(&mut content)?;
        
        // Calcular hash original
        let original_hash = sha2::Sha256::digest(&content);
        let original_hash = BASE64.encode(original_hash);
        
        // Cifrar contenido
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| QuarantineError::Encryption(e.to_string()))?;
            
        let mut nonce = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);
        
        let encrypted = cipher
            .encrypt(nonce, content.as_ref())
            .map_err(|e| QuarantineError::Encryption(e.to_string()))?;
        
        // Guardar archivo cifrado
        let quarantine_path = self.path.join(&quarantine_name);
        let mut file = File::create(&quarantine_path)?;
        file.write_all(nonce)?;
        file.write_all(&encrypted)?;
        
        // Crear entrada
        let entry = QuarantineEntry {
            original_path: file_path.to_path_buf(),
            quarantine_name,
            quarantine_date: Utc::now(),
            original_hash,
            file_size,
            reason: reason.to_string(),
        };
        
        // Guardar metadata
        self.save_entry(&entry)?;
        
        // Eliminar archivo original
        fs::remove_file(file_path)?;
        
        Ok(entry)
    }
    
    /// Restaurar archivo desde cuarentena
    pub fn restore_file(&self, entry: &QuarantineEntry) -> Result<(), QuarantineError> {
        let quarantine_path = self.path.join(&entry.quarantine_name);
        
        // Leer archivo cifrado
        let mut file = File::open(&quarantine_path)?;
        let mut nonce = [0u8; 12];
        file.read_exact(&mut nonce)?;
        
        let mut encrypted = Vec::new();
        file.read_to_end(&mut encrypted)?;
        
        // Descifrar contenido
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| QuarantineError::Decryption(e.to_string()))?;
            
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce), encrypted.as_ref())
            .map_err(|e| QuarantineError::Decryption(e.to_string()))?;
        
        // Verificar hash
        let hash = sha2::Sha256::digest(&decrypted);
        let hash = BASE64.encode(hash);
        if hash != entry.original_hash {
            return Err(QuarantineError::Decryption("Hash verification failed".into()));
        }
        
        // Restaurar archivo
        if let Some(parent) = entry.original_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        
        fs::write(&entry.original_path, decrypted)?;
        fs::remove_file(quarantine_path)?;
        self.remove_entry(entry)?;
        
        Ok(())
    }
    
    /// Eliminar archivo de cuarentena
    pub fn delete_file(&self, entry: &QuarantineEntry) -> Result<(), QuarantineError> {
        let quarantine_path = self.path.join(&entry.quarantine_name);
        fs::remove_file(quarantine_path)?;
        self.remove_entry(entry)?;
        Ok(())
    }
    
    /// Limpiar archivos antiguos
    pub fn cleanup(&self) -> io::Result<()> {
        let entries = self.list_entries()?;
        let now = Utc::now();
        
        for entry in entries {
            let age = now - entry.quarantine_date;
            if age.num_days() > self.retention_days as i64 {
                let _ = self.delete_file(&entry);
            }
        }
        
        Ok(())
    }
    
    /// Listar archivos en cuarentena
    pub fn list_entries(&self) -> io::Result<Vec<QuarantineEntry>> {
        let metadata_path = self.path.join("metadata.json");
        if !metadata_path.exists() {
            return Ok(Vec::new());
        }
        
        let content = fs::read_to_string(metadata_path)?;
        let entries: Vec<QuarantineEntry> = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            
        Ok(entries)
    }
    
    // Métodos privados
    
    fn save_entry(&self, entry: &QuarantineEntry) -> io::Result<()> {
        let mut entries = self.list_entries()?;
        entries.push(entry.clone());
        
        let metadata_path = self.path.join("metadata.json");
        let content = serde_json::to_string_pretty(&entries)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            
        fs::write(metadata_path, content)
    }
    
    fn remove_entry(&self, entry: &QuarantineEntry) -> io::Result<()> {
        let mut entries = self.list_entries()?;
        entries.retain(|e| e.quarantine_name != entry.quarantine_name);
        
        let metadata_path = self.path.join("metadata.json");
        let content = serde_json::to_string_pretty(&entries)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            
        fs::write(metadata_path, content)
    }
    
    fn get_current_size(&self) -> io::Result<u64> {
        let mut total = 0;
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                total += entry.metadata()?.len();
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::io::Write;
    
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
    fn test_cleanup() -> io::Result<()> {
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