use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::time::{SystemTime, Duration};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time;
use thiserror::Error;
use serde::{Serialize, Deserialize};
use log::{LevelFilter, Level, Record, Metadata};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

// Type alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

/// Errores relacionados con el logging seguro
#[derive(Error, Debug)]
pub enum SecureLoggingError {
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("HMAC calculation error: {0}")]
    HmacError(String),
    
    #[error("Tampered log detected: {0}")]
    TamperedLog(String),
    
    #[error("Log rotation error: {0}")]
    RotationError(String),
    
    #[error("Internal logging error: {0}")]
    InternalError(String),
}

/// Nivel de sensibilidad de los logs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensitivityLevel {
    /// Información pública, no sensible
    Public,
    
    /// Información interna, levemente sensible
    Internal,
    
    /// Información sensible, requiere ser ocultada
    Sensitive,
    
    /// Información crítica, requiere encriptación
    Critical,
}

/// Entrada de log seguro
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureLogEntry {
    /// Timestamp de la entrada
    pub timestamp: DateTime<Utc>,
    
    /// Nivel de log
    pub level: String,
    
    /// Mensaje de log
    pub message: String,
    
    /// Módulo que generó el log
    pub module: String,
    
    /// Ubicación en el código
    pub location: String,
    
    /// Nivel de sensibilidad
    pub sensitivity: SensitivityLevel,
    
    /// HMAC para verificar integridad
    pub hmac: String,
    
    /// Contador secuencial
    pub sequence: u64,
}

/// Estructura para configurar el logger seguro
#[derive(Debug, Clone)]
pub struct SecureLoggerConfig {
    /// Ruta base para los archivos de log
    pub log_dir: PathBuf,
    
    /// Tamaño máximo del archivo de log antes de rotar (en bytes)
    pub max_log_size: u64,
    
    /// Número máximo de archivos de log a mantener
    pub max_log_files: usize,
    
    /// Nivel mínimo de log a registrar
    pub min_log_level: LevelFilter,
    
    /// Clave para HMAC (debe ser secreta)
    pub hmac_key: Vec<u8>,
    
    /// Si se deben encriptar los logs sensibles
    pub encrypt_sensitive: bool,
    
    /// Si se debe usar formato JSON para los logs
    pub use_json_format: bool,
}

impl Default for SecureLoggerConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("logs"),
            max_log_size: 10 * 1024 * 1024, // 10 MB
            max_log_files: 10,
            min_log_level: LevelFilter::Info,
            hmac_key: vec![0; 32], // Por defecto, debe ser reemplazada
            encrypt_sensitive: false,
            use_json_format: true,
        }
    }
}

/// Logger seguro que integra verificación de integridad
pub struct SecureLogger {
    /// Configuración del logger
    config: SecureLoggerConfig,
    
    /// Ruta al archivo de log actual
    current_log_file: PathBuf,
    
    /// Contador secuencial para entradas de log
    sequence_counter: Arc<Mutex<u64>>,
    
    /// HMAC calculation instance
    hmac: Arc<Mutex<HmacSha256>>,
}

impl SecureLogger {
    /// Crea una nueva instancia del logger seguro
    pub async fn new<P: AsRef<Path>>(base_dir: P, config: Option<SecureLoggerConfig>) -> Result<Self, SecureLoggingError> {
        let base_dir = base_dir.as_ref().to_path_buf();
        let mut config = config.unwrap_or_default();
        
        // Set log directory to be within the base directory
        config.log_dir = base_dir.join(&config.log_dir);
        
        // Ensure log directory exists
        fs::create_dir_all(&config.log_dir)
            .map_err(|e| SecureLoggingError::IoError(e))?;
        
        // Generate a random HMAC key if not provided
        if config.hmac_key.iter().all(|&x| x == 0) {
            config.hmac_key = Self::generate_hmac_key()?;
            
            // Save the key to a file for future verification
            let key_path = config.log_dir.join("hmac.key");
            let encoded_key = BASE64.encode(&config.hmac_key);
            fs::write(&key_path, encoded_key)
                .map_err(|e| SecureLoggingError::IoError(e))?;
        }
        
        // Create HMAC instance
        let hmac = HmacSha256::new_from_slice(&config.hmac_key)
            .map_err(|e| SecureLoggingError::HmacError(e.to_string()))?;
        
        // Determine the current log file
        let current_log_file = config.log_dir.join(format!("secure_{}.log", 
            chrono::Utc::now().format("%Y%m%d_%H%M%S")));
        
        // Initialize sequence counter
        let sequence_counter = Self::initialize_sequence_counter(&config.log_dir).await?;
        
        let logger = SecureLogger {
            config,
            current_log_file,
            sequence_counter: Arc::new(Mutex::new(sequence_counter)),
            hmac: Arc::new(Mutex::new(hmac)),
        };
        
        // Startup log entry
        logger.log(
            Level::Info,
            "Secure logging initialized",
            "secure_logging",
            "secure_logging.rs:0",
            SensitivityLevel::Internal
        ).await?;
        
        Ok(logger)
    }
    
    /// Initialize the sequence counter from existing logs
    async fn initialize_sequence_counter(log_dir: &Path) -> Result<u64, SecureLoggingError> {
        let mut highest_seq = 0;
        
        // Find all log files
        let log_files = match fs::read_dir(log_dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    if let Some(ext) = entry.path().extension() {
                        ext == "log"
                    } else {
                        false
                    }
                })
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        
        // Read the last entry of each log to find the highest sequence number
        for entry in log_files {
            let path = entry.path();
            
            // Try to read the last few bytes of the file to find the last entry
            if let Ok(mut file) = File::open(&path) {
                let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
                
                // Read the last 4KB of the file, which should contain at least one log entry
                let read_size = std::cmp::min(4096, file_size as usize);
                if read_size > 0 {
                    let offset = if file_size > read_size as u64 {
                        file_size - read_size as u64
                    } else {
                        0
                    };
                    
                    if let Ok(_) = file.seek(SeekFrom::Start(offset)) {
                        let mut buffer = vec![0; read_size];
                        if let Ok(_) = file.read(&mut buffer) {
                            // Look for the last complete line
                            let content = String::from_utf8_lossy(&buffer);
                            let lines: Vec<&str> = content.lines().collect();
                            
                            for line in lines.iter().rev() {
                                // Try to parse as JSON
                                if let Ok(entry) = serde_json::from_str::<SecureLogEntry>(line) {
                                    if entry.sequence > highest_seq {
                                        highest_seq = entry.sequence;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(highest_seq)
    }
    
    /// Generates a random HMAC key
    fn generate_hmac_key() -> Result<Vec<u8>, SecureLoggingError> {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill(&mut key[..]);
        Ok(key)
    }
    
    /// Lee las entradas de un archivo de log
    pub async fn read_log_entries<P: AsRef<Path>>(&self, path: P) -> Result<Vec<SecureLogEntry>, SecureLoggingError> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(SecureLoggingError::IoError(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Log file not found: {}", path.display())
            )));
        }
        
        let file = File::open(path)
            .map_err(|e| SecureLoggingError::IoError(e))?;
        
        let mut entries = Vec::new();
        let reader = io::BufReader::new(file);
        
        for line in io::BufRead::lines(reader) {
            let line = line.map_err(|e| SecureLoggingError::IoError(e))?;
            
            if line.trim().is_empty() {
                continue;
            }
            
            let entry: SecureLogEntry = serde_json::from_str(&line)
                .map_err(|e| SecureLoggingError::SerializationError(e.to_string()))?;
            
            entries.push(entry);
        }
        
        Ok(entries)
    }
    
    /// Calcula el HMAC para una entrada de log
    fn calculate_hmac(&self, entry: &SecureLogEntry) -> Result<String, SecureLoggingError> {
        let mut hmac = self.hmac.blocking_lock();
        
        // Exclude the HMAC field itself from the calculation
        let hmac_data = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            entry.timestamp.to_rfc3339(),
            entry.level,
            entry.message,
            entry.module,
            entry.location,
            serde_json::to_string(&entry.sensitivity).unwrap_or_default(),
            entry.sequence
        );
        
        hmac.update(hmac_data.as_bytes());
        let result = hmac.finalize_reset();
        let hmac_bytes = result.into_bytes();
        
        Ok(BASE64.encode(&hmac_bytes))
    }
    
    /// Valida el HMAC de una entrada de log
    fn validate_hmac(&self, entry: &SecureLogEntry) -> Result<bool, SecureLoggingError> {
        let stored_hmac = &entry.hmac;
        let calculated_hmac = self.calculate_hmac(entry)?;
        
        Ok(calculated_hmac == *stored_hmac)
    }
    
    /// Registro de log con nivel de sensibilidad
    pub async fn log(
        &self,
        level: Level,
        message: &str,
        module: &str,
        location: &str,
        sensitivity: SensitivityLevel,
    ) -> Result<(), SecureLoggingError> {
        // Verificar si el nivel de log debe ser registrado
        if level < self.config.min_log_level.to_level().unwrap_or(Level::Error) {
            return Ok(());
        }
        
        // Incrementar el contador secuencial
        let sequence = {
            let mut counter = self.sequence_counter.lock().await;
            *counter += 1;
            *counter
        };
        
        // Crear entrada de log
        let mut entry = SecureLogEntry {
            timestamp: Utc::now(),
            level: level.to_string(),
            message: message.to_string(),
            module: module.to_string(),
            location: location.to_string(),
            sensitivity,
            hmac: String::new(), // Se calculará más adelante
            sequence,
        };
        
        // Calcular HMAC
        entry.hmac = self.calculate_hmac(&entry)?;
        
        // Escribir entrada de log al archivo
        self.write_log_entry(&entry).await?;
        
        // Verificar si se necesita rotar los logs
        self.check_rotation().await?;
        
        Ok(())
    }
    
    /// Escribe una entrada de log al archivo
    async fn write_log_entry(&self, entry: &SecureLogEntry) -> Result<(), SecureLoggingError> {
        // Serializar la entrada de log
        let log_line = if self.config.use_json_format {
            serde_json::to_string(entry)
                .map_err(|e| SecureLoggingError::SerializationError(e.to_string()))?
        } else {
            format!(
                "[{}] [{}] [{}] [{}] [{}] {}",
                entry.timestamp.to_rfc3339(),
                entry.level,
                entry.module,
                entry.location,
                match entry.sensitivity {
                    SensitivityLevel::Public => "PUBLIC",
                    SensitivityLevel::Internal => "INTERNAL",
                    SensitivityLevel::Sensitive => "SENSITIVE",
                    SensitivityLevel::Critical => "CRITICAL",
                },
                entry.message
            )
        };
        
        // Crear o abrir el archivo de log
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.current_log_file)
            .map_err(|e| SecureLoggingError::IoError(e))?;
        
        let mut writer = io::BufWriter::new(file);
        
        // Escribir la entrada de log
        writeln!(writer, "{}", log_line)
            .map_err(|e| SecureLoggingError::IoError(e))?;
        
        writer.flush()
            .map_err(|e| SecureLoggingError::IoError(e))?;
        
        Ok(())
    }
    
    /// Verifica y rota el archivo de log si es necesario
    async fn check_rotation(&self) -> Result<(), SecureLoggingError> {
        // Verificar si el archivo actual existe y su tamaño
        if !self.current_log_file.exists() {
            return Ok(());
        }
        
        // Verificar si el tamaño del archivo excede el máximo
        let metadata = fs::metadata(&self.current_log_file)
            .map_err(|e| SecureLoggingError::IoError(e))?;
        
        if metadata.len() > self.config.max_log_size {
            self.rotate_logs().await?;
        }
        
        Ok(())
    }
    
    /// Rota los archivos de log
    async fn rotate_logs(&self) -> Result<(), SecureLoggingError> {
        // Crear un nuevo archivo de log
        let new_log_file = self.config.log_dir.join(format!("secure_{}.log", 
            chrono::Utc::now().format("%Y%m%d_%H%M%S")));
        
        // Encontrar todos los archivos de log existentes
        let log_files = match fs::read_dir(&self.config.log_dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    if let Some(ext) = entry.path().extension() {
                        ext == "log"
                    } else {
                        false
                    }
                })
                .map(|entry| entry.path())
                .collect::<Vec<_>>(),
            Err(e) => return Err(SecureLoggingError::IoError(e)),
        };
        
        // Si tenemos demasiados archivos de log, eliminar los más antiguos
        if log_files.len() >= self.config.max_log_files {
            // Ordenar por tiempo de modificación
            let mut log_files_with_time = Vec::new();
            
            for path in log_files {
                if let Ok(metadata) = fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        log_files_with_time.push((path, modified));
                    }
                }
            }
            
            // Ordenar por tiempo de modificación, primero los más antiguos
            log_files_with_time.sort_by(|a, b| a.1.cmp(&b.1));
            
            // Eliminar los archivos de log más antiguos
            let files_to_delete = log_files_with_time.len() - self.config.max_log_files + 1;
            for i in 0..files_to_delete {
                let path = &log_files_with_time[i].0;
                fs::remove_file(path)
                    .map_err(|e| SecureLoggingError::RotationError(format!(
                        "No se pudo eliminar archivo de log antiguo: {}: {}", path.display(), e
                    )))?;
            }
        }
        
        // Establecer el nuevo archivo de log como el actual
        unsafe {
            // Esto es seguro porque solo estamos modificando la ruta
            let mutable_self = self as *const SecureLogger as *mut SecureLogger;
            (*mutable_self).current_log_file = new_log_file;
        }
        
        Ok(())
    }
    
    /// Limpia logs antiguos según la configuración
    pub async fn cleanup_old_logs(&self, max_age: Duration) -> Result<(), SecureLoggingError> {
        // Encontrar todos los archivos de log
        let log_files = match fs::read_dir(&self.config.log_dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    if let Some(ext) = entry.path().extension() {
                        ext == "log"
                    } else {
                        false
                    }
                })
                .map(|entry| entry.path())
                .collect::<Vec<_>>(),
            Err(e) => return Err(SecureLoggingError::IoError(e)),
        };
        
        let now = SystemTime::now();
        
        // Eliminar archivos de log más antiguos que max_age
        for path in log_files {
            if path == self.current_log_file {
                continue; // No eliminar el archivo de log actual
            }
            
            if let Ok(metadata) = fs::metadata(&path) {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(duration) = now.duration_since(modified) {
                        if duration > max_age {
                            fs::remove_file(&path)
                                .map_err(|e| SecureLoggingError::IoError(e))?;
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Verifica la integridad de un archivo de log
    pub async fn verify_log_integrity<P: AsRef<Path>>(&self, path: P) -> Result<bool, SecureLoggingError> {
        let entries = self.read_log_entries(path).await?;
        
        if entries.is_empty() {
            return Ok(true);
        }
        
        // Verificar que los números de secuencia sean consecutivos
        let mut expected_seq = entries[0].sequence;
        
        for entry in &entries {
            // Validar HMAC
            if !self.validate_hmac(entry)? {
                return Ok(false);
            }
            
            // Verificar secuencia
            if entry.sequence != expected_seq {
                return Ok(false);
            }
            
            expected_seq += 1;
        }
        
        Ok(true)
    }
    
    /// Busca entradas de log que coincidan con ciertos criterios
    pub async fn search_logs(&self, keyword: &str, sensitivity: Option<SensitivityLevel>) -> Result<Vec<SecureLogEntry>, SecureLoggingError> {
        let mut results = Vec::new();
        
        // Encontrar todos los archivos de log
        let log_files = match fs::read_dir(&self.config.log_dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    if let Some(ext) = entry.path().extension() {
                        ext == "log"
                    } else {
                        false
                    }
                })
                .map(|entry| entry.path())
                .collect::<Vec<_>>(),
            Err(e) => return Err(SecureLoggingError::IoError(e)),
        };
        
        // Buscar en cada archivo de log
        for path in log_files {
            let entries = self.read_log_entries(&path).await?;
            
            for entry in entries {
                // Filtrar por sensibilidad si se especifica
                if let Some(sens) = sensitivity {
                    if entry.sensitivity != sens {
                        continue;
                    }
                }
                
                // Buscar en mensaje, módulo y ubicación
                if entry.message.contains(keyword) 
                   || entry.module.contains(keyword)
                   || entry.location.contains(keyword) {
                    results.push(entry);
                }
            }
        }
        
        Ok(results)
    }
    
    /// Exporta logs a un archivo CSV
    pub async fn export_to_csv<P: AsRef<Path>>(&self, output_path: P) -> Result<(), SecureLoggingError> {
        let output_path = output_path.as_ref();
        
        // Crear escritor CSV
        let file = File::create(output_path)
            .map_err(|e| SecureLoggingError::IoError(e))?;
        
        let mut writer = csv::Writer::from_writer(file);
        
        // Escribir encabezado
        writer.write_record(&[
            "Timestamp", "Level", "Module", "Location", "Sensitivity", "Message", "Sequence"
        ]).map_err(|e| SecureLoggingError::SerializationError(e.to_string()))?;
        
        // Encontrar todos los archivos de log
        let log_files = match fs::read_dir(&self.config.log_dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    if let Some(ext) = entry.path().extension() {
                        ext == "log"
                    } else {
                        false
                    }
                })
                // Filtrar por módulo
                if let Some(mod_name) = module {
                    if !entry.module.contains(mod_name) {
                        continue;
                    }
                }
                
                // Filtrar por tiempo
                if let Some(from) = from_time {
                    if entry.timestamp < from {
                        continue;
                    }
                }
                
                if let Some(to) = to_time {
                    if entry.timestamp > to {
                        continue;
                    }
                }
                
                // Filtrar por palabras clave
                if let Some(keywords) = keywords {
                    let message_lower = entry.message.to_lowercase();
                    if !keywords.iter().any(|&k| message_lower.contains(&k.to_lowercase())) {
                        continue;
                    }
                }
                
                results.push(entry);
            }
        }
        
        // Ordenar por timestamp y secuencia
        results.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then(a.sequence.cmp(&b.sequence))
        });
        
        Ok(results)
    }
    
    /// Exporta logs a un formato específico
    pub async fn export_logs(
        &self,
        output_file: &Path,
        format: ExportFormat,
    ) -> Result<(), SecureLoggingError> {
        let existing_logs = Self::find_existing_logs(&self.config.log_dir)?;
        let mut all_entries = Vec::new();
        
        // Recopilar todas las entradas
        for log_file in existing_logs {
            let entries = self.read_log_entries(&log_file)?;
            all_entries.extend(entries);
        }
        
        // Ordenar por timestamp y secuencia
        all_entries.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then(a.sequence.cmp(&b.sequence))
        });
        
        // Exportar según el formato
        match format {
            ExportFormat::Json => {
                let json = serde_json::to_string_pretty(&all_entries)
                    .map_err(|e| SecureLoggingError::SerializationError(e.to_string()))?;
                
                let mut file = File::create(output_file)
                    .map_err(|e| SecureLoggingError::Io(e))?;
                
                file.write_all(json.as_bytes())
                    .map_err(|e| SecureLoggingError::Io(e))?;
            },
            ExportFormat::Csv => {
                let mut wtr = csv::Writer::from_path(output_file)
                    .map_err(|e| SecureLoggingError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
                
                // Escribir cabecera
                wtr.write_record(&["Timestamp", "Level", "Module", "Message", "Sequence"])
                    .map_err(|e| SecureLoggingError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
                
                // Escribir entradas
                for entry in all_entries {
                    wtr.write_record(&[
                        entry.timestamp.to_rfc3339(),
                        entry.level,
                        entry.module,
                        entry.message,
                        entry.sequence.to_string(),
                    ]).map_err(|e| SecureLoggingError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
                }
                
                wtr.flush()
                    .map_err(|e| SecureLoggingError::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
            },
            ExportFormat::Text => {
                let mut file = File::create(output_file)
                    .map_err(|e| SecureLoggingError::Io(e))?;
                
                for entry in all_entries {
                    writeln!(
                        file,
                        "[{} {}] [{}] {} (seq: {})",
                        entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        entry.level,
                        entry.module,
                        entry.message,
                        entry.sequence
                    ).map_err(|e| SecureLoggingError::Io(e))?;
                }
            },
        }
        
        Ok(())
    }
}

/// Formatos de exportación disponibles
#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    /// Formato JSON
    Json,
    
    /// Formato CSV
    Csv,
    
    /// Formato de texto plano
    Text,
}

/// Implementación de log::Log para integrarse con el sistema de logging de Rust
pub struct SecureLoggerBackend {
    inner: Arc<Mutex<SecureLogger>>,
}

impl SecureLoggerBackend {
    pub fn new(logger: SecureLogger) -> Self {
        Self {
            inner: Arc::new(Mutex::new(logger)),
        }
    }
}

impl log::Log for SecureLoggerBackend {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // Este método no puede ser async, por lo que no podemos acceder al logger interno
        // Para solucionarlo, simplemente devolvemos true y filtramos en el método log
        true
    }
    
    fn log(&self, record: &Record) {
        let level = record.level();
        let message = record.args().to_string();
        let module = record.module_path().unwrap_or("<unknown>");
        let location = record.file().map(|f| format!("{}:{}", f, record.line().unwrap_or(0)));
        
        // Determinar nivel de sensibilidad basado en el nivel de log
        let sensitivity = match level {
            Level::Error | Level::Warn => SensitivityLevel::Internal,
            Level::Info => SensitivityLevel::Public,
            Level::Debug | Level::Trace => SensitivityLevel::Sensitive,
        };
        
        // Crear una tarea para procesar el log de forma asíncrona
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let logger = inner.lock().await;
            if let Err(e) = logger.log(
                level,
                &message,
                module,
                location.as_deref(),
                sensitivity,
            ).await {
                eprintln!("Error al escribir log: {}", e);
            }
        });
    }
    
    fn flush(&self) {
        // No hay buffer que vaciar inmediatamente, ya que todo se procesa de forma asíncrona
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_logging_and_integrity() {
        let dir = tempdir().unwrap();
        let log_dir = dir.path().join("logs");
        
        // Crear configuración
        let mut config = SecureLoggerConfig::default();
        config.log_dir = log_dir.clone();
        config.hmac_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        
        // Crear logger
        let logger = SecureLogger::new(config, None).await.unwrap();
        
        // Escribir algunas entradas de log
        logger.log(
            Level::Info, 
            "Mensaje de prueba 1",
            "test_module",
            Some("test.rs:123"),
            SensitivityLevel::Public
        ).await.unwrap();
        
        logger.log(
            Level::Warn, 
            "Mensaje de advertencia",
            "test_module",
            Some("test.rs:124"),
            SensitivityLevel::Internal
        ).await.unwrap();
        
        logger.log(
            Level::Error, 
            "Mensaje de error crítico",
            "test_module",
            Some("test.rs:125"),
            SensitivityLevel::Critical
        ).await.unwrap();
        
        // Verificar integridad
        let results = logger.verify_log_integrity().await.unwrap();
        
        // Debería haber al menos un archivo de log y todos válidos
        assert!(!results.is_empty());
        for (_, is_valid) in results {
            assert!(is_valid);
        }
        
        // Buscar logs
        let logs = logger.search_logs(
            Some(Level::Warn),
            None,
            None,
            None,
            None,
        ).await.unwrap();
        
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].message, "Mensaje de advertencia");
    }
} 