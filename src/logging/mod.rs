use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{Level, LevelFilter, Metadata, Record};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use serde_json::json;
use std::fs::{self, File, OpenOptions};
use std::io::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub target: String,
    pub message: String,
    pub module: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub thread: String,
    pub additional: Option<serde_json::Value>,
}

pub struct RotatingFileLogger {
    log_dir: PathBuf,
    current_log: Arc<Mutex<File>>,
    max_size: u64,        // Tamaño máximo en bytes
    max_files: usize,     // Número máximo de archivos de respaldo
    current_size: Arc<Mutex<u64>>,
}

impl RotatingFileLogger {
    pub fn new(log_dir: PathBuf, max_size: u64, max_files: usize) -> Result<Self, std::io::Error> {
        fs::create_dir_all(&log_dir)?;
        
        let current_log_path = log_dir.join("amaru.log");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&current_log_path)?;
            
        let size = file.metadata()?.len();
        
        Ok(Self {
            log_dir,
            current_log: Arc::new(Mutex::new(file)),
            max_size,
            max_files,
            current_size: Arc::new(Mutex::new(size)),
        })
    }
    
    async fn rotate_logs(&self) -> Result<(), std::io::Error> {
        // Renombrar archivos existentes
        for i in (1..self.max_files).rev() {
            let from = self.log_dir.join(format!("amaru.{}.log", i));
            let to = self.log_dir.join(format!("amaru.{}.log", i + 1));
            if from.exists() {
                fs::rename(from, to)?;
            }
        }
        
        // Mover el archivo actual
        let current = self.log_dir.join("amaru.log");
        let backup = self.log_dir.join("amaru.1.log");
        if current.exists() {
            fs::rename(&current, backup)?;
        }
        
        // Crear nuevo archivo
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&current)?;
            
        let mut current_log = self.current_log.lock().await;
        *current_log = new_file;
        
        let mut current_size = self.current_size.lock().await;
        *current_size = 0;
        
        Ok(())
    }
    
    pub async fn write_entry(&self, entry: &LogEntry) -> Result<(), std::io::Error> {
        let entry_json = serde_json::to_string(&entry)?;
        let entry_bytes = entry_json.as_bytes();
        
        let mut current_size = self.current_size.lock().await;
        
        // Verificar si necesitamos rotar
        if *current_size + entry_bytes.len() as u64 > self.max_size {
            drop(current_size); // Liberar el lock antes de rotar
            self.rotate_logs().await?;
            current_size = self.current_size.lock().await;
        }
        
        // Escribir entrada
        let mut file = self.current_log.lock().await;
        file.write_all(entry_bytes)?;
        file.write_all(b"\n")?;
        file.flush()?;
        
        *current_size += entry_bytes.len() as u64 + 1;
        Ok(())
    }
}

pub struct AmaruLogger {
    rotating_logger: Arc<RotatingFileLogger>,
    level_filter: LevelFilter,
}

impl AmaruLogger {
    pub fn new(log_dir: PathBuf, max_size: u64, max_files: usize, level: LevelFilter) -> Result<Self, std::io::Error> {
        Ok(Self {
            rotating_logger: Arc::new(RotatingFileLogger::new(log_dir, max_size, max_files)?),
            level_filter: level,
        })
    }
}

impl log::Log for AmaruLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level_filter
    }
    
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        
        let entry = LogEntry {
            timestamp: Utc::now(),
            level: record.level().to_string(),
            target: record.target().to_string(),
            message: record.args().to_string(),
            module: record.module_path().unwrap_or("unknown").to_string(),
            file: record.file().map(String::from),
            line: record.line(),
            thread: std::thread::current().name().unwrap_or("unknown").to_string(),
            additional: None,
        };
        
        let logger = self.rotating_logger.clone();
        tokio::spawn(async move {
            if let Err(e) = logger.write_entry(&entry).await {
                eprintln!("Error writing log entry: {}", e);
            }
        });
    }
    
    fn flush(&self) {}
}

pub fn init_logging(log_dir: PathBuf, level: LevelFilter) -> Result<(), Box<dyn std::error::Error>> {
    let logger = AmaruLogger::new(
        log_dir,
        10 * 1024 * 1024, // 10 MB por archivo
        5,                 // Mantener 5 archivos de respaldo
        level,
    )?;
    
    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(level);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use log::{debug, error, info, warn};
    
    #[tokio::test]
    async fn test_rotating_logger() {
        let temp_dir = tempdir().unwrap();
        let log_dir = temp_dir.path().to_path_buf();
        
        // Crear logger con tamaño pequeño para probar rotación
        let logger = RotatingFileLogger::new(
            log_dir.clone(),
            100, // 100 bytes máximo
            3,   // 3 archivos de respaldo
        ).unwrap();
        
        // Escribir entradas hasta forzar rotación
        for i in 0..10 {
            let entry = LogEntry {
                timestamp: Utc::now(),
                level: "INFO".to_string(),
                target: "test".to_string(),
                message: format!("Test message {}", i),
                module: "test_module".to_string(),
                file: Some("test.rs".to_string()),
                line: Some(1),
                thread: "main".to_string(),
                additional: None,
            };
            
            logger.write_entry(&entry).await.unwrap();
        }
        
        // Verificar archivos de respaldo
        assert!(log_dir.join("amaru.log").exists());
        assert!(log_dir.join("amaru.1.log").exists());
    }
    
    #[test]
    fn test_logger_initialization() {
        let temp_dir = tempdir().unwrap();
        let log_dir = temp_dir.path().to_path_buf();
        
        init_logging(log_dir.clone(), LevelFilter::Debug).unwrap();
        
        // Generar algunos logs
        debug!("Debug message");
        info!("Info message");
        warn!("Warning message");
        error!("Error message");
        
        // Verificar que el archivo existe y contiene logs
        let log_content = fs::read_to_string(log_dir.join("amaru.log")).unwrap();
        assert!(log_content.contains("Debug message"));
        assert!(log_content.contains("Error message"));
    }
} 