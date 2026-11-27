use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use log::{Level, LevelFilter, Metadata, Record};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use thiserror::Error;
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
#[derive(Clone)]
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

impl std::fmt::Debug for SecureLoggerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureLoggerConfig")
            .field("log_dir", &self.log_dir)
            .field("max_log_size", &self.max_log_size)
            .field("max_log_files", &self.max_log_files)
            .field("min_log_level", &self.min_log_level)
            .field("hmac_key", &"[redacted]")
            .field("encrypt_sensitive", &self.encrypt_sensitive)
            .field("use_json_format", &self.use_json_format)
            .finish()
    }
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

struct LogState {
    current: PathBuf,
    committed_bytes: u64,
    sequence: u64,
}

/// El bloqueo de directorio impide que dos procesos roten los mismos archivos.
pub struct SecureLogger {
    config: SecureLoggerConfig,
    state: Mutex<LogState>,
    _directory_lock: File,
}

impl SecureLogger {
    pub async fn new<P: AsRef<Path>>(
        base_dir: P,
        config: Option<SecureLoggerConfig>,
    ) -> Result<Self, SecureLoggingError> {
        let mut config = config.unwrap_or_default();
        config.log_dir = base_dir.as_ref().join(&config.log_dir);
        if config.max_log_files == 0 || config.max_log_size == 0 {
            return Err(SecureLoggingError::RotationError(
                "Log retention limits must be positive".into(),
            ));
        }
        fs::create_dir_all(&config.log_dir)?;
        let directory_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(config.log_dir.join("secure.lock"))?;
        directory_lock
            .try_lock()
            .map_err(|err| io::Error::other(err.to_string()))?;
        let files = Self::log_files(&config.log_dir)?;
        if config.hmac_key.iter().all(|byte| *byte == 0) {
            let path = config.log_dir.join("hmac.key");
            match fs::read_to_string(&path) {
                Ok(text) => {
                    config.hmac_key = BASE64
                        .decode(text.trim())
                        .map_err(|err| SecureLoggingError::HmacError(err.to_string()))?;
                    if config.hmac_key.iter().all(|byte| *byte == 0) {
                        return Err(SecureLoggingError::HmacError(
                            "Empty or invalid stored key".into(),
                        ));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound && files.is_empty() => {
                    config.hmac_key = vec![0; 32];
                    OsRng.fill_bytes(&mut config.hmac_key);
                    let mut key_file = Self::create_private(&path)?;
                    key_file.write_all(BASE64.encode(&config.hmac_key).as_bytes())?;
                    key_file.sync_all()?;
                }
                Err(err) => return Err(err.into()),
            }
        }
        let mut sequence = 0;
        for path in &files {
            // El antiguo formato de texto no almacenaba secuencia ni HMAC. Se conserva en disco.
            let reader = BufReader::new(File::open(path)?);
            for line in reader.lines() {
                let line = line?;
                let legacy_text = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.len() == 22);
                if line.is_empty() || (legacy_text && line.starts_with('[')) {
                    continue;
                }
                let entry = Self::decode_line(&line)?;
                if !Self::verify_mac(&config.hmac_key, &entry)? {
                    return Err(SecureLoggingError::TamperedLog(path.display().to_string()));
                }
                sequence = sequence.max(entry.sequence);
            }
        }
        let current = Self::new_path(&config.log_dir, sequence.saturating_add(1));
        let logger = Self {
            config,
            state: Mutex::new(LogState {
                current,
                sequence,
                committed_bytes: 0,
            }),
            _directory_lock: directory_lock,
        };
        logger.append(
            Level::Info,
            "Secure logging initialized",
            "secure_logging",
            "secure_logging.rs:0",
            SensitivityLevel::Internal,
        )?;
        Ok(logger)
    }

    fn lock(&self) -> Result<MutexGuard<'_, LogState>, SecureLoggingError> {
        self.state
            .lock()
            .map_err(|_| SecureLoggingError::InternalError("Logger lock poisoned".into()))
    }

    fn create_private(path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)
    }

    fn new_path(dir: &Path, sequence: u64) -> PathBuf {
        dir.join(format!(
            "secure_{}_{:020}_{:016x}.log",
            Utc::now().format("%Y%m%d_%H%M%S"),
            sequence,
            OsRng.next_u64()
        ))
    }

    fn log_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Archivos históricos: secure_YYYYMMDD_HHMMSS.log; los nuevos añaden secuencia y nonce.
            let parts: Vec<_> = name
                .strip_prefix("secure_")
                .and_then(|s| s.strip_suffix(".log"))
                .unwrap_or("")
                .split('_')
                .collect();
            let digits = |s: &str, n| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
            if (parts.len() == 2
                || (parts.len() == 4
                    && digits(parts[2], 20)
                    && parts[3].len() == 16
                    && parts[3].bytes().all(|b| b.is_ascii_hexdigit())))
                && digits(parts[0], 8)
                && digits(parts[1], 6)
                && entry.file_type()?.is_file()
            {
                files.push(entry.path());
            }
        }
        files.sort();
        Ok(files)
    }

    fn mac(key: &[u8], entry: &SecureLogEntry) -> Result<HmacSha256, SecureLoggingError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
            .map_err(|err| SecureLoggingError::HmacError(err.to_string()))?;
        if entry.hmac.starts_with("v2:") || entry.hmac.starts_with("v2e:") {
            let mode = entry.hmac.split(':').next().unwrap_or_default();
            let bytes = serde_json::to_vec(&(
                mode,
                entry.timestamp,
                &entry.level,
                &entry.message,
                &entry.module,
                &entry.location,
                entry.sensitivity,
                entry.sequence,
            ))?;
            mac.update(&bytes);
        } else {
            let bytes = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                entry.timestamp.to_rfc3339(),
                entry.level,
                entry.message,
                entry.module,
                entry.location,
                serde_json::to_string(&entry.sensitivity)?,
                entry.sequence
            );
            mac.update(bytes.as_bytes());
        }
        Ok(mac)
    }

    fn verify_mac(key: &[u8], entry: &SecureLogEntry) -> Result<bool, SecureLoggingError> {
        let tag = entry
            .hmac
            .strip_prefix("v2:")
            .or_else(|| entry.hmac.strip_prefix("v2e:"))
            .unwrap_or(&entry.hmac);
        let Ok(tag) = BASE64.decode(tag) else {
            return Ok(false);
        };
        Ok(Self::mac(key, entry)?.verify_slice(&tag).is_ok())
    }

    fn cipher(&self) -> Result<Aes256Gcm, SecureLoggingError> {
        let mut kdf = <HmacSha256 as Mac>::new_from_slice(&self.config.hmac_key)
            .map_err(|err| SecureLoggingError::HmacError(err.to_string()))?;
        kdf.update(b"Amaru secure log AES-256-GCM key v1");
        Ok(Aes256Gcm::new(&kdf.finalize().into_bytes()))
    }

    fn encrypt(&self, entry: &mut SecureLogEntry) -> Result<(), SecureLoggingError> {
        let mut nonce = [0; 12];
        OsRng.fill_bytes(&mut nonce);
        let payload = serde_json::to_vec(&(&entry.message, &entry.module, &entry.location))?;
        let ciphertext = self
            .cipher()?
            .encrypt(Nonce::from_slice(&nonce), payload.as_slice())
            .map_err(|_| SecureLoggingError::InternalError("Log encryption failed".into()))?;
        entry.message = BASE64.encode([nonce.as_slice(), &ciphertext].concat());
        entry.module.clear();
        entry.location.clear();
        Ok(())
    }

    fn decrypt(&self, entry: &mut SecureLogEntry) -> Result<(), SecureLoggingError> {
        if entry.hmac.starts_with("v2e:") {
            let invalid = || {
                SecureLoggingError::TamperedLog(format!(
                    "Invalid encrypted record {}",
                    entry.sequence
                ))
            };
            let bytes = BASE64.decode(&entry.message).map_err(|_| invalid())?;
            if bytes.len() < 12 {
                return Err(invalid());
            }
            let (nonce, ciphertext) = bytes.split_at(12);
            let plaintext = self
                .cipher()?
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| invalid())?;
            (entry.message, entry.module, entry.location) = serde_json::from_slice(&plaintext)?;
        }
        Ok(())
    }

    // En formato texto los campos se escapan individualmente, preservando tabuladores y saltos de línea.
    fn encode_line(&self, entry: &SecureLogEntry) -> Result<String, SecureLoggingError> {
        if self.config.use_json_format {
            return Ok(serde_json::to_string(entry)?);
        }
        Ok(format!(
            "AMARU2\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            entry.timestamp.to_rfc3339(),
            entry.level,
            serde_json::to_string(&entry.module)?,
            serde_json::to_string(&entry.location)?,
            serde_json::to_string(&entry.sensitivity)?,
            serde_json::to_string(&entry.message)?,
            entry.sequence,
            entry.hmac
        ))
    }

    fn decode_line(line: &str) -> Result<SecureLogEntry, SecureLoggingError> {
        if let Some(fields) = line.strip_prefix("AMARU2\t") {
            let fields: Vec<_> = fields.split('\t').collect();
            if let [date, level, module, location, sensitivity, message, sequence, hmac] =
                fields.as_slice()
            {
                return Ok(SecureLogEntry {
                    timestamp: date.parse().map_err(|e: chrono::ParseError| {
                        SecureLoggingError::SerializationError(e.to_string())
                    })?,
                    level: level.to_string(),
                    message: serde_json::from_str(message)?,
                    module: serde_json::from_str(module)?,
                    location: serde_json::from_str(location)?,
                    sensitivity: serde_json::from_str(sensitivity)?,
                    hmac: hmac.to_string(),
                    sequence: sequence.parse().map_err(|e: std::num::ParseIntError| {
                        SecureLoggingError::SerializationError(e.to_string())
                    })?,
                });
            }
            return Err(SecureLoggingError::SerializationError(
                "Incomplete text log record".into(),
            ));
        }
        Ok(serde_json::from_str(line)?)
    }

    pub async fn log(
        &self,
        level: Level,
        message: &str,
        module: &str,
        location: &str,
        sensitivity: SensitivityLevel,
    ) -> Result<(), SecureLoggingError> {
        self.append(level, message, module, location, sensitivity)
    }

    fn append(
        &self,
        level: Level,
        message: &str,
        module: &str,
        location: &str,
        sensitivity: SensitivityLevel,
    ) -> Result<(), SecureLoggingError> {
        if level > self.config.min_log_level {
            return Ok(());
        }
        let mut state = self.lock()?;
        let sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| SecureLoggingError::InternalError("Log sequence exhausted".into()))?;
        let encrypted = self.config.encrypt_sensitive
            && matches!(
                sensitivity,
                SensitivityLevel::Sensitive | SensitivityLevel::Critical
            );
        let mut entry = SecureLogEntry {
            timestamp: Utc::now(),
            level: level.to_string(),
            message: message.to_string(),
            module: module.to_string(),
            location: location.to_string(),
            sensitivity,
            sequence,
            hmac: if encrypted { "v2e:" } else { "v2:" }.into(),
        };
        if encrypted {
            self.encrypt(&mut entry)?;
        }
        let tag = BASE64.encode(
            Self::mac(&self.config.hmac_key, &entry)?
                .finalize()
                .into_bytes(),
        );
        entry.hmac.push_str(&tag);
        let mut line = self.encode_line(&entry)?;
        line.push('\n');
        let size = match fs::metadata(&state.current) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.into()),
        };
        if size != state.committed_bytes {
            return Err(SecureLoggingError::TamperedLog(
                state.current.display().to_string(),
            ));
        }
        let path = if size > 0 && size.saturating_add(line.len() as u64) > self.config.max_log_size
        {
            Self::new_path(&self.config.log_dir, sequence)
        } else {
            state.current.clone()
        };
        let new_file = size == 0 || path != state.current;
        let mut file = if new_file {
            Self::create_private(&path)?
        } else {
            OpenOptions::new().append(true).open(&path)?
        };
        let start_size = file.metadata()?.len();
        if let Err(err) = file
            .write_all(line.as_bytes())
            .and_then(|_| file.sync_data())
        {
            file.set_len(start_size)?;
            drop(file);
            if new_file {
                fs::remove_file(&path)?;
            }
            return Err(err.into());
        }
        state.committed_bytes = start_size + line.len() as u64;
        state.current = path;
        state.sequence = sequence;
        if new_file {
            let old: Vec<_> = Self::log_files(&self.config.log_dir)?
                .into_iter()
                .filter(|p| p != &state.current)
                .collect();
            for path in old
                .iter()
                .take(old.len().saturating_sub(self.config.max_log_files - 1))
            {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    pub async fn cleanup_old_logs(&self, max_age: Duration) -> Result<(), SecureLoggingError> {
        let state = self.lock()?;
        for path in Self::log_files(&self.config.log_dir)? {
            if path != state.current
                && fs::metadata(&path)?
                    .modified()?
                    .elapsed()
                    .is_ok_and(|age| age > max_age)
            {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    fn read_checked(&self, path: &Path) -> Result<Vec<SecureLogEntry>, SecureLoggingError> {
        let mut entries = Vec::new();
        let mut previous: Option<u64> = None;
        for line in BufReader::new(File::open(path)?).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let mut entry = Self::decode_line(&line)?;
            if !Self::verify_mac(&self.config.hmac_key, &entry)?
                || previous.is_some_and(|n| n.checked_add(1) != Some(entry.sequence))
            {
                return Err(SecureLoggingError::TamperedLog(path.display().to_string()));
            }
            previous = Some(entry.sequence);
            self.decrypt(&mut entry)?;
            entries.push(entry);
        }
        Ok(entries)
    }

    pub async fn read_log_entries<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Vec<SecureLogEntry>, SecureLoggingError> {
        let _guard = self.lock()?;
        self.read_checked(path.as_ref())
    }

    pub async fn verify_log_integrity<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<bool, SecureLoggingError> {
        let state = self.lock()?;
        self.verify_file(path.as_ref(), &state)
    }

    fn verify_file(&self, path: &Path, state: &LogState) -> Result<bool, SecureLoggingError> {
        if path == state.current && state.committed_bytes > 0 {
            match fs::metadata(path) {
                Ok(metadata) if metadata.len() != state.committed_bytes => return Ok(false),
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(err) => return Err(err.into()),
                Ok(_) => {}
            }
        }
        match self.read_checked(path) {
            Ok(entries) => Ok(!entries.is_empty()),
            Err(SecureLoggingError::TamperedLog(_) | SecureLoggingError::SerializationError(_)) => {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    fn managed_files(&self, state: &LogState) -> Result<Vec<PathBuf>, SecureLoggingError> {
        let mut files = Self::log_files(&self.config.log_dir)?;
        if state.committed_bytes > 0 && !files.contains(&state.current) {
            files.push(state.current.clone());
        }
        Ok(files)
    }

    pub async fn verify_all_logs(&self) -> Result<Vec<(PathBuf, bool)>, SecureLoggingError> {
        let state = self.lock()?;
        self.managed_files(&state)?
            .into_iter()
            .map(|path| {
                let valid = self.verify_file(&path, &state)?;
                Ok((path, valid))
            })
            .collect()
    }

    fn all_entries(&self, state: &LogState) -> Result<Vec<SecureLogEntry>, SecureLoggingError> {
        let mut entries = Vec::new();
        for path in self.managed_files(state)? {
            let logs = self.read_checked(&path)?;
            if path == state.current
                && logs.last().map(|entry| entry.sequence) != Some(state.sequence)
            {
                return Err(SecureLoggingError::TamperedLog(path.display().to_string()));
            }
            entries.extend(logs);
        }
        entries.sort_by_key(|e| e.sequence);
        Ok(entries)
    }

    pub async fn search_logs(
        &self,
        keyword: &str,
        sensitivity: Option<SensitivityLevel>,
    ) -> Result<Vec<SecureLogEntry>, SecureLoggingError> {
        let _guard = self.lock()?;
        Ok(self
            .all_entries(&_guard)?
            .into_iter()
            .filter(|e| {
                sensitivity.is_none_or(|s| s == e.sensitivity)
                    && [&e.message, &e.module, &e.location]
                        .iter()
                        .any(|field| field.contains(keyword))
            })
            .collect())
    }

    /// Aplica filtros combinados. Los límites temporales son inclusivos.
    pub async fn filter_logs(
        &self,
        level: Option<Level>,
        module: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        keywords: Option<&[&str]>,
    ) -> Result<Vec<SecureLogEntry>, SecureLoggingError> {
        let _guard = self.lock()?;
        let level = level.map(|value| value.to_string());
        let keywords =
            keywords.map(|words| words.iter().map(|w| w.to_lowercase()).collect::<Vec<_>>());
        Ok(self
            .all_entries(&_guard)?
            .into_iter()
            .filter(|entry| {
                level.as_ref().is_none_or(|v| v == &entry.level)
                    && module.is_none_or(|v| entry.module.contains(v))
                    && from.is_none_or(|time| entry.timestamp >= time)
                    && to.is_none_or(|time| entry.timestamp <= time)
                    && keywords.as_ref().is_none_or(|words| {
                        let message = entry.message.to_lowercase();
                        words.iter().any(|w| message.contains(w))
                    })
            })
            .collect())
    }

    /// Exportación legible con ubicación y sensibilidad, incluidos los mensajes descifrados.
    pub async fn export_to_csv<P: AsRef<Path>>(&self, path: P) -> Result<(), SecureLoggingError> {
        self.export(path.as_ref(), ExportFormat::Csv, true)
    }

    /// Exportación legible: el mensaje, el módulo y la ubicación se descifran tras
    /// verificar el archivo. Para conservar la prueba HMAC, archivar el original.
    pub async fn export_logs(
        &self,
        path: &Path,
        format: ExportFormat,
    ) -> Result<(), SecureLoggingError> {
        self.export(path, format, false)
    }

    fn export(
        &self,
        path: &Path,
        format: ExportFormat,
        extended: bool,
    ) -> Result<(), SecureLoggingError> {
        let _guard = self.lock()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if parent == self.config.log_dir.canonicalize()?
            && (name.eq_ignore_ascii_case("hmac.key")
                || name.eq_ignore_ascii_case("secure.lock")
                || name.to_ascii_lowercase().starts_with("secure_"))
        {
            return Err(SecureLoggingError::InternalError(
                "Export would overwrite logger data".into(),
            ));
        }
        let entries = self.all_entries(&_guard)?;
        let temporary = parent.join(format!(".amaru-export-{:016x}.tmp", OsRng.next_u64()));
        let mut file = Self::create_private(&temporary)?;
        let result = (|| -> Result<(), SecureLoggingError> {
            match format {
                ExportFormat::Json => serde_json::to_writer_pretty(&file, &entries)?,
                ExportFormat::Text => {
                    for e in entries {
                        writeln!(
                            file,
                            "[{} {}] [{}] {} (seq: {})",
                            e.timestamp.format("%Y-%m-%d %H:%M:%S"),
                            e.level,
                            e.module,
                            e.message,
                            e.sequence
                        )?;
                    }
                }
                ExportFormat::Csv => {
                    let mut csv = csv::Writer::from_writer(&mut file);
                    let mut header = vec!["Timestamp", "Level", "Module"];
                    if extended {
                        header.extend(["Location", "Sensitivity"]);
                    }
                    header.extend(["Message", "Sequence"]);
                    csv.write_record(header)?;
                    for e in entries {
                        let mut row = vec![e.timestamp.to_rfc3339(), e.level, e.module];
                        if extended {
                            row.extend([e.location, format!("{:?}", e.sensitivity)]);
                        }
                        row.extend([e.message, e.sequence.to_string()]);
                        csv.write_record(row)?;
                    }
                    csv.flush()?;
                }
            }
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    Json,
    Csv,
    Text,
}

impl From<serde_json::Error> for SecureLoggingError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}
impl From<csv::Error> for SecureLoggingError {
    fn from(err: csv::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

pub struct SecureLoggerBackend {
    inner: SecureLogger,
}
impl SecureLoggerBackend {
    pub fn new(logger: SecureLogger) -> Self {
        Self { inner: logger }
    }
}
impl log::Log for SecureLoggerBackend {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.inner.config.min_log_level
    }
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let sensitivity = match record.level() {
            Level::Error | Level::Warn => SensitivityLevel::Internal,
            Level::Info => SensitivityLevel::Public,
            Level::Debug | Level::Trace => SensitivityLevel::Sensitive,
        };
        let location = record
            .file()
            .map(|f| format!("{}:{}", f, record.line().unwrap_or(0)))
            .unwrap_or_default();
        if let Err(err) = self.inner.append(
            record.level(),
            &record.args().to_string(),
            record.module_path().unwrap_or("<unknown>"),
            &location,
            sensitivity,
        ) {
            eprintln!("Error al escribir log: {err}");
        }
    }
    fn flush(&self) {} // append confirma la escritura antes de devolver el control.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn reuses_existing_key_and_authenticates_legacy_json() {
        let dir = tempdir().unwrap();
        let archived = dir.path().join("logs/secure_20250101_120000.log");
        fs::create_dir(archived.parent().unwrap()).unwrap();
        let key = [42; 32];
        fs::write(dir.path().join("logs/hmac.key"), BASE64.encode(key)).unwrap();
        // Fixed bytes produced by the original, colon-separated format.
        let date = "2025-01-01T12:00:00+00:00";
        let mut signed = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
        signed.update(b"2025-01-01T12:00:00+00:00:WARN:archived:module:file:10:\"Internal\":41");
        let old = serde_json::json!({"timestamp":date,"level":"WARN","message":"archived","module":"module","location":"file:10","sensitivity":"Internal","sequence":41,"hmac":BASE64.encode(signed.finalize().into_bytes())});
        let bytes = serde_json::to_vec(&old).unwrap();
        fs::write(&archived, &bytes).unwrap();
        let logger = SecureLogger::new(dir.path(), None).await.unwrap();
        assert!(logger.verify_log_integrity(&archived).await.unwrap());
        assert_eq!(
            logger.search_logs("initialized", None).await.unwrap()[0].sequence,
            42
        );
        assert!(SecureLogger::new(dir.path(), None).await.is_err());
        drop(logger);
        let reopened = SecureLogger::new(dir.path(), None).await.unwrap();
        assert_eq!(
            reopened.search_logs("initialized", None).await.unwrap()[1].sequence,
            43
        );
        assert_eq!(fs::read(archived).unwrap(), bytes);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_rotation_preserves_order_and_other_application_logs() {
        let dir = tempdir().unwrap();
        let config = SecureLoggerConfig {
            max_log_size: 1,
            max_log_files: 4,
            ..Default::default()
        };
        let logger = Arc::new(SecureLogger::new(dir.path(), Some(config)).await.unwrap());
        let other = dir.path().join("logs/other.log");
        fs::write(&other, "another app").unwrap();
        let mut tasks = Vec::new();
        for i in 0..20 {
            let logger = Arc::clone(&logger);
            tasks.push(tokio::spawn(async move {
                logger
                    .log(
                        Level::Warn,
                        &i.to_string(),
                        "worker",
                        "",
                        SensitivityLevel::Public,
                    )
                    .await
                    .unwrap()
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let files = logger.verify_all_logs().await.unwrap();
        assert_eq!(files.len(), 4);
        assert!(files.iter().all(|(_, ok)| *ok));
        assert_eq!(
            logger
                .search_logs("", None)
                .await
                .unwrap()
                .iter()
                .map(|e| e.sequence)
                .collect::<Vec<_>>(),
            vec![18, 19, 20, 21]
        );
        assert_eq!(fs::read_to_string(other).unwrap(), "another app");
    }

    #[tokio::test]
    async fn sensitive_text_round_trips_and_exports_field_boundaries() {
        let dir = tempdir().unwrap();
        let config = SecureLoggerConfig {
            encrypt_sensitive: true,
            use_json_format: false,
            ..Default::default()
        };
        let logger = SecureLogger::new(dir.path(), Some(config)).await.unwrap();
        let message = "private: waarde, \"test\"\nline";
        logger
            .log(
                Level::Warn,
                message,
                "sensitive-module",
                "sensitive-location",
                SensitivityLevel::Critical,
            )
            .await
            .unwrap();
        logger
            .log(
                Level::Debug,
                "filtered",
                "test",
                "",
                SensitivityLevel::Public,
            )
            .await
            .unwrap();
        let live = logger.verify_all_logs().await.unwrap()[0].0.clone();
        let disk = fs::read_to_string(&live).unwrap();
        assert_eq!(disk.lines().count(), 2);
        for item in [
            "private",
            "sensitive-module",
            "sensitive-location",
            "filtered",
        ] {
            assert!(!disk.contains(item));
        }
        let entries = logger
            .filter_logs(
                Some(Level::Warn),
                Some("module"),
                None,
                None,
                Some(&["WAARDE"]),
            )
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, message);
        assert!(logger.export_to_csv(&live).await.is_err());
        let csv = dir.path().join("export.csv");
        logger.export_to_csv(&csv).await.unwrap();
        let mut reader = csv::Reader::from_path(csv).unwrap();
        assert_eq!(reader.headers().unwrap().len(), 7);
        assert_eq!(&reader.records().last().unwrap().unwrap()[5], message);
        let output = dir.path().join("logs.json");
        logger
            .export_logs(&output, ExportFormat::Json)
            .await
            .unwrap();
        let exported: Vec<SecureLogEntry> =
            serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(exported.len(), 2);
        assert_eq!(exported[1].module, "sensitive-module");
    }

    #[tokio::test]
    async fn tampering_does_not_replace_previous_export_or_create_a_new_key() {
        let dir = tempdir().unwrap();
        let logger = SecureLogger::new(dir.path(), None).await.unwrap();
        logger
            .log(
                Level::Error,
                "one:two",
                "three",
                "test.rs",
                SensitivityLevel::Internal,
            )
            .await
            .unwrap();
        let live = logger.verify_all_logs().await.unwrap()[0].0.clone();
        let data = fs::read_to_string(&live).unwrap();
        fs::write(
            &live,
            data.replace("one:two", "one")
                .replace("\"three\"", "\"two:three\""),
        )
        .unwrap();
        assert!(!logger.verify_log_integrity(&live).await.unwrap());
        let out = dir.path().join("export.txt");
        fs::write(&out, "prior export").unwrap();
        assert!(logger.export_logs(&out, ExportFormat::Text).await.is_err());
        assert_eq!(fs::read_to_string(&out).unwrap(), "prior export");
        drop(logger);
        assert!(SecureLogger::new(dir.path(), None).await.is_err());
        let key = dir.path().join("logs/hmac.key");
        fs::remove_file(&key).unwrap();
        assert!(SecureLogger::new(dir.path(), None).await.is_err());
        assert!(!key.exists());
    }
    #[tokio::test]
    async fn reports_removed_active_log_and_refuses_to_append() {
        let dir = tempdir().unwrap();
        let logger = SecureLogger::new(dir.path(), None).await.unwrap();
        let live = logger.verify_all_logs().await.unwrap()[0].0.clone();
        fs::remove_file(&live).unwrap();
        assert_eq!(
            logger.verify_all_logs().await.unwrap(),
            vec![(live.clone(), false)]
        );
        assert!(!logger.verify_log_integrity(&live).await.unwrap());
        assert!(logger
            .log(
                Level::Warn,
                "lost history",
                "",
                "",
                SensitivityLevel::Public
            )
            .await
            .is_err());
        assert!(logger.search_logs("", None).await.is_err());
        assert!(!live.exists());
    }
}
