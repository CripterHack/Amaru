pub mod behavior;
pub mod config;
mod core_services;
pub mod events;
pub mod quarantine;
pub mod quick_paths;
mod resource_manager;
pub mod scheduler;
mod security;

pub use behavior::{BehaviorAnalyzer, MaliciousBehavior, MaliciousBehaviorType};
pub use config::Config;
pub use core_services::{CoreNotification, CoreServices, IntegratedScanResult};
pub use events::{ErrorCode, Event, EventChannel, RiskLevel, ThreatDetails, ThreatType};
pub use quarantine::{Quarantine, QuarantineEntry, QuarantineError};
pub use resource_manager::{ResourceManager, ResourceMetrics, SystemPriority, TaskType};

use chrono::Utc;
use parking_lot::{Mutex, RwLock};
use radare2_analyzer::{AnalysisResult, Radare2Analyzer, Radare2Config};
use realtime_monitor::{EventAction, FileEventType, MonitorConfig, MonitorStats, RealtimeMonitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::mpsc;
use yara_engine::heuristic::{ConfidenceLevel, HeuristicConfig, HeuristicEngine, HeuristicResult};
use yara_engine::{RuleMatch, YaraEngine};

#[cfg(windows)]
pub mod ipc;
#[cfg(windows)]
pub mod service;
// Re-exportar elementos de seguridad
pub use security::{
    DigitalSignature, IntegrityManager, SecureLogger, SecurityCheckResult, SecurityError,
    SecurityManager, TamperProtection,
};

// Usar el allocator optimizado
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Error, Debug)]
pub enum AmaruError {
    #[error("Error de E/S: {0}")]
    Io(#[from] std::io::Error),

    #[error("Error en el motor YARA: {0}")]
    Yara(String),

    #[error("Error en el análisis estático: {0}")]
    Analysis(String),

    #[error("Error en el sistema de cuarentena: {0}")]
    Quarantine(#[from] QuarantineError),

    #[error("File exceeds configured size limit: {0}")]
    FileTooLarge(PathBuf),

    #[error("Error de configuración: {0}")]
    Config(String),

    #[cfg(windows)]
    #[error("Error de comunicación con el servicio: {0}")]
    Ipc(#[from] ipc::IpcError),

    #[error("Error interno del sistema: {0}")]
    Internal(String),

    #[error("Error de inicialización: {0}")]
    InitializationError(String),

    #[error("Error en el monitor en tiempo real: {0}")]
    RealTimeMonitorError(String),

    #[error("Error en el sistema de actualización: {0}")]
    UpdateError(String),
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub heuristic_result: Option<HeuristicResult>,
    pub sha256: String,
    /// Elapsed wall time for this request, in seconds.
    pub scan_time: f64,
    /// Ruta del archivo
    pub path: PathBuf,

    /// Coincidencias YARA
    pub yara_matches: Vec<RuleMatch>,

    /// Análisis estático
    pub static_analysis: Option<AnalysisResult>,

    /// Nivel de riesgo
    pub risk_level: RiskLevel,

    /// Detalles de la amenaza
    pub threat_details: Option<ThreatDetails>,

    /// Análisis de comportamiento
    pub behaviors: Option<Vec<MaliciousBehavior>>,
}

/// Estado del servicio
#[derive(Debug, Clone)]
pub struct ServiceState {
    pub is_running: bool,
    pub uptime: Duration,
    pub files_monitored: usize,
    pub threats_detected: usize,
    pub scan_in_progress: bool,
    pub scan_progress: Option<ScanProgress>,
    pub last_update: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub files_scanned: usize,
    pub files_total: usize,
    pub current_file: PathBuf,
    pub start_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
struct Engines {
    yara: YaraEngine,
    heuristic: Arc<HeuristicEngine>,
    heuristic_threshold: u32,
    heuristic_enabled: bool,
}

struct CachedScan {
    engines: Arc<Engines>,
    heuristic: bool,
    radare: bool,
    result: ScanResult,
}

struct Scanner {
    config: Config,
    engines: RwLock<Arc<Engines>>,
    behavior: BehaviorAnalyzer,
    radare: Option<Radare2Analyzer>,
    quarantine: Quarantine,
    events: EventChannel,
    cache: Mutex<HashMap<PathBuf, CachedScan>>,
    slots: Arc<tokio::sync::Semaphore>,
}

struct ActiveMonitor {
    watcher: Arc<RealtimeMonitor>,
    worker: tokio::task::JoinHandle<()>,
}

impl Drop for ActiveMonitor {
    fn drop(&mut self) {
        self.worker.abort();
        let _ = self.watcher.stop();
    }
}

#[derive(Clone)]
pub struct Amaru {
    scanner: Arc<Scanner>,
    monitor: Arc<Mutex<Option<ActiveMonitor>>>,
    monitor_changes: Arc<tokio::sync::Mutex<()>>,
    core_services: Option<Arc<tokio::sync::Mutex<CoreServices>>>,
}

impl Scanner {
    async fn scan(
        self: &Arc<Self>,
        path: &Path,
        heuristic: bool,
        radare: Option<bool>,
    ) -> Result<ScanResult, AmaruError> {
        let _permit = self
            .slots
            .acquire()
            .await
            .map_err(|e| AmaruError::Internal(e.to_string()))?;
        let start = Instant::now();
        let engines = self.engines.read().clone();
        let scanner = self.clone();
        let owned_path = path.to_owned();
        // All byte-based detectors and the digest consume the same bounded snapshot.
        let outcome = tokio::task::spawn_blocking(move || -> Result<_, AmaruError> {
            let file = File::open(&owned_path)?;
            let size_limit = scanner.config.scan_config.max_file_size;
            let meta = file.metadata()?;
            if !meta.is_file() {
                return Err(AmaruError::Analysis(format!(
                    "Expected a regular file: {}",
                    owned_path.display()
                )));
            }
            if meta.len() > size_limit {
                return Err(AmaruError::FileTooLarge(owned_path));
            }
            let mut bytes = Vec::new();
            file.take(size_limit.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > size_limit {
                return Err(AmaruError::FileTooLarge(owned_path));
            }
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let is_pe = has_pe_header(&bytes);
            let run_radare = radare.unwrap_or(scanner.radare.is_some() && is_pe);
            if run_radare && scanner.radare.is_none() {
                return Err(AmaruError::Analysis(
                    "Radare2 is required for the requested static analysis".into(),
                ));
            }
            if let Some(hit) = scanner.cache.lock().get(&owned_path) {
                if Arc::ptr_eq(&hit.engines, &engines)
                    && hit.heuristic == heuristic
                    && hit.radare == run_radare
                    && hit.result.sha256 == digest
                {
                    return Ok(ScanWork::Cached(hit.result.clone()));
                }
            }
            let yara_matches = engines
                .yara
                .scan_memory(&bytes)
                .map_err(|e| AmaruError::Yara(e.to_string()))?;
            let heuristic_result = if heuristic {
                Some(
                    engines
                        .heuristic
                        .analyze_bytes(&owned_path, &bytes)
                        .map_err(|e| AmaruError::Analysis(e.to_string()))?,
                )
            } else {
                None
            };
            let pe_behavior = heuristic && is_pe;
            let behaviors = if pe_behavior {
                scanner
                    .behavior
                    .analyze_optimized(&bytes, &digest)
                    .map_err(|err| AmaruError::Analysis(err.to_string()))?
            } else {
                scanner
                    .behavior
                    .detect_test_files(&bytes)
                    .into_iter()
                    .collect()
            };
            Ok(ScanWork::Fresh {
                result: ScanResult {
                    path: owned_path,
                    yara_matches,
                    heuristic_result,
                    behaviors: (!behaviors.is_empty()).then_some(behaviors),
                    static_analysis: None,
                    risk_level: RiskLevel::Low,
                    threat_details: None,
                    sha256: digest,
                    scan_time: 0.0,
                },
                size: bytes.len() as u64,
                engines,
                radare: run_radare,
                pe_behavior,
            })
        })
        .await
        .map_err(|e| AmaruError::Internal(e.to_string()))??;

        let mut result = match outcome {
            ScanWork::Cached(result) => result,
            ScanWork::Fresh {
                mut result,
                size,
                engines,
                radare,
                pe_behavior,
            } => {
                if radare {
                    let analyzer = self
                        .radare
                        .as_ref()
                        .ok_or_else(|| AmaruError::Analysis("Radare2 unavailable".into()))?;
                    let analysis = analyzer
                        .analyze_file(path)
                        .await
                        .map_err(|e| AmaruError::Analysis(e.to_string()))?;
                    if analysis.sha256.as_deref() != Some(&result.sha256) {
                        return Err(AmaruError::Analysis(format!(
                            "File changed during static analysis: {}",
                            path.display()
                        )));
                    }
                    if !pe_behavior {
                        let imports = analysis
                            .imports
                            .iter()
                            .map(|i| i.name.clone())
                            .collect::<Vec<_>>();
                        let sections = analysis
                            .sections
                            .iter()
                            .map(|s| (s.name.clone(), s.entropy))
                            .collect::<Vec<_>>();
                        let mut behaviors = self
                            .behavior
                            .analyze_imports_optimized(&imports, &result.sha256)
                            .await;
                        behaviors.extend(
                            self.behavior
                                .analyze_sections_optimized(&sections, &result.sha256)
                                .await,
                        );
                        if !behaviors.is_empty() {
                            result
                                .behaviors
                                .get_or_insert_with(Vec::new)
                                .extend(behaviors);
                        }
                    }
                    result.static_analysis = Some(analysis);
                }
                result.classify(size, engines.heuristic_threshold);
                let mut cache = self.cache.lock();
                if cache.len() >= 512 {
                    cache.clear();
                }
                cache.insert(
                    path.to_owned(),
                    CachedScan {
                        engines,
                        heuristic,
                        radare,
                        result: result.clone(),
                    },
                );
                result
            }
        };
        result.scan_time = start.elapsed().as_secs_f64();
        if let Some(details) = &result.threat_details {
            let _ = self.events.send(Event::ThreatDetected {
                path: result.path.clone(),
                risk_level: result.risk_level,
                threat_type: result.threat_type(),
                details: details.clone(),
                timestamp: Utc::now(),
            });
        }
        Ok(result)
    }

    fn quarantine_event(&self, entry: &QuarantineEntry) {
        let _ = self.events.send(Event::FileQuarantined {
            original_path: entry.original_path.clone(),
            reason: entry.reason.clone(),
            timestamp: entry.quarantine_date,
        });
    }

    fn report_error(&self, path: &Path, code: ErrorCode, err: impl std::fmt::Display) {
        log::warn!("{}: {}", path.display(), err);
        let _ = self.events.send(Event::Error {
            code,
            message: err.to_string(),
            details: Some(path.display().to_string()),
            timestamp: Utc::now(),
        });
    }
}

enum ScanWork {
    Cached(ScanResult),
    Fresh {
        result: ScanResult,
        size: u64,
        engines: Arc<Engines>,
        radare: bool,
        pe_behavior: bool,
    },
}

fn has_pe_header(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"MZ") || bytes.len() < 64 {
        return false;
    }
    let offset = u32::from_le_bytes(bytes[60..64].try_into().expect("four bytes")) as usize;
    bytes
        .get(offset..)
        .is_some_and(|rest| rest.starts_with(b"PE\0\0"))
}

/// Normalize the two severity representations used by Amaru rule catalogs.
pub(crate) fn rule_severity(rule: &RuleMatch) -> Option<u8> {
    let value = rule.meta.get("severity")?;
    let score = if let Some(n) = value.as_u64() {
        u8::try_from(n).ok()?
    } else {
        match value.as_str()?.trim().to_ascii_lowercase().as_str() {
            "low" => 25,
            "medium" => 55,
            "high" => 75,
            "critical" => 95,
            other => other.parse().ok()?,
        }
    };
    (score <= 100).then_some(score)
}

fn risk_band(score: u8) -> RiskLevel {
    match score {
        90.. => RiskLevel::Critical,
        70..=89 => RiskLevel::High,
        50..=69 => RiskLevel::Medium,
        _ => RiskLevel::Low,
    }
}

impl ScanResult {
    fn classify(&mut self, size: u64, min_score: u32) {
        let mut risk = RiskLevel::Low;
        for rule in &self.yara_matches {
            let severity = rule_severity(rule)
                .map(risk_band)
                .unwrap_or(RiskLevel::Medium);
            risk = risk.max(severity);
        }
        let heur = self
            .heuristic_result
            .as_ref()
            .filter(|h| h.score > 0 && h.score >= min_score);
        if let Some(heur) = heur {
            risk = risk.max(match heur.confidence {
                ConfidenceLevel::Low | ConfidenceLevel::Medium => RiskLevel::Medium,
                ConfidenceLevel::High => RiskLevel::High,
                ConfidenceLevel::Critical => RiskLevel::Critical,
            });
        }
        for behavior in self.behaviors.iter().flatten() {
            let severity = if matches!(behavior.behavior_type, MaliciousBehaviorType::TestFile) {
                RiskLevel::High
            } else {
                match behavior.confidence {
                    90..=u8::MAX => RiskLevel::Critical,
                    70..=89 => RiskLevel::High,
                    _ => RiskLevel::Medium,
                }
            };
            risk = risk.max(severity);
        }
        if let Some(analysis) = &self.static_analysis {
            risk = risk.max(risk_band(analysis.risk_score));
        }
        self.risk_level = risk;
        if risk > RiskLevel::Low || !self.yara_matches.is_empty() {
            self.threat_details = Some(ThreatDetails {
                file_hash: self.sha256.clone(),
                file_size: size,
                file_type: self
                    .static_analysis
                    .as_ref()
                    .and_then(|a| a.file_type.clone())
                    .unwrap_or_else(|| "Unknown".into()),
                matches: self
                    .yara_matches
                    .iter()
                    .map(|r| r.rule_name.clone())
                    .collect(),
                additional_info: Some(
                    serde_json::json!({"behaviors":self.behaviors,"heuristic":heur,"static_risk":self.static_analysis.as_ref().map(|a|a.risk_score)}),
                ),
            });
        }
    }

    fn threat_type(&self) -> ThreatType {
        if let Some(rule) = self
            .yara_matches
            .iter()
            .max_by_key(|rule| rule_severity(rule).unwrap_or(55))
        {
            ThreatType::YaraMatch {
                rule_name: rule.rule_name.clone(),
                description: rule
                    .meta
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
            }
        } else if let Some(b) = self.behaviors.iter().flatten().max_by_key(|b| b.confidence) {
            ThreatType::SuspiciousBehavior {
                behavior_type: format!("{:?}", b.behavior_type),
                description: b.description.clone(),
            }
        } else if let Some(b) = self
            .static_analysis
            .iter()
            .flat_map(|a| &a.behaviors)
            .next()
        {
            ThreatType::SuspiciousBehavior {
                behavior_type: b.name.clone(),
                description: b.description.clone(),
            }
        } else {
            ThreatType::SuspiciousBehavior {
                behavior_type: "Heuristic".into(),
                description: self
                    .heuristic_result
                    .as_ref()
                    .map(|h| h.description.clone())
                    .unwrap_or_default(),
            }
        }
    }
}

impl Amaru {
    pub(crate) fn from_config(config: Config) -> Result<Self, AmaruError> {
        Self::from_config_with_radare2(config, |_| true)
    }

    pub(crate) fn from_config_with_radare2(
        config: Config,
        allowed: impl FnOnce(&mut Radare2Analyzer) -> bool,
    ) -> Result<Self, AmaruError> {
        config
            .validate()
            .map_err(|e| AmaruError::Config(e.to_string()))?;
        let mut yara = YaraEngine::new(&config.yara_rules_path)
            .map_err(|e| AmaruError::Yara(e.to_string()))?;
        let deadline = Duration::from_secs(config.scan_config.scan_timeout);
        yara.set_scan_timeout(deadline);
        let behavior = BehaviorAnalyzer::new();
        behavior.set_timeout(deadline.as_millis().clamp(1, u64::MAX as u128) as u64);
        behavior.set_memory_limit(
            usize::try_from(config.scan_config.max_file_size).unwrap_or(usize::MAX),
        );
        let heuristic_config = HeuristicConfig {
            max_file_size: config.scan_config.max_file_size,
            min_detection_score: u32::from(config.heuristic_threshold),
            ..Default::default()
        };
        let engines = Engines {
            yara,
            heuristic_threshold: heuristic_config.min_detection_score,
            heuristic_enabled: config.heuristic_analysis,
            heuristic: Arc::new(HeuristicEngine::new(heuristic_config)),
        };
        let radare = match Radare2Analyzer::new(Radare2Config {
            timeout_seconds: config.scan_config.scan_timeout,
            ..Default::default()
        }) {
            Ok(mut analyzer) => allowed(&mut analyzer).then_some(analyzer),
            Err(radare2_analyzer::Radare2Error::NotFound) => None,
            Err(e) => return Err(AmaruError::Analysis(e.to_string())),
        };
        let quarantine = Quarantine::new(
            &config.quarantine_config.quarantine_path,
            config.quarantine_config.max_size,
            config.quarantine_config.retention_days,
        )?;
        let slots = Arc::new(tokio::sync::Semaphore::new(config.scan_config.max_threads));
        Ok(Self {
            scanner: Arc::new(Scanner {
                config,
                engines: RwLock::new(Arc::new(engines)),
                behavior,
                radare,
                quarantine,
                events: EventChannel::new(),
                cache: Mutex::new(HashMap::new()),
                slots,
            }),
            monitor: Arc::new(Mutex::new(None)),
            monitor_changes: Arc::default(),
            core_services: None,
        })
    }

    pub async fn new(config: Config) -> Result<Self, AmaruError> {
        let mut amaru = Self::from_config(config)?;
        amaru.init_core_services().await?;
        Ok(amaru)
    }

    pub fn config(&self) -> &Config {
        &self.scanner.config
    }
    pub fn quarantine(&self) -> &Quarantine {
        &self.scanner.quarantine
    }
    pub fn realtime_enabled(&self) -> bool {
        self.monitor.lock().is_some()
    }
    pub fn monitor_stats(&self) -> Option<MonitorStats> {
        self.monitor
            .lock()
            .as_ref()
            .map(|monitor| monitor.watcher.get_stats())
    }
    pub fn event_receiver(&self) -> crossbeam_channel::Receiver<Event> {
        self.scanner.events.receiver()
    }

    pub async fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResult, AmaruError> {
        let heuristic = self.scanner.engines.read().heuristic_enabled;
        self.scanner.scan(path.as_ref(), heuristic, None).await
    }

    pub async fn scan_file_with_options(
        &self,
        path: impl AsRef<Path>,
        heuristic: bool,
        radare2: bool,
    ) -> Result<ScanResult, AmaruError> {
        self.scanner
            .scan(path.as_ref(), heuristic, Some(radare2))
            .await
    }

    pub fn quarantine_file(
        &self,
        path: impl AsRef<Path>,
        reason: &str,
    ) -> Result<QuarantineEntry, AmaruError> {
        let entry = self.quarantine().quarantine_file(path, reason)?;
        self.scanner.quarantine_event(&entry);
        Ok(entry)
    }

    /// Capture only the exact contents that produced the detection.
    pub fn quarantine_detected(
        &self,
        result: &ScanResult,
        reason: &str,
    ) -> Result<QuarantineEntry, AmaruError> {
        let entry =
            self.quarantine()
                .quarantine_if_unchanged(&result.path, reason, &result.sha256)?;
        self.scanner.quarantine_event(&entry);
        Ok(entry)
    }

    pub fn restore_quarantined(&self, id: &str) -> Result<PathBuf, AmaruError> {
        let path = self.quarantine().restore_file_by_id(id)?;
        let _ = self.scanner.events.send(Event::FileRestored {
            original_path: path.clone(),
            timestamp: Utc::now(),
        });
        Ok(path)
    }

    pub async fn update_yara_rules(&self) -> Result<(), AmaruError> {
        let mut next = self.scanner.engines.write();
        Arc::make_mut(&mut next)
            .yara
            .reload_rules()
            .map_err(|e| AmaruError::Yara(e.to_string()))?;
        self.scanner.cache.lock().clear();
        Ok(())
    }

    pub fn init_heuristic_engine(
        &mut self,
        config: Option<HeuristicConfig>,
    ) -> Result<(), AmaruError> {
        let config = config.unwrap_or_else(|| HeuristicConfig {
            max_file_size: self.config().scan_config.max_file_size,
            min_detection_score: u32::from(self.config().heuristic_threshold),
            ..Default::default()
        });
        let mut engines = self.scanner.engines.write();
        let settings = Arc::make_mut(&mut engines);
        settings.heuristic_threshold = config.min_detection_score;
        settings.heuristic_enabled = true;
        settings.heuristic = Arc::new(HeuristicEngine::new(config));
        self.scanner.cache.lock().clear();
        Ok(())
    }

    pub async fn scan_file_optimized(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<EnhancedScanResult, AmaruError> {
        let result = self.scan_file(path).await?;
        Ok(EnhancedScanResult {
            file_path: result.path,
            yara_matches: result.yara_matches,
            heuristic_result: result.heuristic_result,
            is_malicious: result.threat_details.is_some(),
            scan_time: result.scan_time,
        })
    }

    pub async fn optimize_resources(&self) -> Result<(), AmaruError> {
        self.scanner.cache.lock().clear();
        self.scanner.behavior.cleanup_cache(512).await;
        self.scanner
            .behavior
            .optimize_thread_pool(self.config().scan_config.max_threads)
            .await;
        Ok(())
    }

    pub async fn enable_realtime_protection(&mut self) -> Result<(), AmaruError> {
        let _change = self.monitor_changes.lock().await;
        let mut slot = self.monitor.lock();
        if slot.is_some() {
            return Ok(());
        }
        let mut ignored: Vec<_> = self
            .config()
            .scan_config
            .exclude_paths
            .iter()
            .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
            .collect();
        ignored.push(
            self.config()
                .quarantine_config
                .quarantine_path
                .canonicalize()?,
        );
        ignored.push(self.config().yara_rules_path.canonicalize()?);
        let config = MonitorConfig {
            paths: self
                .config()
                .monitored_paths
                .iter()
                .map(std::fs::canonicalize)
                .collect::<io::Result<_>>()?,
            extensions_filter: self.config().scan_config.scan_extensions.clone(),
            ignore_paths: ignored,
            ..Default::default()
        };
        let paths = config.paths.clone();
        let mut watcher = RealtimeMonitor::new(config)
            .map_err(|e| AmaruError::RealTimeMonitorError(e.to_string()))?;
        let (tx, mut rx) = mpsc::channel::<PathBuf>(256);
        let events = self.scanner.events.clone();
        let quarantine = self.scanner.quarantine.clone();
        watcher
            .start(move |ev| {
                let path = match ev.event_type {
                    FileEventType::Created | FileEventType::Modified => ev.path,
                    FileEventType::Renamed(new) => new,
                    FileEventType::Deleted => return EventAction::Continue,
                };
                if quarantine.is_staging_path(&path) {
                    return EventAction::Continue;
                }
                if let Err(mpsc::error::TrySendError::Full(path)) = tx.try_send(path) {
                    let _ = events.send(Event::Error {
                        code: ErrorCode::Analysis,
                        message: "Real-time scan queue is full".into(),
                        details: Some(path.display().to_string()),
                        timestamp: Utc::now(),
                    });
                }
                EventAction::Continue
            })
            .map_err(|e| AmaruError::RealTimeMonitorError(e.to_string()))?;
        let watcher = Arc::new(watcher);
        let stats = watcher.clone();
        let scanner = Arc::clone(&self.scanner);
        let worker = tokio::spawn(async move {
            while let Some(path) = rx.recv().await {
                if path.is_dir() {
                    continue;
                }
                let enabled = scanner.engines.read().heuristic_enabled;
                let scanned = scanner.scan(&path, enabled, None).await;
                if scanned
                    .as_ref()
                    .is_ok_and(|result| result.threat_details.is_some())
                {
                    stats.increment_threats_detected();
                }
                match scanned {
                    Ok(result) if scanner.config.should_auto_quarantine(result.risk_level) => {
                        match scanner.quarantine.quarantine_if_unchanged(
                            &path,
                            "Real-time detection",
                            &result.sha256,
                        ) {
                            Ok(entry) => scanner.quarantine_event(&entry),
                            Err(err) => scanner.report_error(&path, ErrorCode::Quarantine, err),
                        }
                    }
                    Err(err) => scanner.report_error(&path, ErrorCode::Analysis, err),
                    _ => {}
                }
            }
        });
        *slot = Some(ActiveMonitor { watcher, worker });
        let _ = self
            .scanner
            .events
            .send(Event::RealtimeProtectionStatusChanged {
                enabled: true,
                monitored_paths: paths,
                timestamp: Utc::now(),
            });
        Ok(())
    }

    pub async fn disable_realtime_protection(&mut self) -> Result<(), AmaruError> {
        let _change = self.monitor_changes.lock().await;
        let active = self.monitor.lock().take();
        if let Some(mut monitor) = active {
            monitor
                .watcher
                .stop()
                .map_err(|e| AmaruError::RealTimeMonitorError(e.to_string()))?;
            monitor.worker.abort();
            let _ = (&mut monitor.worker).await;
            let _ = self
                .scanner
                .events
                .send(Event::RealtimeProtectionStatusChanged {
                    enabled: false,
                    monitored_paths: vec![],
                    timestamp: Utc::now(),
                });
        }
        Ok(())
    }

    pub async fn init_core_services(&mut self) -> Result<(), AmaruError> {
        if self.core_services.is_some() {
            return Ok(());
        }
        let (tx, mut rx) = mpsc::channel(128);
        let core = CoreServices::from_amaru(self.clone(), self.config().clone(), tx)?;
        self.core_services = Some(Arc::new(tokio::sync::Mutex::new(core)));
        let events = self.scanner.events.clone();
        tokio::spawn(async move {
            while let Some(notification) = rx.recv().await {
                let payload = match notification {
                    CoreNotification::UpdateAvailable {
                        component,
                        version,
                        size,
                        timestamp,
                    } => Some((
                        events::UpdateStatus::Starting,
                        format!(
                            "{component} {version}{}",
                            size.map(|bytes| format!(" ({bytes} bytes)"))
                                .unwrap_or_default()
                        ),
                        timestamp,
                    )),
                    CoreNotification::UpdateApplied {
                        component,
                        version,
                        timestamp,
                    } => Some((
                        events::UpdateStatus::Completed { version },
                        component,
                        timestamp,
                    )),
                    _ => None,
                };
                if let Some((status, details, timestamp)) = payload {
                    let _ = events.send(Event::UpdateEvent {
                        update_type: events::UpdateType::YaraRules,
                        status,
                        details,
                        timestamp,
                    });
                }
            }
        });
        Ok(())
    }

    fn core(&self) -> Result<&tokio::sync::Mutex<CoreServices>, AmaruError> {
        self.core_services.as_deref().ok_or_else(|| {
            AmaruError::InitializationError("Integrated services are unavailable".into())
        })
    }
    pub async fn integrated_scan_file(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<IntegratedScanResult, AmaruError> {
        self.core()?.lock().await.scan_file(path).await
    }
    pub async fn enable_integrated_realtime_protection(&mut self) -> Result<bool, AmaruError> {
        self.core()?.lock().await.enable_realtime_protection().await
    }
    pub async fn disable_integrated_realtime_protection(&mut self) -> Result<bool, AmaruError> {
        self.core()?
            .lock()
            .await
            .disable_realtime_protection()
            .await
    }
    pub async fn check_core_updates(&self) -> Result<bool, AmaruError> {
        self.core()?.lock().await.check_updates().await
    }
    pub async fn integrated_quarantine_file(
        &self,
        path: impl AsRef<Path>,
        reason: &str,
    ) -> Result<(), AmaruError> {
        self.quarantine_file(path, reason)?;
        Ok(())
    }
    pub async fn integrated_restore_file(&self, id: &str) -> Result<PathBuf, AmaruError> {
        self.restore_quarantined(id)
    }
}

#[cfg(windows)]
impl Amaru {
    /// Inicia el servicio de Amaru
    pub fn start_service() -> windows_service::Result<()> {
        service::start_service()
    }

    /// Detiene el servicio de Amaru
    pub fn stop_service() -> windows_service::Result<()> {
        service::stop_service()
    }

    /// Instala el servicio de Amaru
    pub fn install_service() -> windows_service::Result<()> {
        service::install_service()
    }

    /// Desinstala el servicio de Amaru
    pub fn uninstall_service() -> windows_service::Result<()> {
        service::uninstall_service()
    }

    /// Obtiene el estado del servicio
    pub fn get_service_status() -> windows_service::Result<windows_service::service::ServiceStatus>
    {
        service::get_service_status()
    }

    /// Crea un nuevo cliente IPC para comunicarse con el servicio
    pub fn create_ipc_client() -> Result<ipc::IpcClient, ipc::IpcError> {
        ipc::IpcClient::connect()
    }

    /// Obtiene el estado actual del servicio
    pub async fn get_service_state() -> Result<ServiceState, AmaruError> {
        let mut client =
            Self::create_ipc_client().map_err(|e| AmaruError::Internal(e.to_string()))?;

        match client.get_status()? {
            ipc::IpcResponse::Status {
                is_running,
                uptime_secs,
                files_monitored,
                threats_detected,
            } => {
                let scan_progress = if is_running {
                    match client.get_scan_progress()? {
                        ipc::IpcResponse::ScanProgress {
                            files_scanned,
                            files_total,
                            current_file,
                            start_time,
                        } => Some(ScanProgress {
                            files_scanned,
                            files_total,
                            current_file: PathBuf::from(current_file),
                            start_time,
                        }),
                        _ => None,
                    }
                } else {
                    None
                };

                Ok(ServiceState {
                    is_running,
                    uptime: Duration::from_secs(uptime_secs),
                    files_monitored,
                    threats_detected,
                    scan_in_progress: scan_progress.is_some(),
                    scan_progress,
                    last_update: chrono::Utc::now(),
                })
            }
            _ => Err(AmaruError::Internal(
                "Respuesta inesperada del servicio".into(),
            )),
        }
    }

    /// Inicia un escaneo a través del servicio
    pub async fn service_start_scan<P: AsRef<Path>>(&self, path: P) -> Result<(), AmaruError> {
        let mut client =
            Self::create_ipc_client().map_err(|e| AmaruError::Internal(e.to_string()))?;

        match client.start_scan(path.as_ref().to_string_lossy().into_owned())? {
            ipc::IpcResponse::Ok => Ok(()),
            ipc::IpcResponse::Error(msg) => Err(AmaruError::Internal(msg)),
            _ => Err(AmaruError::Internal(
                "Respuesta inesperada del servicio".into(),
            )),
        }
    }

    /// Detiene el escaneo actual a través del servicio
    pub async fn service_stop_scan(&self) -> Result<(), AmaruError> {
        let mut client =
            Self::create_ipc_client().map_err(|e| AmaruError::Internal(e.to_string()))?;

        match client.stop_scan()? {
            ipc::IpcResponse::Ok => Ok(()),
            ipc::IpcResponse::Error(msg) => Err(AmaruError::Internal(msg)),
            _ => Err(AmaruError::Internal(
                "Respuesta inesperada del servicio".into(),
            )),
        }
    }

    /// Actualiza las reglas YARA a través del servicio
    pub async fn service_update_rules(&self) -> Result<(), AmaruError> {
        let mut client =
            Self::create_ipc_client().map_err(|e| AmaruError::Internal(e.to_string()))?;

        match client.update_rules()? {
            ipc::IpcResponse::Ok => Ok(()),
            ipc::IpcResponse::Error(msg) => Err(AmaruError::Internal(msg)),
            _ => Err(AmaruError::Internal(
                "Respuesta inesperada del servicio".into(),
            )),
        }
    }

    /// Obtiene estadísticas del servicio
    pub async fn get_service_stats(&self) -> Result<ServiceStats, AmaruError> {
        let mut client =
            Self::create_ipc_client().map_err(|e| AmaruError::Internal(e.to_string()))?;

        match client.get_service_stats()? {
            ipc::IpcResponse::ServiceStats {
                cpu_usage,
                memory_usage,
                scan_queue_size,
            } => Ok(ServiceStats {
                cpu_usage,
                memory_usage,
                scan_queue_size,
            }),
            _ => Err(AmaruError::Internal(
                "Respuesta inesperada del servicio".into(),
            )),
        }
    }
}
#[derive(Debug, Clone)]
pub struct ServiceStats {
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub scan_queue_size: usize,
}

/// Resultado mejorado de análisis que incluye YARA y heurística
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedScanResult {
    pub file_path: PathBuf,
    pub yara_matches: Vec<RuleMatch>,
    pub heuristic_result: Option<HeuristicResult>,
    pub is_malicious: bool,
    pub scan_time: f64,
}

impl Event {
    pub fn is_threat_event(&self) -> bool {
        matches!(
            self,
            Self::ThreatDetected { .. } | Self::FileQuarantined { .. } | Self::FileRestored { .. }
        )
    }

    pub fn is_update_event(&self) -> bool {
        matches!(self, Self::UpdateEvent { .. })
    }

    pub fn is_status_event(&self) -> bool {
        matches!(self, Self::RealtimeProtectionStatusChanged { .. })
    }
}

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod pe_fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn scan_config(root: &Path) -> io::Result<Config> {
        let rules = root.join("rules");
        std::fs::create_dir(&rules)?;
        std::fs::write(
            rules.join("test.yar"),
            r#"rule test_rule { meta: severity = "high" strings: $a = "amaru-test-marker" condition: $a }"#,
        )?;
        let mut config = Config {
            yara_rules_path: rules,
            monitored_paths: vec![root.to_owned()],
            ..Default::default()
        };
        config.quarantine_config.quarantine_path = root.join("quarantine");
        Ok(config)
    }

    #[tokio::test]
    async fn evidence_follows_file_contents_and_active_rules() -> Result<(), AmaruError> {
        let temp = tempdir()?;
        let config = scan_config(temp.path())?;
        let rule = config.yara_rules_path.join("test.yar");
        let path = temp.path().join("test.exe");
        std::fs::write(&path, b"amaru-test-marker")?;
        let amaru = Amaru::new(config).await?;
        let first = amaru.scan_file(&path).await?;
        assert_eq!(first.risk_level, RiskLevel::High);
        assert_eq!(first.yara_matches[0].rule_name, "test_rule");
        assert_eq!(
            first.threat_details.as_ref().unwrap().file_hash,
            first.sha256
        );
        let cached = amaru.scan_file(&path).await?;
        assert_eq!(cached.yara_matches[0].strings[0].data, b"amaru-test-marker");
        std::fs::write(&path, b"other-test-marker")?;
        let changed = amaru.scan_file(&path).await?;
        assert_ne!(first.sha256, changed.sha256);
        assert!(changed.threat_details.is_none());
        assert!(amaru
            .quarantine_detected(&first, "stale detection")
            .is_err());
        assert_eq!(std::fs::read(&path)?, b"other-test-marker");
        std::fs::write(&rule, "rule invalid {")?;
        assert!(amaru.update_yara_rules().await.is_err());
        std::fs::write(&path, b"amaru-test-marker")?;
        assert_eq!(amaru.scan_file(&path).await?.yara_matches.len(), 1);
        std::fs::write(&rule, "rule revised { condition: false }")?;
        amaru.update_yara_rules().await?;
        let revised = amaru.scan_file(&path).await?;
        assert!(revised.yara_matches.is_empty() && revised.threat_details.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn pe_import_evidence_is_distinct_from_incidental_strings() -> Result<(), AmaruError> {
        let temp = tempdir()?;
        let config = scan_config(temp.path())?;
        let amaru = Amaru::new(config).await?;
        let path = temp.path().join("metadata.exe");
        let incidental = pe_fixture::import_fixture(&[], b"NtCreateFile WSAConnect");
        std::fs::write(&path, incidental)?;
        let result = amaru.scan_file_with_options(&path, true, false).await?;
        let has_import = |p: &yara_engine::heuristic::PatternMatch| {
            matches!(
                p.pattern_name.as_str(),
                "rootkit_system_hook" | "backdoor_remote_connection"
            )
        };
        assert!(!result
            .heuristic_result
            .unwrap()
            .patterns
            .iter()
            .any(has_import));
        let imports = pe_fixture::import_fixture(&["NtCreateFile", "WSAConnect"], b"");
        std::fs::write(&path, imports)?;
        let result = amaru.scan_file_with_options(&path, true, false).await?;
        assert_eq!(
            result
                .heuristic_result
                .unwrap()
                .patterns
                .iter()
                .filter(|p| has_import(p))
                .count(),
            2
        );
        Ok(())
    }

    #[tokio::test]
    async fn scan_errors_are_distinct_from_clean_files() -> Result<(), AmaruError> {
        let temp = tempdir()?;
        let mut config = scan_config(temp.path())?;
        config.scan_config.max_file_size = 4;
        let amaru = Amaru::new(config).await?;
        let path = temp.path().join("input");
        assert!(matches!(
            amaru.scan_file(&path).await,
            Err(AmaruError::Io(_))
        ));
        std::fs::write(&path, b"12345")?;
        assert!(matches!(
            amaru.scan_file(&path).await,
            Err(AmaruError::FileTooLarge(_))
        ));
        std::fs::write(&path, b"1234")?;
        let clean = amaru.scan_file_with_options(&path, false, false).await?;
        assert_eq!(clean.risk_level, RiskLevel::Low);
        assert!(clean.threat_details.is_none() && clean.heuristic_result.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn realtime_reports_file_without_moving_it_by_default() -> Result<(), AmaruError> {
        let temp = tempdir()?;
        let config = scan_config(temp.path())?;
        let mut amaru = Amaru::new(config).await?;
        let receiver = amaru.event_receiver();
        amaru.enable_realtime_protection().await?;
        let path = temp.path().canonicalize()?.join("test.exe");
        std::fs::write(&path, b"amaru-test-marker")?;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if receiver.try_iter().any(|event| {
                    matches!(event, Event::ThreatDetected { path: ref p, .. } if p == &path)
                }) { break; }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the real-time monitor should scan the new file");
        assert!(path.is_file());
        assert!(amaru.monitor_stats().unwrap().threats_detected >= 1);
        amaru.disable_realtime_protection().await?;
        assert!(!amaru.realtime_enabled());
        Ok(())
    }

    #[tokio::test]
    async fn test_eicar_detection() -> Result<(), AmaruError> {
        let temp_dir = tempdir()?;

        // Create rules directory
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir)?;

        // Create EICAR test file
        let eicar_file = temp_dir.path().join("eicar.txt");
        let eicar_content =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        std::fs::File::create(&eicar_file)?.write_all(eicar_content)?;

        // Create configuration
        let mut config = Config::default();
        config.yara_rules_path = rules_dir;
        config.monitored_paths = vec![temp_dir.path().to_path_buf()];
        config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");

        // Create Amaru instance
        let amaru = Amaru::new(config).await?;

        // Scan EICAR file
        let result = amaru.scan_file(&eicar_file).await?;

        // Verify test file detection
        assert!(
            result.behaviors.is_some(),
            "EICAR test file should be detected"
        );
        if let Some(behaviors) = &result.behaviors {
            assert!(behaviors
                .iter()
                .any(|b| matches!(b.behavior_type, MaliciousBehaviorType::TestFile)));
        }

        Ok(())
    }
}
