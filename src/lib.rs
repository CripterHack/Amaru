mod config;
mod events;
mod quarantine;
mod behavior;
mod core_services;
mod security;
mod resource_manager;

pub use config::Config;
pub use events::{Event, EventChannel, ThreatType, RiskLevel, ThreatDetails, ErrorCode};
pub use quarantine::{Quarantine, QuarantineError};
pub use behavior::{BehaviorAnalyzer, MaliciousBehavior, MaliciousBehaviorType};
pub use core_services::{CoreServices, CoreNotification, IntegratedScanResult};
pub use resource_manager::{ResourceManager, ResourceMetrics, TaskType, SystemPriority};

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use thiserror::Error;
use log::{debug, error, info, warn};
use std::io;
use std::time::Duration;

use yara_engine::{YaraEngine, ScanResult as YaraScanResult, RuleMatch};
use radare2_analyzer::{Radare2Analyzer, PEAnalysis};
use realtime_monitor::{RealtimeMonitor, FileEvent, FileEventType};
use yara_engine::heuristic::{HeuristicEngine, HeuristicConfig, HeuristicResult, ConfidenceLevel};

pub mod service;
pub mod ipc;

// Re-exportar elementos de seguridad
pub use security::{
    SecurityManager, SecurityError, SecurityCheckResult,
    IntegrityManager, TamperProtection, SecureLogger, DigitalSignature
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
    
    #[error("Error de configuración: {0}")]
    Config(String),
    
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
    /// Ruta del archivo
    pub path: PathBuf,
    
    /// Coincidencias YARA
    pub yara_matches: Vec<YaraScanResult>,
    
    /// Análisis estático
    pub static_analysis: Option<PEAnalysis>,
    
    /// Nivel de riesgo
    pub risk_level: RiskLevel,
    
    /// Detalles de la amenaza
    pub threat_details: Option<ThreatDetails>,
    
    /// Análisis de comportamiento
    pub behaviors: Option<Vec<MaliciousBehavior>>,
}

/// Estructura principal del antivirus Amaru
///
/// Proporciona funcionalidades para:
/// - Escaneo de archivos con YARA
/// - Análisis estático con Radare2
/// - Protección en tiempo real
/// - Sistema de cuarentena
/// - Gestión de eventos
/// - Análisis heurístico
/// - Integración de servicios core
#[derive(Clone)]
pub struct Amaru {
    /// Configuración
    config: Config,
    
    /// Motor YARA
    yara_engine: Option<YaraEngine>,
    
    /// Analizador Radare2
    radare2_analyzer: Arc<Radare2Analyzer>,
    
    /// Analizador de comportamiento
    behavior_analyzer: Arc<BehaviorAnalyzer>,
    
    /// Monitor en tiempo real
    realtime_monitor: Option<RealtimeMonitor>,
    
    /// Sistema de cuarentena
    quarantine: Arc<Quarantine>,
    
    /// Canal de eventos
    event_channel: EventChannel,
    
    /// Cache de resultados de escaneo
    scan_cache: dashmap::DashMap<PathBuf, (ScanResult, std::time::Instant)>,
    
    /// Motor de análisis heurístico
    heuristic_engine: Option<HeuristicEngine>,
    
    /// Servicios core integrados
    core_services: Option<Arc<tokio::sync::Mutex<CoreServices>>>,
}

impl Amaru {
    /// Crea una nueva instancia de Amaru
    ///
    /// # Argumentos
    /// * `config` - Configuración inicial del antivirus
    ///
    /// # Errores
    /// Retorna error si:
    /// - La configuración es inválida
    /// - No se pueden cargar las reglas YARA
    /// - No se puede inicializar el analizador Radare2
    pub async fn new(config: Config) -> Result<Self, AmaruError> {
        // Validar configuración
        config.validate().map_err(|e| AmaruError::Config(e.to_string()))?;
        
        // Inicializar componentes
        let yara_engine = Arc::new(YaraEngine::new(&config.yara_rules_path)
            .map_err(|e| AmaruError::Yara(e.to_string()))?);
            
        let radare2_analyzer = Arc::new(Radare2Analyzer::new()
            .map_err(|e| AmaruError::Analysis(e.to_string()))?);
            
        let quarantine = Arc::new(Quarantine::new(
            &config.quarantine_config.quarantine_path,
            config.quarantine_config.max_size,
            config.quarantine_config.retention_days,
        )?);
        
        let behavior_analyzer = Arc::new(BehaviorAnalyzer::new());
        
        Ok(Self {
            config,
            yara_engine: None,
            radare2_analyzer,
            behavior_analyzer,
            realtime_monitor: None,
            quarantine,
            event_channel: EventChannel::new(),
            scan_cache: dashmap::DashMap::new(),
            heuristic_engine: None,
            core_services: None,
        })
    }
    
    /// Escanea un archivo en busca de amenazas
    ///
    /// # Argumentos
    /// * `path` - Ruta al archivo a escanear
    ///
    /// # Errores
    /// Retorna error si:
    /// - El archivo no existe
    /// - El archivo es demasiado grande
    /// - Hay un error en el escaneo YARA
    /// - Hay un error en el análisis estático
    pub async fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<ScanResult, AmaruError> {
        let path = path.as_ref();
        
        // Verificar cache
        if let Some(entry) = self.scan_cache.get(path) {
            let (result, timestamp) = entry.value();
            if timestamp.elapsed() < std::time::Duration::from_secs(3600) {
                return Ok(result.clone());
            }
        }
        
        // Verificar tamaño máximo
        let metadata = path.metadata().map_err(|e| AmaruError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("No se puede acceder al archivo {}: {}", path.display(), e)
        )))?;
        
        if metadata.len() > self.config.scan_config.max_file_size {
            return Err(AmaruError::Analysis(format!(
                "El archivo {} excede el tamaño máximo permitido de {} bytes",
                path.display(),
                self.config.scan_config.max_file_size
            )));
        }
        
        // Escanear con YARA
        let yara_matches = self.yara_engine.as_ref().unwrap().scan_file(path)
            .map_err(|e| AmaruError::Yara(format!(
                "Error al escanear el archivo {} con YARA: {}",
                path.display(), e
            )))?;
            
        // Análisis estático para ejecutables
        let static_analysis = if path.extension().map_or(false, |ext| ext == "exe" || ext == "dll") {
            Some(self.radare2_analyzer.analyze_pe(path)
                .map_err(|e| AmaruError::Analysis(format!(
                    "Error al analizar el archivo PE {}: {}",
                    path.display(), e
                )))?)
        } else {
            None
        };
        
        // Análisis de comportamiento para ejecutables
        let behaviors = if let Some(analysis) = &static_analysis {
            let mut all_behaviors = Vec::new();
            
            // Analizar importaciones
            all_behaviors.extend(
                self.behavior_analyzer.analyze_imports(&analysis.imports)
            );
            
            // Analizar secciones
            all_behaviors.extend(
                self.behavior_analyzer.analyze_sections(
                    &analysis.sections.iter()
                        .map(|s| (s.name.clone(), s.entropy))
                        .collect::<Vec<_>>()
                )
            );
            
            // Analizar recursos
            all_behaviors.extend(
                self.behavior_analyzer.analyze_resources(&analysis.resources)
            );
            
            Some(all_behaviors)
        } else {
            None
        };
        
        // Calcular nivel de riesgo considerando comportamientos
        let risk_level = self.calculate_risk_level(&yara_matches, &static_analysis, behaviors.as_deref());
        
        // Crear detalles de amenaza si es necesario
        let threat_details = if risk_level > RiskLevel::Low {
            Some(self.create_threat_details(path, &yara_matches, &static_analysis, behaviors.as_deref())?)
        } else {
            None
        };
        
        // Crear resultado
        let result = ScanResult {
            path: path.to_path_buf(),
            yara_matches,
            static_analysis,
            risk_level,
            threat_details,
            behaviors,
        };
        
        // Actualizar cache
        self.scan_cache.insert(
            path.to_path_buf(),
            (result.clone(), std::time::Instant::now()),
        );
        
        // Emitir evento si es una amenaza
        if risk_level > RiskLevel::Low {
            if let Some(details) = &result.threat_details {
                self.event_channel.sender().send(Event::ThreatDetected {
                    path: path.to_path_buf(),
                    threat_type: self.determine_threat_type(&result),
                    risk_level,
                    details: details.clone(),
                    timestamp: chrono::Utc::now(),
                }).map_err(|e| AmaruError::Internal(e.to_string()))?;
            }
        }
        
        Ok(result)
    }
    
    /// Habilita la protección en tiempo real
    ///
    /// Comienza a monitorear las rutas especificadas en la configuración
    /// y escanea automáticamente los archivos nuevos o modificados.
    ///
    /// # Errores
    /// Retorna error si:
    /// - No se puede inicializar el monitor
    /// - No se pueden establecer los filtros
    /// - No se pueden monitorear las rutas
    pub async fn enable_realtime_protection(&mut self) -> Result<(), AmaruError> {
        if self.realtime_monitor.is_some() {
            info!("La protección en tiempo real ya está activa");
            return Ok(());
        }
        
        info!("Habilitando protección en tiempo real con análisis heurístico...");
        
        // Inicializamos el motor heurístico si no estaba inicializado
        if self.heuristic_engine.is_none() {
            self.init_heuristic_engine(None)?;
        }
        
        // Configuración para el monitor
        let config = MonitorConfig {
            paths: vec![PathBuf::from("C:\\"), PathBuf::from("D:\\")], // Monitorear drives principales
            extensions_filter: vec!["exe".to_string(), "dll".to_string(), "sys".to_string()],
            ignore_paths: vec![PathBuf::from("C:\\Windows\\Temp")],
            event_delay_ms: 500,
        };
        
        let monitor = RealtimeMonitor::new(config).await
            .map_err(|e| AmaruError::RealTimeMonitorError(format!(
                "No se pudo inicializar el monitor en tiempo real: {}", e
            )))?;
        
        // Configuramos un callback que analiza archivos en tiempo real
        // y utiliza análisis heurístico además de reglas YARA
        let yara_engine = self.yara_engine.clone();
        let heuristic_engine = self.heuristic_engine.clone();
        
        monitor.set_callback(move |event: FileEvent| {
            // Solo procesamos eventos de creación y modificación
            if matches!(event.event_type, FileEventType::Created | FileEventType::Modified) {
                // Ruta del archivo a analizar
                let file_path = event.path.clone();
                
                // Análisis con YARA si está disponible
                if let Some(yara) = &yara_engine {
                    if let Ok(result) = yara.scan_file(&file_path) {
                        if !result.matches.is_empty() {
                            // Detectamos amenaza con YARA
                            warn!("ALERTA: Amenaza detectada por YARA en {}: {} reglas coincidentes", 
                                  file_path.display(), result.matches.len());
                            
                            // Aquí podríamos tomar acciones como cuarentena
                            // ...
                            
                            return EventAction::Continue;
                        }
                    }
                }
                
                // Análisis heurístico si está disponible y no se detectó por YARA
                if let Some(heuristic) = &heuristic_engine {
                    if let Ok(result) = heuristic.analyze_file(&file_path) {
                        // Solo consideramos resultados con confianza media o superior
                        if result.confidence >= ConfidenceLevel::Medium {
                            warn!("ALERTA: Comportamiento sospechoso detectado en {}: {} ({:?})", 
                                  file_path.display(), result.description, result.threat_type);
                            
                            // Aquí podríamos tomar acciones basadas en el tipo de amenaza
                            // ...
                            
                            return EventAction::Continue;
                        }
                    }
                }
            }
            
            // Continuar monitoreando
            EventAction::Continue
        });
        
        // Iniciamos el monitor
        monitor.start().await.map_err(|e| AmaruError::RealTimeMonitorError(e.to_string()))?;
        
        self.realtime_monitor = Some(monitor);
        info!("Protección en tiempo real activada correctamente");
        
        Ok(())
    }
    
    /// Deshabilita la protección en tiempo real
    ///
    /// Detiene el monitoreo de archivos y libera los recursos asociados.
    pub async fn disable_realtime_protection(&mut self) -> Result<(), AmaruError> {
        if let Some(monitor) = self.realtime_monitor.take() {
            monitor.stop().await
                .map_err(|e| AmaruError::RealTimeMonitorError(e.to_string()))?;
        }
        Ok(())
    }
    
    /// Actualiza las reglas YARA
    ///
    /// Recarga las reglas desde el directorio configurado.
    ///
    /// # Errores
    /// Retorna error si:
    /// - No se pueden cargar las nuevas reglas
    /// - Las reglas son inválidas
    pub async fn update_yara_rules(&self) -> Result<(), AmaruError> {
        self.yara_engine.as_ref().unwrap().reload_rules()
            .map_err(|e| AmaruError::Yara(e.to_string()))?;
        Ok(())
    }
    
    /// Obtiene un receptor de eventos del antivirus
    ///
    /// Los eventos incluyen:
    /// - Detección de amenazas
    /// - Archivos en cuarentena
    /// - Archivos restaurados
    /// - Actualizaciones
    /// - Errores
    pub fn event_receiver(&self) -> crossbeam_channel::Receiver<Event> {
        self.event_channel.receiver()
    }
    
    // Métodos privados
    
    async fn scan_file_internal(
        path: &Path,
        yara_engine: &YaraEngine,
        radare2_analyzer: &Radare2Analyzer,
        config: &Config,
    ) -> Result<ScanResult, AmaruError> {
        // Verificar tamaño máximo
        let metadata = path.metadata()?;
        if metadata.len() > config.scan_config.max_file_size {
            return Err(AmaruError::Analysis("Archivo demasiado grande".into()));
        }
        
        // Escanear con YARA
        let yara_matches = yara_engine.scan_file(path)
            .map_err(|e| AmaruError::Yara(e.to_string()))?;
            
        // Análisis estático para ejecutables
        let static_analysis = if path.extension().map_or(false, |ext| ext == "exe" || ext == "dll") {
            Some(radare2_analyzer.analyze_pe(path)
                .map_err(|e| AmaruError::Analysis(e.to_string()))?)
        } else {
            None
        };
        
        Ok(ScanResult {
            path: path.to_path_buf(),
            yara_matches,
            static_analysis,
            risk_level: RiskLevel::Low, // El nivel de riesgo se calcula después
            threat_details: None,
            behaviors: None,
        })
    }
    
    fn calculate_risk_level(
        &self,
        yara_matches: &[YaraScanResult],
        static_analysis: &Option<PEAnalysis>,
        behaviors: Option<&[MaliciousBehavior]>,
    ) -> RiskLevel {
        let mut score = 0;
        
        // Puntuación por coincidencias YARA
        for m in yara_matches {
            score += match m.rule_name.as_str() {
                name if name.contains("malware") => 3,
                name if name.contains("exploit") => 4,
                name if name.contains("suspicious") => 2,
                _ => 1,
            };
        }
        
        // Puntuación por análisis estático
        if let Some(analysis) = static_analysis {
            // Secciones sospechosas
            if analysis.has_suspicious_sections {
                score += 2;
            }
            
            // Importaciones sospechosas
            if analysis.has_suspicious_imports {
                score += 2;
            }
            
            // Entropía alta
            if analysis.entropy > 7.0 {
                score += 2;
            }
        }
        
        // Puntuación por comportamientos maliciosos
        if let Some(behaviors) = behaviors {
            for behavior in behaviors {
                score += match behavior.behavior_type {
                    MaliciousBehaviorType::ProcessInjection => 4,
                    MaliciousBehaviorType::SystemPersistence => 3,
                    MaliciousBehaviorType::DetectionEvasion => 3,
                    MaliciousBehaviorType::Ransomware => 5,
                    MaliciousBehaviorType::Keylogger => 4,
                    MaliciousBehaviorType::DataExfiltration => 4,
                    MaliciousBehaviorType::CommandAndControl => 4,
                };
                
                // Ajustar por nivel de confianza
                score = (score as f32 * (behavior.confidence as f32 / 100.0)) as i32;
            }
        }
        
        match score {
            0..=2 => RiskLevel::Low,
            3..=5 => RiskLevel::Medium,
            6..=8 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
    
    fn determine_threat_type(&self, result: &ScanResult) -> ThreatType {
        if !result.yara_matches.is_empty() {
            let rule = &result.yara_matches[0];
            ThreatType::YaraMatch {
                rule_name: rule.rule_name.clone(),
                description: rule.description.clone(),
            }
        } else if let Some(behaviors) = result.behaviors.as_ref() {
            if let Some(behavior) = behaviors.iter().max_by_key(|b| b.confidence) {
                ThreatType::SuspiciousBehavior {
                    behavior_type: format!("{:?}", behavior.behavior_type),
                    description: behavior.description.clone(),
                }
            } else {
                ThreatType::SuspiciousBehavior {
                    behavior_type: "Unknown".into(),
                    description: "Comportamiento sospechoso detectado".into(),
                }
            }
        } else if let Some(analysis) = &result.static_analysis {
            ThreatType::SuspiciousBehavior {
                behavior_type: "Suspicious PE".into(),
                description: format!(
                    "Entropía: {}, Secciones sospechosas: {}, Importaciones sospechosas: {}",
                    analysis.entropy,
                    analysis.has_suspicious_sections,
                    analysis.has_suspicious_imports,
                ),
            }
        } else {
            ThreatType::SuspiciousBehavior {
                behavior_type: "Unknown".into(),
                description: "Comportamiento sospechoso detectado".into(),
            }
        }
    }
    
    fn create_threat_details(
        &self,
        path: &Path,
        yara_matches: &[YaraScanResult],
        static_analysis: &Option<PEAnalysis>,
        behaviors: Option<&[MaliciousBehavior]>,
    ) -> Result<ThreatDetails, AmaruError> {
        use sha2::{Sha256, Digest};
        
        // Calcular hash
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)?;
        let hash = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hasher.finalize());
        
        // Obtener tipo de archivo
        let file_type = if let Some(analysis) = static_analysis {
            analysis.file_type.clone()
        } else {
            "Unknown".to_string()
        };
        
        // Recopilar coincidencias
        let matches = yara_matches.iter()
            .map(|m| format!("{}: {}", m.rule_name, m.description.as_deref().unwrap_or("")))
            .collect();
            
        // Información adicional
        let mut additional_info = serde_json::Map::new();
        if let Some(analysis) = static_analysis {
            additional_info.insert(
                "entropy".to_string(),
                serde_json::Value::Number(serde_json::Number::from_f64(analysis.entropy).unwrap()),
            );
            additional_info.insert(
                "suspicious_sections".to_string(),
                serde_json::Value::Bool(analysis.has_suspicious_sections),
            );
            additional_info.insert(
                "suspicious_imports".to_string(),
                serde_json::Value::Bool(analysis.has_suspicious_imports),
            );
        }
        
        if let Some(behaviors) = behaviors {
            additional_info.insert(
                "malicious_behaviors".to_string(),
                serde_json::Value::Array(
                    behaviors.iter()
                        .map(|b| serde_json::json!({
                            "type": format!("{:?}", b.behavior_type),
                            "description": b.description,
                            "confidence": b.confidence,
                            "evidence": b.evidence
                        }))
                        .collect()
                ),
            );
        }
        
        Ok(ThreatDetails {
            file_hash: hash,
            file_size: path.metadata()?.len(),
            file_type,
            matches,
            additional_info: Some(serde_json::Value::Object(additional_info)),
        })
    }
    
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
    pub fn get_service_status() -> windows_service::Result<windows_service::service::ServiceStatus> {
        service::get_service_status()
    }
    
    /// Crea un nuevo cliente IPC para comunicarse con el servicio
    pub fn create_ipc_client() -> Result<ipc::IpcClient, ipc::IpcError> {
        ipc::IpcClient::connect()
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
    
    /// Obtiene el estado actual del servicio
    pub async fn get_service_state() -> Result<ServiceState, AmaruError> {
        let client = Self::create_ipc_client()
            .map_err(|e| AmaruError::Internal(e.to_string()))?;
            
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
                        } => Some(ScanProgress {
                            files_scanned,
                            files_total,
                            current_file: PathBuf::from(current_file),
                            start_time: chrono::Utc::now() - chrono::Duration::seconds(uptime_secs as i64),
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
            _ => Err(AmaruError::Internal("Respuesta inesperada del servicio".into())),
        }
    }
    
    /// Inicia un escaneo a través del servicio
    pub async fn service_start_scan<P: AsRef<Path>>(&self, path: P) -> Result<(), AmaruError> {
        let mut client = Self::create_ipc_client()
            .map_err(|e| AmaruError::Internal(e.to_string()))?;
            
        match client.start_scan(path.as_ref().to_string_lossy().into_owned())? {
            ipc::IpcResponse::Ok => Ok(()),
            ipc::IpcResponse::Error(msg) => Err(AmaruError::Internal(msg)),
            _ => Err(AmaruError::Internal("Respuesta inesperada del servicio".into())),
        }
    }
    
    /// Detiene el escaneo actual a través del servicio
    pub async fn service_stop_scan(&self) -> Result<(), AmaruError> {
        let mut client = Self::create_ipc_client()
            .map_err(|e| AmaruError::Internal(e.to_string()))?;
            
        match client.stop_scan()? {
            ipc::IpcResponse::Ok => Ok(()),
            ipc::IpcResponse::Error(msg) => Err(AmaruError::Internal(msg)),
            _ => Err(AmaruError::Internal("Respuesta inesperada del servicio".into())),
        }
    }
    
    /// Actualiza las reglas YARA a través del servicio
    pub async fn service_update_rules(&self) -> Result<(), AmaruError> {
        let mut client = Self::create_ipc_client()
            .map_err(|e| AmaruError::Internal(e.to_string()))?;
            
        match client.update_rules()? {
            ipc::IpcResponse::Ok => Ok(()),
            ipc::IpcResponse::Error(msg) => Err(AmaruError::Internal(msg)),
            _ => Err(AmaruError::Internal("Respuesta inesperada del servicio".into())),
        }
    }
    
    /// Obtiene estadísticas del servicio
    pub async fn get_service_stats(&self) -> Result<ServiceStats, AmaruError> {
        let mut client = Self::create_ipc_client()
            .map_err(|e| AmaruError::Internal(e.to_string()))?;
            
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
            _ => Err(AmaruError::Internal("Respuesta inesperada del servicio".into())),
        }
    }
    
    /// Inicializa el motor de análisis heurístico con gestión optimizada de recursos
    pub fn init_heuristic_engine(&mut self, config: Option<HeuristicConfig>) -> Result<(), AmaruError> {
        let heuristic_config = config.unwrap_or_default();
        
        info!("Inicializando motor de análisis heurístico...");
        
        // Usar MiMalloc para la asignación de memoria
        #[cfg(feature = "optimize_memory")]
        {
            std::alloc::System::set_alloc_error_hook(|_| {
                error!("Error crítico de memoria en el motor heurístico");
                std::process::abort();
            });
        }
        
        match HeuristicEngine::new(heuristic_config) {
            Ok(engine) => {
                self.heuristic_engine = Some(engine);
                info!("Motor heurístico inicializado correctamente");
                Ok(())
            },
            Err(e) => {
                error!("Error al inicializar motor heurístico: {}", e);
                Err(AmaruError::InitializationError(format!("Error al inicializar motor heurístico: {}", e)))
            }
        }
    }
    
    /// Optimiza los recursos del sistema según la configuración actual
    pub async fn optimize_resources(&self) -> Result<(), AmaruError> {
        let config = self.config.clone();
        
        // Limpiar caché de escaneo si está demasiado grande
        let cache_size = self.scan_cache.len();
        if cache_size > 10000 {
            debug!("Limpiando caché de escaneo (tamaño actual: {})", cache_size);
            self.scan_cache.retain(|_, (_, timestamp)| {
                timestamp.elapsed() < Duration::from_secs(3600) // Mantener solo la última hora
            });
        }
        
        // Optimizar hilos de análisis según configuración
        if let Some(ref behavior_analyzer) = self.behavior_analyzer {
            behavior_analyzer.optimize_thread_pool(
                if config.performance_config.low_resource_mode { 2 } else { 4 }
            ).await;
        }
        
        // Aplicar límites de memoria para análisis
        if config.performance_config.low_resource_mode {
            if let Some(ref heuristic_engine) = self.heuristic_engine {
                heuristic_engine.set_memory_limit(256 * 1024 * 1024); // 256 MB
            }
        }
        
        Ok(())
    }
    
    /// Inicializa los servicios core integrados
    ///
    /// Esto establece la comunicación entre el sistema de detección de comportamientos,
    /// el sistema de actualizaciones, el sistema de cuarentena y el módulo de análisis
    /// en tiempo real para proporcionar una protección más completa y eficiente.
    pub async fn init_core_services(&mut self) -> Result<(), AmaruError> {
        // Asegurarse de que los motores principales estén inicializados
        if self.yara_engine.is_none() {
            self.yara_engine = Some(YaraEngine::new(&self.config.yara_rules_path)
                .map_err(|e| AmaruError::Yara(e.to_string()))?);
        }
        
        if self.heuristic_engine.is_none() {
            self.init_heuristic_engine(None)?;
        }
        
        // Configurar canal de notificaciones para los servicios core
        let (notif_tx, mut notif_rx) = mpsc::channel::<CoreNotification>(100);
        
        // Inicializar servicios core
        let core_services = CoreServices::new(self.config.clone(), notif_tx)
            .map_err(|e| AmaruError::InitializationError(format!(
                "Error al inicializar los servicios core: {}", e
            )))?;
        
        let core_services = Arc::new(tokio::sync::Mutex::new(core_services));
        self.core_services = Some(core_services.clone());
        
        // Configurar manejo de notificaciones de servicios core
        let event_channel = self.event_channel.clone();
        tokio::spawn(async move {
            while let Some(notification) = notif_rx.recv().await {
                match notification {
                    CoreNotification::ThreatDetected { path, threat_type, confidence, description, timestamp } => {
                        let risk_level = if confidence >= 90 {
                            RiskLevel::Critical
                        } else if confidence >= 70 {
                            RiskLevel::High
                        } else if confidence >= 50 {
                            RiskLevel::Medium
                        } else {
                            RiskLevel::Low
                        };
                        
                        let threat_details = ThreatDetails {
                            path: PathBuf::from(path.clone()),
                            name: threat_type.clone(),
                            description: description.clone(),
                            detection_date: timestamp,
                            signature_type: "Integrated".to_string(),
                            recommended_action: "Quarantine".to_string(),
                        };
                        
                        event_channel.send(Event::ThreatDetected {
                            path: PathBuf::from(path),
                            threat_type: ThreatType::from_str(&threat_type),
                            risk_level,
                            details: threat_details,
                        });
                    },
                    CoreNotification::FileQuarantined { original_path, reason, timestamp } => {
                        event_channel.send(Event::FileQuarantined {
                            path: PathBuf::from(original_path),
                            reason,
                        });
                    },
                    CoreNotification::FileRestored { original_path, timestamp } => {
                        event_channel.send(Event::FileRestored {
                            path: PathBuf::from(original_path),
                        });
                    },
                    CoreNotification::UpdateAvailable { component, version, size, timestamp } => {
                        event_channel.send(Event::UpdateAvailable {
                            component,
                            version,
                            size,
                            timestamp,
                        });
                    },
                    CoreNotification::UpdateApplied { component, version, timestamp } => {
                        event_channel.send(Event::UpdateApplied {
                            component,
                            version,
                            timestamp,
                        });
                    },
                    CoreNotification::RealtimeProtectionStatus { enabled, monitored_paths, timestamp } => {
                        event_channel.send(Event::RealtimeProtectionStatusChanged {
                            enabled,
                            monitored_paths,
                            timestamp,
                        });
                    },
                }
            }
        });
        
        info!("Servicios core inicializados correctamente");
        Ok(())
    }
    
    /// Realiza un análisis integrado de un archivo utilizando todos los servicios core
    ///
    /// Este método combina el análisis de YARA, análisis heurístico y detección de comportamientos
    /// para proporcionar un resultado completo sobre un archivo.
    pub async fn integrated_scan_file<P: AsRef<Path>>(&self, path: P) -> Result<IntegratedScanResult, AmaruError> {
        if let Some(core_services) = &self.core_services {
            let guard = core_services.lock().await;
            guard.scan_file(path).await
        } else {
            Err(AmaruError::Internal("Los servicios core no están inicializados".to_string()))
        }
    }
    
    /// Habilita la protección en tiempo real integrada con todos los servicios
    ///
    /// Activa el monitoreo en tiempo real utilizando YARA, heurística y análisis de comportamiento
    pub async fn enable_integrated_realtime_protection(&mut self) -> Result<bool, AmaruError> {
        if let Some(core_services) = &self.core_services {
            let mut guard = core_services.lock().await;
            guard.enable_realtime_protection().await
        } else {
            Err(AmaruError::Internal("Los servicios core no están inicializados".to_string()))
        }
    }
    
    /// Deshabilita la protección en tiempo real integrada
    pub async fn disable_integrated_realtime_protection(&mut self) -> Result<bool, AmaruError> {
        if let Some(core_services) = &self.core_services {
            let mut guard = core_services.lock().await;
            guard.disable_realtime_protection().await
        } else {
            Err(AmaruError::Internal("Los servicios core no están inicializados".to_string()))
        }
    }
    
    /// Verifica si hay actualizaciones disponibles
    pub async fn check_core_updates(&self) -> Result<bool, AmaruError> {
        if let Some(core_services) = &self.core_services {
            let guard = core_services.lock().await;
            guard.check_updates().await
        } else {
            Err(AmaruError::Internal("Los servicios core no están inicializados".to_string()))
        }
    }
    
    /// Coloca un archivo en cuarentena utilizando el sistema integrado
    pub async fn integrated_quarantine_file<P: AsRef<Path>>(&self, path: P, reason: &str) -> Result<(), AmaruError> {
        if let Some(core_services) = &self.core_services {
            let guard = core_services.lock().await;
            guard.quarantine_file(path, reason)?;
            Ok(())
        } else {
            Err(AmaruError::Internal("Los servicios core no están inicializados".to_string()))
        }
    }
    
    /// Restaura un archivo de cuarentena utilizando el sistema integrado
    pub async fn integrated_restore_file(&self, entry_id: &str) -> Result<PathBuf, AmaruError> {
        if let Some(core_services) = &self.core_services {
            let guard = core_services.lock().await;
            guard.restore_from_quarantine(entry_id)
        } else {
            Err(AmaruError::Internal("Los servicios core no están inicializados".to_string()))
        }
    }

    /// Ejecuta un escaneo con optimización de recursos
    pub async fn scan_file_optimized<P: AsRef<Path>>(&self, path: P) -> Result<EnhancedScanResult, AmaruError> {
        let path = path.as_ref();
        
        // Verificar si tenemos una versión cacheada reciente
        let cache_key = path.to_string_lossy().to_string();
        if let Some(cached) = self.scan_cache.get(&path.to_path_buf()) {
            if cached.1.elapsed() < Duration::from_secs(300) { // Caché válida por 5 minutos
                debug!("Usando resultado cacheado para {}", path.display());
                return Ok(EnhancedScanResult {
                    file_path: path.to_path_buf(),
                    yara_matches: cached.0.yara_matches.clone(),
                    heuristic_result: cached.0.heuristic_result.clone(),
                    is_malicious: cached.0.risk_level >= RiskLevel::Medium,
                    scan_time: 0.0,
                });
            }
        }
        
        // Verificar si el archivo excede el tamaño máximo
        match std::fs::metadata(path) {
            Ok(metadata) => {
                if metadata.len() > self.config.scan_config.max_file_size {
                    warn!("Archivo excede el tamaño máximo: {}", path.display());
                    return Err(AmaruError::Analysis(format!(
                        "El archivo excede el tamaño máximo permitido ({} bytes)",
                        self.config.scan_config.max_file_size
                    )));
                }
            },
            Err(e) => return Err(AmaruError::Io(e)),
        }
        
        let start_time = std::time::Instant::now();
        
        // Ejecutar escaneo YARA
        let yara_result = if let Some(ref engine) = self.yara_engine {
            match engine.scan_file(path) {
                Ok(result) => result,
                Err(e) => return Err(AmaruError::Yara(format!("Error en escaneo YARA: {}", e))),
            }
        } else {
            return Err(AmaruError::Yara("Motor YARA no inicializado".into()));
        };
        
        // Ejecutar análisis heurístico si está habilitado y no hay coincidencias YARA
        let heuristic_result = if self.config.heuristic_analysis && yara_result.matches.is_empty() {
            if let Some(ref engine) = self.heuristic_engine {
                engine.analyze_file(path).ok().flatten()
            } else {
                None
            }
        } else {
            None
        };
        
        let is_malicious = !yara_result.matches.is_empty() || 
                          heuristic_result.as_ref().map_or(false, |r| r.confidence > self.config.heuristic_threshold as f32);
        
        let scan_time = start_time.elapsed().as_secs_f64();
        
        let result = EnhancedScanResult {
            file_path: path.to_path_buf(),
            yara_matches: yara_result.matches,
            heuristic_result,
            is_malicious,
            scan_time,
        };
        
        // Guardar en caché
        self.scan_cache.insert(
            path.to_path_buf(),
            (ScanResult {
                path: path.to_path_buf(),
                yara_matches: vec![],
                static_analysis: None,
                risk_level: if is_malicious { RiskLevel::High } else { RiskLevel::Safe },
                threat_details: None,
                behaviors: None,
            }, std::time::Instant::now())
        );
        
        Ok(result)
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

/// Extensión del ThreatType para facilitar la conversión desde cadenas
impl ThreatType {
    pub fn from_str(s: &str) -> Self {
        match s {
            s if s.starts_with("Malware") => ThreatType::Malware,
            s if s.starts_with("Ransomware") => ThreatType::Ransomware,
            s if s.starts_with("PUA") || s.starts_with("PUP") => ThreatType::PotentiallyUnwantedApp,
            s if s.starts_with("Suspicious") => ThreatType::SuspiciousFile,
            s if s.starts_with("Exploit") => ThreatType::Exploit,
            s if s.starts_with("Rootkit") => ThreatType::Rootkit,
            s if s.contains("Adware") => ThreatType::Adware,
            s if s.contains("Spyware") => ThreatType::Spyware,
            s if s.contains("Keylogger") => ThreatType::Keylogger,
            s if s.contains("Backdoor") => ThreatType::Backdoor,
            s if s.contains("Trojan") => ThreatType::Trojan,
            s if s.contains("Worm") => ThreatType::Worm,
            s if s.contains("Virus") => ThreatType::Virus,
            _ => ThreatType::Unknown,
        }
    }
}

// Extender Event para los nuevos tipos de eventos
impl Event {
    pub fn is_threat_event(&self) -> bool {
        matches!(self, 
            Event::ThreatDetected { .. } | 
            Event::FileQuarantined { .. } |
            Event::FileRestored { .. }
        )
    }
    
    pub fn is_update_event(&self) -> bool {
        matches!(self,
            Event::UpdateAvailable { .. } |
            Event::UpdateApplied { .. }
        )
    }
    
    pub fn is_status_event(&self) -> bool {
        matches!(self,
            Event::RealtimeProtectionStatusChanged { .. } |
            Event::ScanStarted { .. } |
            Event::ScanProgress { .. } |
            Event::ScanCompleted { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::io::Write;
    
    #[tokio::test]
    async fn test_scan_file() -> Result<(), AmaruError> {
        let temp_dir = tempdir()?;
        
        // Crear directorio de reglas
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir)?;
        
        // Crear regla YARA
        let rule_content = r#"
rule test_rule {
    meta:
        description = "Test rule"
    strings:
        $s1 = "malicious"
    condition:
        any of them
}
"#;
        std::fs::write(rules_dir.join("test.yar"), rule_content)?;
        
        // Crear archivo de prueba
        let test_file = temp_dir.path().join("test.exe");
        let content = b"This is a malicious test file";
        std::fs::File::create(&test_file)?.write_all(content)?;
        
        // Crear configuración
        let mut config = Config::default();
        config.yara_rules_path = rules_dir;
        config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");
        
        // Crear instancia de Amaru
        let amaru = Amaru::new(config).await?;
        
        // Escanear archivo
        let result = amaru.scan_file(&test_file).await?;
        
        // Verificar resultado
        assert!(!result.yara_matches.is_empty());
        assert_eq!(result.risk_level, RiskLevel::Medium);
        assert!(result.threat_details.is_some());
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_realtime_protection() -> Result<(), AmaruError> {
        let temp_dir = tempdir()?;
        
        // Crear directorio de reglas
        let rules_dir = temp_dir.path().join("rules");
        std::fs::create_dir(&rules_dir)?;
        
        // Crear regla YARA
        let rule_content = r#"
rule test_rule {
    meta:
        description = "Test rule"
    strings:
        $s1 = "malicious"
    condition:
        any of them
}
"#;
        std::fs::write(rules_dir.join("test.yar"), rule_content)?;
        
        // Crear configuración
        let mut config = Config::default();
        config.yara_rules_path = rules_dir;
        config.monitored_paths = vec![temp_dir.path().to_path_buf()];
        config.quarantine_config.quarantine_path = temp_dir.path().join("quarantine");
        
        // Crear instancia de Amaru
        let mut amaru = Amaru::new(config).await?;
        
        // Habilitar protección en tiempo real
        amaru.enable_realtime_protection().await?;
        
        // Crear archivo malicioso
        let test_file = temp_dir.path().join("test.exe");
        let content = b"This is a malicious test file";
        std::fs::File::create(&test_file)?.write_all(content)?;
        
        // Esperar eventos
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        
        // Deshabilitar protección
        amaru.disable_realtime_protection().await?;
        
        Ok(())
    }
} 