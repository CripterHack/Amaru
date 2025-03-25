use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};

use crate::{
    behavior::{BehaviorAnalyzer, MaliciousBehavior, MaliciousBehaviorType},
    quarantine::{Quarantine, QuarantineEntry, QuarantineError},
    config::{Config, UpdateConfig},
    AmaruError,
};

use realtime_monitor::{RealtimeMonitor, FileEvent, FileEventType, EventAction};
use amaru_yara_engine::{YaraEngine, ScanResult, RuleMatch};
use amaru_yara_engine::heuristic::{HeuristicEngine, HeuristicResult, ThreatType, ConfidenceLevel};
use amaru_updater::{Updater, RuleUpdate, UpdateError};

/// Estructura principal que coordina todos los servicios core
pub struct CoreServices {
    /// Analizador de comportamiento
    behavior_analyzer: Arc<BehaviorAnalyzer>,
    
    /// Motor de reglas YARA
    yara_engine: Arc<Mutex<YaraEngine>>,
    
    /// Motor de análisis heurístico
    heuristic_engine: Arc<Mutex<HeuristicEngine>>,
    
    /// Sistema de cuarentena
    quarantine: Arc<Quarantine>,
    
    /// Monitor en tiempo real
    realtime_monitor: Option<RealtimeMonitor>,
    
    /// Sistema de actualización
    updater: Arc<Mutex<Option<Updater>>>,
    
    /// Configuración
    config: Arc<Mutex<Config>>,
    
    /// Canal para notificaciones
    notification_tx: mpsc::Sender<CoreNotification>,
}

/// Tipos de notificaciones que pueden enviar los servicios core
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoreNotification {
    /// Se ha detectado una amenaza
    ThreatDetected {
        path: String,
        threat_type: String,
        confidence: u8,
        description: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    
    /// Se ha puesto un archivo en cuarentena
    FileQuarantined {
        original_path: String,
        reason: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    
    /// Se ha restaurado un archivo de cuarentena
    FileRestored {
        original_path: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    
    /// Hay actualizaciones disponibles
    UpdateAvailable {
        component: String,
        version: String,
        size: u64,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    
    /// Las actualizaciones se han aplicado
    UpdateApplied {
        component: String,
        version: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    
    /// Estado del servicio de protección en tiempo real
    RealtimeProtectionStatus {
        enabled: bool,
        monitored_paths: Vec<String>,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
}

/// Resultado integrado del análisis de archivos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegratedScanResult {
    /// Ruta del archivo analizado
    pub path: String,
    
    /// Resultados del análisis YARA
    pub yara_matches: Vec<RuleMatch>,
    
    /// Resultados del análisis heurístico
    pub heuristic_result: Option<HeuristicResult>,
    
    /// Comportamientos maliciosos identificados
    pub behaviors: Option<Vec<MaliciousBehavior>>,
    
    /// Nivel de confianza general
    pub confidence: u8,
    
    /// Tipo de amenaza principal detectada
    pub threat_type: String,
    
    /// Descripción de la amenaza
    pub description: String,
    
    /// Timestamp del análisis
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Tiempo que tomó el análisis (en milisegundos)
    pub scan_time_ms: u64,
}

impl CoreServices {
    /// Crea una nueva instancia de CoreServices
    pub fn new(
        config: Config,
        notification_tx: mpsc::Sender<CoreNotification>,
    ) -> Result<Self, AmaruError> {
        let config = Arc::new(Mutex::new(config));
        
        // Inicializar el analizador de comportamiento
        let behavior_analyzer = Arc::new(BehaviorAnalyzer::new());
        
        // Inicializar el motor YARA
        let yara_engine = {
            let config_guard = config.lock().unwrap();
            let yara_config = amaru_yara_engine::YaraConfig {
                rules_paths: vec![config_guard.yara_rules_path.clone()],
                timeout_ms: 3000,
            };
            
            Arc::new(Mutex::new(YaraEngine::new(yara_config)?))
        };
        
        // Inicializar el motor heurístico
        let heuristic_engine = {
            let config_guard = config.lock().unwrap();
            let heuristic_config = amaru_yara_engine::heuristic::HeuristicConfig {
                max_file_size: config_guard.max_file_scan_size,
                min_detection_score: config_guard.heuristic_threshold as u32,
                entropy_threshold: 0.8,
                behavioral_analysis: true,
                pe_analysis: true,
            };
            
            Arc::new(Mutex::new(HeuristicEngine::new(heuristic_config)))
        };
        
        // Inicializar el sistema de cuarentena
        let quarantine = {
            let config_guard = config.lock().unwrap();
            Arc::new(Quarantine::new(
                &config_guard.quarantine_config.quarantine_path,
                config_guard.quarantine_config.max_size,
                config_guard.quarantine_config.retention_days,
            )?)
        };
        
        // Inicializar el sistema de actualización
        let updater = {
            let config_guard = config.lock().unwrap();
            let public_key = if let Some(key) = &config_guard.update_config.public_key {
                key.as_bytes().to_vec()
            } else {
                // Usar una clave pública vacía si no está configurada
                vec![]
            };
            
            let updater = if !public_key.is_empty() {
                match Updater::new(
                    config_guard.yara_rules_path.clone(),
                    PathBuf::from("backup/rules"),
                    &public_key,
                ) {
                    Ok(updater) => Some(updater),
                    Err(e) => {
                        error!("Error al inicializar el sistema de actualización: {}", e);
                        None
                    }
                }
            } else {
                warn!("No se ha configurado una clave pública para verificar actualizaciones");
                None
            };
            
            Arc::new(Mutex::new(updater))
        };
        
        Ok(Self {
            behavior_analyzer,
            yara_engine,
            heuristic_engine,
            quarantine,
            realtime_monitor: None,
            updater,
            config,
            notification_tx,
        })
    }
    
    /// Realiza un análisis integrado de un archivo
    pub async fn scan_file(&self, path: impl AsRef<Path>) -> Result<IntegratedScanResult, AmaruError> {
        let path = path.as_ref().to_path_buf();
        let start_time = std::time::Instant::now();
        
        // Análisis YARA
        let yara_result = {
            let engine = self.yara_engine.lock().unwrap();
            engine.scan_file(&path)?
        };
        
        // Análisis heurístico
        let heuristic_result = {
            let engine = self.heuristic_engine.lock().unwrap();
            engine.analyze_file(&path).ok().flatten()
        };
        
        // Análisis de comportamiento
        let behaviors = if let Some(ref heuristic) = heuristic_result {
            // Utilizar información del análisis heurístico para mejorar la detección de comportamientos
            let mut behaviors = Vec::new();
            
            // Analizar patrones de comportamiento basados en los resultados heurísticos
            if heuristic.entropy > 0.7 {
                behaviors.push(MaliciousBehavior {
                    behavior_type: MaliciousBehaviorType::DetectionEvasion,
                    confidence: ((heuristic.entropy * 100.0) as u8).min(100),
                    description: "Alto nivel de entropía detectado, posible ofuscación".to_string(),
                });
            }
            
            // Si es un PE, añadir comportamientos específicos
            if let Some(ref patterns) = heuristic.patterns {
                for pattern in patterns {
                    if pattern.name.contains("injection") {
                        behaviors.push(MaliciousBehavior {
                            behavior_type: MaliciousBehaviorType::ProcessInjection,
                            confidence: pattern.confidence as u8,
                            description: pattern.description.clone(),
                        });
                    } else if pattern.name.contains("persistence") {
                        behaviors.push(MaliciousBehavior {
                            behavior_type: MaliciousBehaviorType::SystemPersistence,
                            confidence: pattern.confidence as u8,
                            description: pattern.description.clone(),
                        });
                    } else if pattern.name.contains("ransom") || pattern.pattern.contains("encrypt") {
                        behaviors.push(MaliciousBehavior {
                            behavior_type: MaliciousBehaviorType::Ransomware,
                            confidence: pattern.confidence as u8,
                            description: pattern.description.clone(),
                        });
                    }
                }
            }
            
            if behaviors.is_empty() {
                None
            } else {
                Some(behaviors)
            }
        } else {
            None
        };
        
        // Determinar el nivel de confianza general
        let confidence = self.calculate_confidence(&yara_result, &heuristic_result, &behaviors);
        
        // Determinar el tipo de amenaza
        let (threat_type, description) = self.determine_threat_type(&yara_result, &heuristic_result, &behaviors);
        
        let scan_time_ms = start_time.elapsed().as_millis() as u64;
        
        // Notificar si se encontró una amenaza
        if confidence >= 70 {
            self.notify_threat_detected(&path, &threat_type, confidence, &description).await;
        }
        
        Ok(IntegratedScanResult {
            path: path.to_string_lossy().to_string(),
            yara_matches: yara_result.matches,
            heuristic_result,
            behaviors,
            confidence,
            threat_type,
            description,
            timestamp: chrono::Utc::now(),
            scan_time_ms,
        })
    }
    
    /// Calcula el nivel de confianza general basado en los resultados de diferentes análisis
    fn calculate_confidence(
        &self,
        yara_result: &ScanResult,
        heuristic_result: &Option<HeuristicResult>,
        behaviors: &Option<Vec<MaliciousBehavior>>,
    ) -> u8 {
        let mut confidence = 0;
        
        // Confianza por coincidencias YARA
        if !yara_result.matches.is_empty() {
            let max_severity = yara_result.matches.iter()
                .map(|m| m.meta.get("severity").unwrap_or(&"50".to_string()).parse::<u8>().unwrap_or(50))
                .max()
                .unwrap_or(50);
            
            confidence = confidence.max(max_severity);
        }
        
        // Confianza por resultado heurístico
        if let Some(heuristic) = heuristic_result {
            let heuristic_confidence = match heuristic.confidence {
                ConfidenceLevel::Low => 30,
                ConfidenceLevel::Medium => 60,
                ConfidenceLevel::High => 80,
                ConfidenceLevel::VeryHigh => 95,
            };
            
            confidence = confidence.max(heuristic_confidence);
        }
        
        // Confianza por comportamientos detectados
        if let Some(behaviors) = behaviors {
            for behavior in behaviors {
                let behavior_confidence = match behavior.behavior_type {
                    MaliciousBehaviorType::Ransomware => (behavior.confidence as u16 * 12 / 10).min(100) as u8,
                    MaliciousBehaviorType::ProcessInjection => (behavior.confidence as u16 * 11 / 10).min(100) as u8,
                    MaliciousBehaviorType::CommandAndControl => (behavior.confidence as u16 * 11 / 10).min(100) as u8,
                    _ => behavior.confidence,
                };
                
                confidence = confidence.max(behavior_confidence);
            }
        }
        
        confidence
    }
    
    /// Determina el tipo principal de amenaza y su descripción
    fn determine_threat_type(
        &self,
        yara_result: &ScanResult,
        heuristic_result: &Option<HeuristicResult>,
        behaviors: &Option<Vec<MaliciousBehavior>>,
    ) -> (String, String) {
        // Priorizar coincidencias YARA con alta severidad
        if !yara_result.matches.is_empty() {
            let highest_severity_match = yara_result.matches.iter()
                .max_by_key(|m| m.meta.get("severity").unwrap_or(&"50".to_string()).parse::<u8>().unwrap_or(50));
            
            if let Some(top_match) = highest_severity_match {
                let malware_type = top_match.meta.get("malware_type")
                    .unwrap_or(&"Malware".to_string())
                    .to_string();
                
                let description = top_match.meta.get("description")
                    .unwrap_or(&format!("Amenaza detectada: {}", top_match.rule_name))
                    .to_string();
                
                return (malware_type, description);
            }
        }
        
        // Si no hay coincidencias YARA de alta severidad, revisar resultados heurísticos
        if let Some(heuristic) = heuristic_result {
            let threat_type = match &heuristic.threat_type {
                ThreatType::Malware { name, .. } => format!("Malware:{}", name),
                ThreatType::Ransomware { family, .. } => format!("Ransomware:{}", family),
                ThreatType::SuspiciousBehavior { behavior_type, .. } => format!("Suspicious:{}", behavior_type),
                ThreatType::Unknown => "Unknown".to_string(),
            };
            
            return (threat_type, heuristic.description.clone());
        }
        
        // Por último, revisar comportamientos
        if let Some(behaviors) = behaviors {
            if let Some(primary_behavior) = behaviors.iter().max_by_key(|b| b.confidence) {
                let behavior_type = format!("{:?}", primary_behavior.behavior_type);
                return (behavior_type, primary_behavior.description.clone());
            }
        }
        
        // Si no hay nada, devolver tipo desconocido
        ("Unknown".to_string(), "Archivo analizado sin amenazas detectadas".to_string())
    }
    
    /// Envía una notificación sobre una amenaza detectada
    async fn notify_threat_detected(
        &self, 
        path: &Path,
        threat_type: &str,
        confidence: u8,
        description: &str
    ) -> bool {
        let notification = CoreNotification::ThreatDetected {
            path: path.to_string_lossy().to_string(),
            threat_type: threat_type.to_string(),
            confidence,
            description: description.to_string(),
            timestamp: chrono::Utc::now(),
        };
        
        match self.notification_tx.send(notification).await {
            Ok(_) => true,
            Err(e) => {
                error!("Error al enviar notificación de amenaza: {}", e);
                false
            }
        }
    }
    
    /// Coloca un archivo en cuarentena
    pub fn quarantine_file(&self, path: impl AsRef<Path>, reason: &str) -> Result<QuarantineEntry, AmaruError> {
        let entry = self.quarantine.quarantine_file(path.as_ref(), reason)?;
        
        // Intentar enviar la notificación de cuarentena de forma no bloqueante
        let notification = CoreNotification::FileQuarantined {
            original_path: entry.original_path.to_string_lossy().to_string(),
            reason: reason.to_string(),
            timestamp: chrono::Utc::now(),
        };
        
        let notification_tx = self.notification_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = notification_tx.send(notification).await {
                error!("Error al enviar notificación de cuarentena: {}", e);
            }
        });
        
        Ok(entry)
    }
    
    /// Restaura un archivo de cuarentena
    pub fn restore_from_quarantine(&self, entry_id: &str) -> Result<PathBuf, AmaruError> {
        let original_path = self.quarantine.restore_file_by_id(entry_id)?;
        
        // Intentar enviar la notificación de restauración de forma no bloqueante
        let notification = CoreNotification::FileRestored {
            original_path: original_path.to_string_lossy().to_string(),
            timestamp: chrono::Utc::now(),
        };
        
        let notification_tx = self.notification_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = notification_tx.send(notification).await {
                error!("Error al enviar notificación de restauración: {}", e);
            }
        });
        
        Ok(original_path)
    }
    
    /// Habilita la protección en tiempo real integrando todos los servicios core
    pub async fn enable_realtime_protection(&mut self) -> Result<bool, AmaruError> {
        if self.realtime_monitor.is_some() {
            info!("La protección en tiempo real ya está activa");
            return Ok(true);
        }
        
        info!("Habilitando protección en tiempo real con análisis integrado...");
        
        // Obtener configuración
        let monitor_config = {
            let config_guard = self.config.lock().unwrap();
            
            realtime_monitor::MonitorConfig {
                paths_to_monitor: config_guard.monitored_paths.clone(),
                extensions_to_monitor: config_guard.monitored_extensions.clone(),
                ignore_patterns: config_guard.exclude_patterns.clone(),
                event_delay_ms: 500,
                max_file_size: config_guard.max_file_scan_size,
            }
        };
        
        // Referencias clonadas para el callback
        let yara_engine = self.yara_engine.clone();
        let heuristic_engine = self.heuristic_engine.clone();
        let behavior_analyzer = self.behavior_analyzer.clone();
        let quarantine = self.quarantine.clone();
        let notification_tx = self.notification_tx.clone();
        let config = self.config.clone();
        
        // Crear y configurar el monitor con un callback que integra todos los servicios
        let monitor = RealtimeMonitor::with_callback(
            monitor_config,
            move |event: FileEvent| -> EventAction {
                let path = event.path.clone();
                
                // Solo procesar creaciones y modificaciones
                if !matches!(event.event_type, FileEventType::Created | FileEventType::Modified) {
                    return EventAction::Continue;
                }
                
                // Ignorar archivos muy grandes
                if let Ok(metadata) = std::fs::metadata(&path) {
                    let config_guard = config.lock().unwrap();
                    if metadata.len() > config_guard.max_file_scan_size as u64 {
                        return EventAction::Continue;
                    }
                }
                
                // Verificar con YARA
                let yara_scan = {
                    let engine = yara_engine.lock().unwrap();
                    match engine.scan_file(&path) {
                        Ok(result) => {
                            if !result.matches.is_empty() {
                                // Amenaza detectada por YARA
                                let threat_name = if let Some(first_match) = result.matches.first() {
                                    first_match.rule_name.clone()
                                } else {
                                    "Amenaza desconocida".to_string()
                                };
                                
                                let description = format!("Amenaza detectada por YARA: {}", threat_name);
                                
                                // Colocar en cuarentena si está habilitado
                                let config_guard = config.lock().unwrap();
                                if config_guard.auto_quarantine {
                                    if let Err(e) = quarantine.quarantine_file(&path, &description) {
                                        error!("Error al poner en cuarentena: {}", e);
                                    }
                                }
                                
                                // Notificar
                                let notification = CoreNotification::ThreatDetected {
                                    path: path.to_string_lossy().to_string(),
                                    threat_type: "Malware".to_string(),
                                    confidence: 90,
                                    description,
                                    timestamp: chrono::Utc::now(),
                                };
                                
                                let tx = notification_tx.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = tx.send(notification).await {
                                        error!("Error al enviar notificación: {}", e);
                                    }
                                });
                                
                                return EventAction::Continue;
                            }
                            false
                        }
                        Err(e) => {
                            error!("Error en análisis YARA: {}", e);
                            false
                        }
                    }
                };
                
                // Si YARA no detectó nada, verificar con análisis heurístico
                if !yara_scan {
                    let heuristic_scan = {
                        let engine = heuristic_engine.lock().unwrap();
                        match engine.analyze_file(&path) {
                            Some(Ok(result)) if result.score >= 70 => {
                                // Comportamiento sospechoso detectado
                                let description = result.description.clone();
                                
                                // Colocar en cuarentena si está habilitado y la confianza es alta
                                let config_guard = config.lock().unwrap();
                                if config_guard.auto_quarantine && result.confidence == ConfidenceLevel::High {
                                    if let Err(e) = quarantine.quarantine_file(&path, &description) {
                                        error!("Error al poner en cuarentena: {}", e);
                                    }
                                }
                                
                                // Notificar
                                let notification = CoreNotification::ThreatDetected {
                                    path: path.to_string_lossy().to_string(),
                                    threat_type: "Comportamiento sospechoso".to_string(),
                                    confidence: (result.score as f32 * 0.9) as u8,
                                    description,
                                    timestamp: chrono::Utc::now(),
                                };
                                
                                let tx = notification_tx.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = tx.send(notification).await {
                                        error!("Error al enviar notificación: {}", e);
                                    }
                                });
                                
                                true
                            }
                            _ => false,
                        }
                    };
                    
                    if heuristic_scan {
                        return EventAction::Continue;
                    }
                }
                
                // Si no se detectó nada con YARA ni heurística, continuar monitoreando
                EventAction::Continue
            },
        ).await.map_err(|e| AmaruError::RealTimeMonitorError(format!(
            "No se pudo inicializar el monitor en tiempo real: {}", e
        )))?;
        
        // Iniciar el monitor
        monitor.start().await.map_err(|e| AmaruError::RealTimeMonitorError(e.to_string()))?;
        
        self.realtime_monitor = Some(monitor);
        
        // Notificar que se ha activado la protección en tiempo real
        let monitored_paths = {
            let config_guard = self.config.lock().unwrap();
            config_guard.monitored_paths.clone()
        };
        
        let notification = CoreNotification::RealtimeProtectionStatus {
            enabled: true,
            monitored_paths,
            timestamp: chrono::Utc::now(),
        };
        
        if let Err(e) = self.notification_tx.send(notification).await {
            error!("Error al enviar notificación de protección en tiempo real: {}", e);
        }
        
        info!("Protección en tiempo real activada correctamente");
        Ok(true)
    }
    
    /// Deshabilita la protección en tiempo real
    pub async fn disable_realtime_protection(&mut self) -> Result<bool, AmaruError> {
        if let Some(monitor) = self.realtime_monitor.take() {
            monitor.stop().await.map_err(|e| AmaruError::RealTimeMonitorError(e.to_string()))?;
            
            // Notificar que se ha desactivado la protección en tiempo real
            let notification = CoreNotification::RealtimeProtectionStatus {
                enabled: false,
                monitored_paths: Vec::new(),
                timestamp: chrono::Utc::now(),
            };
            
            if let Err(e) = self.notification_tx.send(notification).await {
                error!("Error al enviar notificación de protección en tiempo real: {}", e);
            }
            
            info!("Protección en tiempo real desactivada");
            Ok(true)
        } else {
            info!("La protección en tiempo real ya está desactivada");
            Ok(false)
        }
    }
    
    /// Verifica si hay actualizaciones disponibles y notifica
    pub async fn check_updates(&self) -> Result<bool, AmaruError> {
        let updater_guard = self.updater.lock().unwrap();
        let update_config = {
            let config_guard = self.config.lock().unwrap();
            config_guard.update_config.clone()
        };
        
        if let Some(updater) = &*updater_guard {
            match updater.check_updates(&update_config.update_url).await {
                Ok(Some(update)) => {
                    // Notificar que hay actualizaciones disponibles
                    let notification = CoreNotification::UpdateAvailable {
                        component: "YARA Rules".to_string(),
                        version: update.version.clone(),
                        size: update.rules.iter().map(|r| r.size).sum(),
                        timestamp: chrono::Utc::now(),
                    };
                    
                    if let Err(e) = self.notification_tx.send(notification).await {
                        error!("Error al enviar notificación de actualización: {}", e);
                    }
                    
                    // Aplicar automáticamente si está configurado
                    if update_config.auto_update {
                        return self.apply_update(update).await;
                    }
                    
                    Ok(true)
                }
                Ok(None) => {
                    info!("No hay actualizaciones disponibles");
                    Ok(false)
                }
                Err(e) => {
                    error!("Error al verificar actualizaciones: {}", e);
                    Err(AmaruError::UpdateError(format!("Error al verificar actualizaciones: {}", e)))
                }
            }
        } else {
            warn!("Sistema de actualización no inicializado");
            Ok(false)
        }
    }
    
    /// Aplica una actualización
    pub async fn apply_update(&self, update: RuleUpdate) -> Result<bool, AmaruError> {
        let updater_guard = self.updater.lock().unwrap();
        
        if let Some(updater) = &*updater_guard {
            match updater.apply_update(update.clone()).await {
                Ok(()) => {
                    // Recargar las reglas YARA
                    {
                        let mut yara_engine = self.yara_engine.lock().unwrap();
                        if let Err(e) = yara_engine.update_rules() {
                            error!("Error al recargar reglas YARA: {}", e);
                        }
                    }
                    
                    // Notificar que se ha aplicado la actualización
                    let notification = CoreNotification::UpdateApplied {
                        component: "YARA Rules".to_string(),
                        version: update.version.clone(),
                        timestamp: chrono::Utc::now(),
                    };
                    
                    if let Err(e) = self.notification_tx.send(notification).await {
                        error!("Error al enviar notificación de actualización aplicada: {}", e);
                    }
                    
                    info!("Actualización aplicada correctamente: {}", update.version);
                    Ok(true)
                }
                Err(e) => {
                    error!("Error al aplicar actualización: {}", e);
                    Err(AmaruError::UpdateError(format!("Error al aplicar actualización: {}", e)))
                }
            }
        } else {
            warn!("Sistema de actualización no inicializado");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::sync::mpsc;
    
    async fn setup_test_services() -> (CoreServices, mpsc::Receiver<CoreNotification>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        
        // Crear directorios necesarios
        let rules_dir = temp_dir.path().join("rules");
        let quarantine_dir = temp_dir.path().join("quarantine");
        std::fs::create_dir_all(&rules_dir).unwrap();
        std::fs::create_dir_all(&quarantine_dir).unwrap();
        
        // Crear regla YARA de prueba
        let rule_content = r#"
        rule test_malware {
            meta:
                description = "Test malware"
                severity = "80"
                malware_type = "Test"
            strings:
                $a = "MALWARE_TEST" ascii
            condition:
                $a
        }
        "#;
        std::fs::write(rules_dir.join("test.yar"), rule_content).unwrap();
        
        // Configuración
        let mut config = Config::default();
        config.yara_rules_path = rules_dir.to_string_lossy().to_string();
        config.monitored_paths = vec![temp_dir.path().to_string_lossy().to_string()];
        config.quarantine_config.quarantine_path = quarantine_dir;
        
        // Canales para notificaciones
        let (tx, rx) = mpsc::channel(100);
        
        // Crear servicios
        let services = CoreServices::new(config, tx).unwrap();
        
        (services, rx, temp_dir)
    }
    
    #[tokio::test]
    async fn test_integrated_scan() {
        let (services, mut rx, temp_dir) = setup_test_services().await;
        
        // Crear archivo limpio
        let clean_file = temp_dir.path().join("clean.txt");
        std::fs::write(&clean_file, "This is a clean file").unwrap();
        
        // Crear archivo malicioso
        let malicious_file = temp_dir.path().join("malicious.txt");
        std::fs::write(&malicious_file, "This file contains MALWARE_TEST pattern").unwrap();
        
        // Escanear archivo limpio
        let clean_result = services.scan_file(&clean_file).await.unwrap();
        assert!(clean_result.yara_matches.is_empty());
        assert!(clean_result.confidence < 70);
        
        // Escanear archivo malicioso
        let malicious_result = services.scan_file(&malicious_file).await.unwrap();
        assert!(!malicious_result.yara_matches.is_empty());
        assert!(malicious_result.confidence >= 70);
        assert_eq!(malicious_result.threat_type, "Test");
        
        // Verificar que se recibió la notificación
        let notification = rx.try_recv().unwrap();
        match notification {
            CoreNotification::ThreatDetected { path, .. } => {
                assert_eq!(path, malicious_file.to_string_lossy().to_string());
            }
            _ => panic!("Notificación incorrecta"),
        }
    }
    
    #[tokio::test]
    async fn test_quarantine_integration() {
        let (services, mut rx, temp_dir) = setup_test_services().await;
        
        // Crear archivo para cuarentena
        let test_file = temp_dir.path().join("test_quarantine.txt");
        std::fs::write(&test_file, "Test file for quarantine").unwrap();
        
        // Poner en cuarentena
        let entry = services.quarantine_file(&test_file, "Prueba de cuarentena").unwrap();
        
        // Verificar que el archivo ya no existe en su ubicación original
        assert!(!test_file.exists());
        
        // Verificar notificación
        let notification = rx.try_recv().unwrap();
        match notification {
            CoreNotification::FileQuarantined { original_path, .. } => {
                assert_eq!(original_path, test_file.to_string_lossy().to_string());
            }
            _ => panic!("Notificación incorrecta"),
        }
        
        // Restaurar
        let restored_path = services.restore_from_quarantine(&entry.id).unwrap();
        assert_eq!(restored_path, test_file);
        assert!(test_file.exists());
        
        // Verificar notificación de restauración
        let notification = rx.try_recv().unwrap();
        match notification {
            CoreNotification::FileRestored { original_path, .. } => {
                assert_eq!(original_path, test_file.to_string_lossy().to_string());
            }
            _ => panic!("Notificación incorrecta"),
        }
    }
    
    #[tokio::test]
    async fn test_realtime_protection() {
        let (mut services, mut rx, temp_dir) = setup_test_services().await;
        
        // Habilitar protección en tiempo real
        services.enable_realtime_protection().await.unwrap();
        
        // Verificar notificación
        let notification = rx.try_recv().unwrap();
        match notification {
            CoreNotification::RealtimeProtectionStatus { enabled, .. } => {
                assert!(enabled);
            }
            _ => panic!("Notificación incorrecta"),
        }
        
        // Crear archivo malicioso en la carpeta monitoreada
        let malicious_file = temp_dir.path().join("realtime_test.txt");
        std::fs::write(&malicious_file, "This file contains MALWARE_TEST pattern").unwrap();
        
        // Esperar un poco para que el monitor procese el archivo
        tokio::time::sleep(Duration::from_millis(1000)).await;
        
        // Verificar notificación de amenaza
        let notification = rx.try_recv().unwrap();
        match notification {
            CoreNotification::ThreatDetected { path, .. } => {
                assert_eq!(path, malicious_file.to_string_lossy().to_string());
            }
            _ => panic!("Notificación incorrecta"),
        }
        
        // Deshabilitar protección en tiempo real
        services.disable_realtime_protection().await.unwrap();
        
        // Verificar notificación
        let notification = rx.try_recv().unwrap();
        match notification {
            CoreNotification::RealtimeProtectionStatus { enabled, .. } => {
                assert!(!enabled);
            }
            _ => panic!("Notificación incorrecta"),
        }
    }
} 