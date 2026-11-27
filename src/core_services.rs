use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};
use tokio::sync::mpsc;

use crate::{
    behavior::MaliciousBehavior, config::Config, quarantine::QuarantineEntry, Amaru, AmaruError,
    Event, RiskLevel, ThreatType,
};
use updater::{RuleUpdate, Updater};
use yara_engine::{heuristic::HeuristicResult, RuleMatch};

/// Adapter for the service API. All file, monitor and quarantine operations use the same engine.
pub struct CoreServices {
    amaru: Amaru,
    config: Config,
    updater: Option<Updater>,
    notification_tx: mpsc::Sender<CoreNotification>,
    _relay_lifetime: crossbeam_channel::Sender<()>,
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
        size: Option<u64>,
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

    /// Puntuación de compatibilidad (0–100) basada en severidad o evidencia del motor.
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
    pub fn new(
        config: Config,
        notifications: mpsc::Sender<CoreNotification>,
    ) -> Result<Self, AmaruError> {
        Self::from_amaru(Amaru::from_config(config.clone())?, config, notifications)
    }

    pub(crate) fn from_amaru(
        amaru: Amaru,
        config: Config,
        notification_tx: mpsc::Sender<CoreNotification>,
    ) -> Result<Self, AmaruError> {
        let updater = config
            .update_config
            .public_key
            .as_ref()
            .map(|key| {
                let bytes = hex::decode(key.trim())
                    .map_err(|e| AmaruError::Config(format!("Invalid updater public key: {e}")))?;
                let rules = &config.yara_rules_path;
                let mut name = rules
                    .file_name()
                    .ok_or_else(|| {
                        AmaruError::Config("The rule update directory must have a name".into())
                    })?
                    .to_owned();
                name.push(".backups");
                let backup = rules.with_file_name(name);
                Updater::new(&config.yara_rules_path, backup, &bytes)
                    .map_err(|e| AmaruError::UpdateError(e.to_string()))
            })
            .transpose()?;

        let events = amaru.event_receiver();
        let tx = notification_tx.clone();
        let (lifetime, shutdown) = crossbeam_channel::bounded::<()>(0);
        std::thread::Builder::new()
            .name("amaru-service-notifications".into())
            .spawn(move || {
                let forward = |event| {
                    if let Some(notification) = Self::translate_event(event) {
                        match tx.try_send(notification) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Closed(_)) => return false,
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                log::warn!("Core notification queue is full")
                            }
                        }
                    }
                    true
                };
                loop {
                    crossbeam_channel::select! {
                        recv(shutdown) -> _ => {
                            // Flush events already emitted by a one-shot command.
                            for event in events.try_iter().take(events.len()) {
                                if !forward(event) { break; }
                            }
                            break;
                        }
                        recv(events) -> event => match event {
                            Ok(event) => if !forward(event) { break; },
                            Err(_) => break,
                        }
                    }
                }
            })?;
        Ok(Self {
            amaru,
            config,
            updater,
            notification_tx,
            _relay_lifetime: lifetime,
        })
    }

    fn translate_event(event: Event) -> Option<CoreNotification> {
        match event {
            Event::ThreatDetected {
                path,
                threat_type,
                risk_level,
                details,
                timestamp,
            } => {
                let (name, description) = match threat_type {
                    ThreatType::YaraMatch {
                        rule_name,
                        description,
                    } => (rule_name, description.unwrap_or_default()),
                    ThreatType::SuspiciousBehavior {
                        behavior_type,
                        description,
                    } => (behavior_type, description),
                    ThreatType::KnownMalware { name, family } => (name, family.unwrap_or_default()),
                    ThreatType::PotentialExploit { exploit_type, cve } => {
                        (exploit_type, cve.unwrap_or_default())
                    }
                };
                let confidence = details
                    .additional_info
                    .as_ref()
                    .and_then(|v| v.get("confidence"))
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u8::try_from(v).ok())
                    .unwrap_or_else(|| Self::risk_confidence(risk_level));
                Some(CoreNotification::ThreatDetected {
                    path: path.display().to_string(),
                    threat_type: name,
                    description,
                    confidence,
                    timestamp,
                })
            }
            Event::FileQuarantined {
                original_path,
                reason,
                timestamp,
            } => Some(CoreNotification::FileQuarantined {
                original_path: original_path.display().to_string(),
                reason,
                timestamp,
            }),
            Event::FileRestored {
                original_path,
                timestamp,
            } => Some(CoreNotification::FileRestored {
                original_path: original_path.display().to_string(),
                timestamp,
            }),
            Event::RealtimeProtectionStatusChanged {
                enabled,
                monitored_paths,
                timestamp,
            } => Some(CoreNotification::RealtimeProtectionStatus {
                enabled,
                monitored_paths: monitored_paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect(),
                timestamp,
            }),
            _ => None,
        }
    }

    // Compatibility values for older integrations that only expose numeric confidence bands.
    fn risk_confidence(risk: RiskLevel) -> u8 {
        match risk {
            RiskLevel::Low => 0,
            RiskLevel::Medium => 50,
            RiskLevel::High => 80,
            RiskLevel::Critical => 95,
        }
    }

    pub async fn scan_file(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<IntegratedScanResult, AmaruError> {
        let start = Instant::now();
        let scan = self.amaru.scan_file(path.as_ref()).await?;
        let mut confidence = Self::risk_confidence(scan.risk_level);
        let mut threat_type = String::from("Unknown");
        let mut description = scan
            .threat_details
            .as_ref()
            .map(|d| d.matches.join(", "))
            .unwrap_or_default();
        if let Some(rule_match) = scan
            .yara_matches
            .iter()
            .max_by_key(|r| crate::rule_severity(r).unwrap_or(55))
        {
            if let Some(severity) = crate::rule_severity(rule_match) {
                confidence = severity;
            }
            threat_type = rule_match
                .meta
                .get("malware_type")
                .and_then(|v| v.as_str())
                .unwrap_or(&rule_match.rule_name)
                .to_owned();
            description = rule_match
                .meta
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or(&rule_match.rule_name)
                .to_owned();
        } else if let Some(behavior) = scan.behaviors.iter().flatten().max_by_key(|b| b.confidence)
        {
            confidence = behavior.confidence;
            threat_type = format!("{:?}", behavior.behavior_type);
            description = behavior.description.clone();
        } else if let Some(h) = &scan.heuristic_result {
            if h.score >= u32::from(self.config.heuristic_threshold) {
                threat_type = format!("{:?}", h.threat_type);
                description = h.description.clone();
            }
        }
        Ok(IntegratedScanResult {
            path: scan.path.display().to_string(),
            yara_matches: scan.yara_matches,
            heuristic_result: scan.heuristic_result,
            behaviors: scan.behaviors,
            confidence,
            threat_type,
            description,
            timestamp: chrono::Utc::now(),
            scan_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    pub fn quarantine_file(
        &self,
        path: impl AsRef<Path>,
        reason: &str,
    ) -> Result<QuarantineEntry, AmaruError> {
        self.amaru.quarantine_file(path, reason)
    }

    pub fn restore_from_quarantine(&self, entry_id: &str) -> Result<PathBuf, AmaruError> {
        self.amaru.restore_quarantined(entry_id)
    }

    fn send(&self, message: CoreNotification) {
        if let Err(err) = self.notification_tx.try_send(message) {
            log::warn!("Core notification: {err}");
        }
    }

    pub async fn enable_realtime_protection(&mut self) -> Result<bool, AmaruError> {
        let was_enabled = self.amaru.realtime_enabled();
        self.amaru.enable_realtime_protection().await?;
        Ok(!was_enabled)
    }

    pub async fn disable_realtime_protection(&mut self) -> Result<bool, AmaruError> {
        let was_enabled = self.amaru.realtime_enabled();
        self.amaru.disable_realtime_protection().await?;
        Ok(was_enabled)
    }

    pub async fn check_updates(&self) -> Result<bool, AmaruError> {
        if self.updater.is_none() {
            return Ok(false);
        }
        self.check_rule_update(self.config.update_config.auto_update)
            .await
    }

    /// Explicit user request: authenticate and apply an available rule package.
    pub async fn update_rules(&self) -> Result<bool, AmaruError> {
        self.check_rule_update(true).await
    }

    async fn check_rule_update(&self, apply: bool) -> Result<bool, AmaruError> {
        let updater = self
            .updater
            .as_ref()
            .ok_or_else(|| AmaruError::UpdateError("Missing update verification key".into()))?;
        let Some(update) = updater
            .check_updates(&self.config.update_config.update_url)
            .await
            .map_err(|e| AmaruError::UpdateError(e.to_string()))?
        else {
            return Ok(false);
        };
        self.send(CoreNotification::UpdateAvailable {
            component: "YARA Rules".into(),
            version: update.version.clone(),
            size: None,
            timestamp: chrono::Utc::now(),
        });
        if apply {
            self.apply_update(update).await
        } else {
            Ok(true)
        }
    }

    pub async fn apply_update(&self, update: RuleUpdate) -> Result<bool, AmaruError> {
        let updater = self
            .updater
            .as_ref()
            .ok_or_else(|| AmaruError::UpdateError("Missing update verification key".into()))?;
        let version = update.version.clone();
        updater
            .apply_update_checked(update, |staging| {
                yara_engine::YaraEngine::new(staging)
                    .map(|_| ())
                    .map_err(|e| updater::UpdateError::Invalid(e.to_string()))
            })
            .await
            .map_err(|e| AmaruError::UpdateError(e.to_string()))?;
        self.amaru.update_yara_rules().await?;
        self.send(CoreNotification::UpdateApplied {
            component: "YARA Rules".into(),
            version,
            timestamp: chrono::Utc::now(),
        });
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
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
        config.yara_rules_path = rules_dir;
        config.monitored_paths = vec![temp_dir.path().to_path_buf()];
        config.scan_config.scan_extensions.clear();
        config.quarantine_config.quarantine_path = quarantine_dir;
        // Public test key corresponding to the deterministic Ed25519 seed [7; 32].
        config.update_config.public_key =
            Some("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c".into());

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
        let notification = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        match notification {
            CoreNotification::ThreatDetected { path, .. } => {
                assert_eq!(path, malicious_file.to_string_lossy().to_string());
            }
            _ => panic!("Notificación incorrecta"),
        }
    }

    #[tokio::test]
    async fn signed_but_invalid_rules_preserve_installed_tree_and_scanner() {
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        const INVALID: &[u8] = b"rule Broken { condition: }";
        let (services, _rx, temp) = setup_test_services().await;
        let live = temp.path().join("rules");
        let original = std::fs::read(live.join("test.yar")).unwrap();
        std::fs::write(live.join("version.txt"), "1.0.0").unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = format!("http://{}/test.yar", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = String::new();
            BufReader::new(&mut stream)
                .read_line(&mut request)
                .await
                .unwrap();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        INVALID.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(INVALID).await.unwrap();
        });
        let package = RuleUpdate {
            version: "1.1.0".into(),
            timestamp: 0,
            rules: vec![updater::RuleFile {
                path: "test.yar".into(),
                hash: hex::encode(Sha256::digest(INVALID)),
                url,
            }],
            signatures: vec![updater::Signature {
                file_path: "test.yar".into(),
                signature: hex::decode(concat!(
                    "e87a8ceb543b7bc9c12497e672c966e9a0027b864df7df92f22655ce2eb12de7",
                    "80c326f07c2c81dc470c9aeeda655c86991840fabce0807f2d53be0612ea2f0d"
                ))
                .unwrap(),
            }],
            rollback_version: None,
        };
        let error = services.apply_update(package).await.unwrap_err();
        server.await.unwrap();
        assert!(error.to_string().contains("syntax error"), "{error}");
        assert_eq!(std::fs::read(live.join("test.yar")).unwrap(), original);
        assert_eq!(
            std::fs::read_to_string(live.join("version.txt")).unwrap(),
            "1.0.0"
        );
        let sample = temp.path().join("sample.txt");
        std::fs::write(&sample, "MALWARE_TEST").unwrap();
        assert_eq!(
            services.scan_file(sample).await.unwrap().yara_matches.len(),
            1
        );
    }

    #[tokio::test]
    async fn test_quarantine_integration() {
        let (services, mut rx, temp_dir) = setup_test_services().await;

        // Crear archivo para cuarentena
        let test_file = temp_dir.path().join("test_quarantine.txt");
        std::fs::write(&test_file, "Test file for quarantine").unwrap();

        // Poner en cuarentena
        let entry = services
            .quarantine_file(&test_file, "Prueba de cuarentena")
            .unwrap();

        // Verificar que el archivo ya no existe en su ubicación original
        assert!(!test_file.exists());

        // Verificar notificación
        let notification = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        match notification {
            CoreNotification::FileQuarantined { original_path, .. } => {
                assert_eq!(original_path, test_file.to_string_lossy().to_string());
            }
            _ => panic!("Notificación incorrecta"),
        }

        // Restaurar
        let restored_path = services
            .restore_from_quarantine(&entry.quarantine_name)
            .unwrap();
        assert_eq!(restored_path, test_file);
        assert!(test_file.exists());

        // Verificar notificación de restauración
        let notification = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
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
        let notification = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        match notification {
            CoreNotification::RealtimeProtectionStatus { enabled, .. } => {
                assert!(enabled);
            }
            _ => panic!("Notificación incorrecta"),
        }

        // Crear archivo malicioso en la carpeta monitoreada
        let malicious_file = temp_dir.path().join("realtime_test.txt");
        std::fs::write(&malicious_file, "This file contains MALWARE_TEST pattern").unwrap();

        // Esperar a que el monitor detecte el archivo
        let notification = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        match notification {
            CoreNotification::ThreatDetected { path, .. } => {
                assert_eq!(path, malicious_file.to_string_lossy().to_string());
            }
            _ => panic!("Notificación incorrecta"),
        }

        // Deshabilitar protección en tiempo real
        services.disable_realtime_protection().await.unwrap();

        // A filesystem can report several writes for the same path before stopping.
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(message) = rx.recv().await {
                if matches!(
                    message,
                    CoreNotification::RealtimeProtectionStatus { enabled: false, .. }
                ) {
                    return;
                }
            }
            panic!("Notification channel closed before the monitor stopped");
        })
        .await
        .unwrap();
    }
}
