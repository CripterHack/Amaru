use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// Evento de detección de amenaza
    ThreatDetected {
        /// Ruta del archivo
        path: PathBuf,
        /// Tipo de amenaza
        threat_type: ThreatType,
        /// Nivel de riesgo
        risk_level: RiskLevel,
        /// Detalles de la detección
        details: ThreatDetails,
        /// Timestamp
        timestamp: DateTime<Utc>,
    },
    
    /// Evento de archivo en cuarentena
    FileQuarantined {
        /// Ruta original del archivo
        original_path: PathBuf,
        /// Razón de la cuarentena
        reason: String,
        /// Timestamp
        timestamp: DateTime<Utc>,
    },
    
    /// Evento de archivo restaurado desde cuarentena
    FileRestored {
        /// Ruta original del archivo
        original_path: PathBuf,
        /// Timestamp
        timestamp: DateTime<Utc>,
    },
    
    /// Evento de actualización
    UpdateEvent {
        /// Tipo de actualización
        update_type: UpdateType,
        /// Estado de la actualización
        status: UpdateStatus,
        /// Detalles
        details: String,
        /// Timestamp
        timestamp: DateTime<Utc>,
    },
    
    /// Evento de error
    Error {
        /// Código de error
        code: ErrorCode,
        /// Mensaje de error
        message: String,
        /// Detalles adicionales
        details: Option<String>,
        /// Timestamp
        timestamp: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    /// Malware detectado por YARA
    YaraMatch {
        /// Nombre de la regla
        rule_name: String,
        /// Descripción de la regla
        description: Option<String>,
    },
    
    /// Comportamiento sospechoso detectado por análisis estático
    SuspiciousBehavior {
        /// Tipo de comportamiento
        behavior_type: String,
        /// Descripción del comportamiento
        description: String,
    },
    
    /// Archivo malicioso conocido (por hash)
    KnownMalware {
        /// Nombre del malware
        name: String,
        /// Familia del malware
        family: Option<String>,
    },
    
    /// Exploit potencial
    PotentialExploit {
        /// Tipo de exploit
        exploit_type: String,
        /// CVE relacionado
        cve: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetails {
    /// Hash del archivo (SHA-256)
    pub file_hash: String,
    
    /// Tamaño del archivo
    pub file_size: u64,
    
    /// Tipo de archivo
    pub file_type: String,
    
    /// Coincidencias encontradas
    pub matches: Vec<String>,
    
    /// Información adicional
    pub additional_info: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateType {
    /// Actualización de reglas YARA
    YaraRules,
    
    /// Actualización de firmas
    Signatures,
    
    /// Actualización del motor
    Engine,
    
    /// Actualización de la base de datos de malware
    MalwareDB,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateStatus {
    /// Iniciando actualización
    Starting,
    
    /// Descargando
    Downloading {
        /// Progreso (0-100)
        progress: u8,
        /// Bytes descargados
        downloaded: u64,
        /// Tamaño total
        total_size: u64,
    },
    
    /// Instalando
    Installing {
        /// Progreso (0-100)
        progress: u8,
    },
    
    /// Completado
    Completed {
        /// Nueva versión
        version: String,
    },
    
    /// Error
    Failed {
        /// Razón del error
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorCode {
    /// Error de E/S
    IO = 1,
    
    /// Error de configuración
    Config = 2,
    
    /// Error de YARA
    Yara = 3,
    
    /// Error de análisis
    Analysis = 4,
    
    /// Error de cuarentena
    Quarantine = 5,
    
    /// Error de actualización
    Update = 6,
    
    /// Error de red
    Network = 7,
    
    /// Error interno
    Internal = 8,
}

/// Canal de eventos para comunicación entre componentes
pub struct EventChannel {
    sender: crossbeam_channel::Sender<Event>,
    receiver: crossbeam_channel::Receiver<Event>,
}

impl EventChannel {
    /// Crear un nuevo canal de eventos
    pub fn new() -> Self {
        let (sender, receiver) = crossbeam_channel::unbounded();
        Self { sender, receiver }
    }
    
    /// Obtener un clon del sender
    pub fn sender(&self) -> crossbeam_channel::Sender<Event> {
        self.sender.clone()
    }
    
    /// Obtener un clon del receiver
    pub fn receiver(&self) -> crossbeam_channel::Receiver<Event> {
        self.receiver.clone()
    }
}

impl Default for EventChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_event_channel() {
        let channel = EventChannel::new();
        let sender = channel.sender();
        let receiver = channel.receiver();
        
        // Enviar evento
        let event = Event::ThreatDetected {
            path: PathBuf::from("test.exe"),
            threat_type: ThreatType::YaraMatch {
                rule_name: "test_rule".to_string(),
                description: Some("Test description".to_string()),
            },
            risk_level: RiskLevel::High,
            details: ThreatDetails {
                file_hash: "test_hash".to_string(),
                file_size: 1024,
                file_type: "PE32".to_string(),
                matches: vec!["match1".to_string()],
                additional_info: None,
            },
            timestamp: Utc::now(),
        };
        
        sender.send(event.clone()).unwrap();
        
        // Recibir evento
        let received = receiver.recv().unwrap();
        
        match (event, received) {
            (
                Event::ThreatDetected { path: p1, threat_type: t1, risk_level: r1, .. },
                Event::ThreatDetected { path: p2, threat_type: t2, risk_level: r2, .. }
            ) => {
                assert_eq!(p1, p2);
                assert_eq!(r1, r2);
                match (t1, t2) {
                    (
                        ThreatType::YaraMatch { rule_name: n1, .. },
                        ThreatType::YaraMatch { rule_name: n2, .. }
                    ) => {
                        assert_eq!(n1, n2);
                    }
                    _ => panic!("Wrong threat type"),
                }
            }
            _ => panic!("Wrong event type"),
        }
    }
    
    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
        
        let mut levels = vec![
            RiskLevel::Critical,
            RiskLevel::Low,
            RiskLevel::High,
            RiskLevel::Medium,
        ];
        levels.sort();
        
        assert_eq!(levels, vec![
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ]);
    }
} 