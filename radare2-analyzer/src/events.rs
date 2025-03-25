use std::sync::mpsc::{channel, Sender, Receiver};
use serde::{Serialize, Deserialize};
use crate::{AnalysisResult, DetectedBehavior, ThreatCategory};

/// Tipos de eventos del analizador
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnalyzerEvent {
    /// Análisis iniciado
    AnalysisStarted {
        file_path: String,
    },
    
    /// Comportamiento sospechoso detectado
    BehaviorDetected {
        file_path: String,
        behavior: DetectedBehavior,
    },
    
    /// Amenaza identificada
    ThreatDetected {
        file_path: String,
        category: ThreatCategory,
        risk_score: u8,
    },
    
    /// Análisis completado
    AnalysisCompleted {
        file_path: String,
        result: AnalysisResult,
    },
    
    /// Error durante el análisis
    AnalysisError {
        file_path: String,
        error: String,
    },
}

/// Manejador de eventos del analizador
pub struct EventHandler {
    sender: Sender<AnalyzerEvent>,
    receiver: Receiver<AnalyzerEvent>,
}

impl EventHandler {
    /// Crear un nuevo manejador de eventos
    pub fn new() -> Self {
        let (sender, receiver) = channel();
        Self { sender, receiver }
    }
    
    /// Obtener un clon del sender
    pub fn get_sender(&self) -> Sender<AnalyzerEvent> {
        self.sender.clone()
    }
    
    /// Obtener una referencia al receiver
    pub fn get_receiver(&self) -> &Receiver<AnalyzerEvent> {
        &self.receiver
    }
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    
    #[test]
    fn test_event_handler() {
        let handler = EventHandler::new();
        let sender = handler.get_sender();
        
        // Enviar evento en otro hilo
        thread::spawn(move || {
            sender.send(AnalyzerEvent::AnalysisStarted {
                file_path: "test.exe".to_string(),
            }).unwrap();
        });
        
        // Esperar y recibir evento
        thread::sleep(Duration::from_millis(100));
        if let Ok(event) = handler.get_receiver().try_recv() {
            match event {
                AnalyzerEvent::AnalysisStarted { file_path } => {
                    assert_eq!(file_path, "test.exe");
                },
                _ => panic!("Evento inesperado"),
            }
        } else {
            panic!("No se recibió el evento");
        }
    }
    
    #[test]
    fn test_multiple_events() {
        let handler = EventHandler::new();
        let sender = handler.get_sender();
        
        // Enviar múltiples eventos
        let events = vec![
            AnalyzerEvent::AnalysisStarted {
                file_path: "test1.exe".to_string(),
            },
            AnalyzerEvent::ThreatDetected {
                file_path: "test1.exe".to_string(),
                category: ThreatCategory::Trojan,
                risk_score: 85,
            },
            AnalyzerEvent::AnalysisCompleted {
                file_path: "test1.exe".to_string(),
                result: AnalysisResult {
                    path: std::path::PathBuf::from("test1.exe"),
                    md5: Some("test".to_string()),
                    sha256: Some("test".to_string()),
                    file_type: Some("PE32".to_string()),
                    size: Some(1024),
                    sections: vec![],
                    imports: vec![],
                    suspicious_strings: vec![],
                    risk_score: 85,
                    analysis_time_ms: 100,
                    behaviors: vec![],
                    threat_category: Some(ThreatCategory::Trojan),
                },
            },
        ];
        
        for event in events {
            sender.send(event).unwrap();
        }
        
        // Verificar recepción de eventos
        let mut received = 0;
        while let Ok(_) = handler.get_receiver().try_recv() {
            received += 1;
        }
        
        assert_eq!(received, 3, "No se recibieron todos los eventos");
    }
} 