use std::sync::Arc;
use tokio::sync::Mutex;
use log::{debug, error, info, warn};
use crate::events::EventHandler;
use crate::yara_engine::YaraEngine;
use crate::radare2_analyzer::Radare2Analyzer;
use crate::realtime_monitor::RealtimeMonitor;

pub struct SystemCoordinator {
    event_handler: Arc<EventHandler>,
    yara_engine: Arc<Mutex<YaraEngine>>,
    radare2_analyzer: Arc<Mutex<Radare2Analyzer>>,
    realtime_monitor: Arc<Mutex<RealtimeMonitor>>,
}

impl SystemCoordinator {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let event_handler = Arc::new(EventHandler::new());
        
        // Initialize components with event handler
        let yara_engine = Arc::new(Mutex::new(YaraEngine::new(event_handler.get_sender())?));
        let radare2_analyzer = Arc::new(Mutex::new(Radare2Analyzer::new(
            Radare2Config {
                event_sender: Some(event_handler.get_sender()),
                ..Default::default()
            }
        )?));
        let realtime_monitor = Arc::new(Mutex::new(RealtimeMonitor::new(event_handler.get_sender())?));
        
        Ok(Self {
            event_handler,
            yara_engine,
            radare2_analyzer,
            realtime_monitor,
        })
    }
    
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Iniciando coordinador del sistema...");
        
        // Start realtime monitoring
        let monitor = self.realtime_monitor.clone();
        tokio::spawn(async move {
            if let Err(e) = monitor.lock().await.start().await {
                error!("Error en monitor en tiempo real: {}", e);
            }
        });
        
        // Start event processing
        let event_handler = self.event_handler.clone();
        let yara_engine = self.yara_engine.clone();
        let radare2_analyzer = self.radare2_analyzer.clone();
        
        tokio::spawn(async move {
            while let Ok(event) = event_handler.get_receiver().recv() {
                match event {
                    AnalyzerEvent::FileDetected { path } => {
                        debug!("Archivo detectado: {}", path);
                        
                        // YARA scan
                        if let Ok(mut engine) = yara_engine.lock().await {
                            if let Err(e) = engine.scan_file(&path).await {
                                error!("Error en escaneo YARA: {}", e);
                            }
                        }
                        
                        // Radare2 analysis
                        if let Ok(mut analyzer) = radare2_analyzer.lock().await {
                            if let Err(e) = analyzer.analyze_file(&path).await {
                                error!("Error en análisis Radare2: {}", e);
                            }
                        }
                    },
                    AnalyzerEvent::ThreatDetected { .. } => {
                        info!("Amenaza detectada, notificando...");
                        // Implementar notificaciones
                    },
                    _ => {}
                }
            }
        });
        
        info!("Coordinador del sistema iniciado correctamente");
        Ok(())
    }
    
    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Deteniendo coordinador del sistema...");
        
        // Stop realtime monitoring
        if let Ok(mut monitor) = self.realtime_monitor.lock().await {
            monitor.stop().await?;
        }
        
        info!("Coordinador del sistema detenido correctamente");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs::File;
    use std::io::Write;
    
    #[tokio::test]
    async fn test_coordinator_initialization() {
        let coordinator = SystemCoordinator::new().await;
        assert!(coordinator.is_ok(), "El coordinador debería inicializarse correctamente");
    }
    
    #[tokio::test]
    async fn test_coordinator_file_detection() {
        let coordinator = SystemCoordinator::new().await.unwrap();
        
        // Create test file
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.exe");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"Test file content").unwrap();
        
        // Start coordinator
        coordinator.start().await.unwrap();
        
        // Simulate file detection
        let event_sender = coordinator.event_handler.get_sender();
        event_sender.send(AnalyzerEvent::FileDetected {
            path: file_path.to_string_lossy().to_string(),
        }).unwrap();
        
        // Wait for processing
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        
        // Stop coordinator
        coordinator.stop().await.unwrap();
    }
} 