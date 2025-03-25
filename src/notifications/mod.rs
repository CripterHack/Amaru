use std::sync::Arc;
use tokio::sync::Mutex;
use windows_toast::{Toast, ToastManager, ToastDuration};
use serde::{Serialize, Deserialize};
use log::{debug, error, info, warn};
use chrono::{DateTime, Utc};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationPriority {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    ThreatDetected {
        path: String,
        threat_name: String,
        risk_level: u8,
    },
    SystemAlert {
        message: String,
        code: String,
    },
    UpdateAvailable {
        component: String,
        version: String,
    },
    ScanComplete {
        files_scanned: u64,
        threats_found: u64,
        duration_secs: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub notification_type: NotificationType,
    pub priority: NotificationPriority,
    pub acknowledged: bool,
}

pub struct NotificationManager {
    toast_manager: Arc<Mutex<ToastManager>>,
    log_path: PathBuf,
    notifications: Arc<Mutex<Vec<Notification>>>,
    max_history: usize,
}

impl NotificationManager {
    pub async fn new(app_name: &str, log_path: PathBuf, max_history: usize) -> Result<Self, Box<dyn std::error::Error>> {
        // Crear directorio de logs si no existe
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let toast_manager = ToastManager::new(app_name)?;
        
        Ok(Self {
            toast_manager: Arc::new(Mutex::new(toast_manager)),
            log_path,
            notifications: Arc::new(Mutex::new(Vec::new())),
            max_history,
        })
    }
    
    pub async fn notify(&self, notification_type: NotificationType, priority: NotificationPriority) -> Result<(), Box<dyn std::error::Error>> {
        let notification = Notification {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            notification_type: notification_type.clone(),
            priority: priority.clone(),
            acknowledged: false,
        };
        
        // Enviar notificación Windows Toast
        let toast_content = self.format_toast_content(&notification);
        let mut toast = Toast::new();
        toast.set_duration(match priority {
            NotificationPriority::Critical => ToastDuration::Long,
            _ => ToastDuration::Short,
        });
        
        match priority {
            NotificationPriority::Critical => {
                toast.set_title("⚠️ Alerta Crítica - Amaru Antivirus");
            },
            NotificationPriority::High => {
                toast.set_title("🚨 Alerta - Amaru Antivirus");
            },
            NotificationPriority::Medium => {
                toast.set_title("ℹ️ Notificación - Amaru Antivirus");
            },
            NotificationPriority::Low => {
                toast.set_title("📝 Información - Amaru Antivirus");
            },
        }
        
        toast.set_text(&toast_content);
        self.toast_manager.lock().await.show(&toast)?;
        
        // Guardar en historial
        {
            let mut notifications = self.notifications.lock().await;
            notifications.push(notification.clone());
            
            // Mantener límite de historial
            if notifications.len() > self.max_history {
                notifications.remove(0);
            }
        }
        
        // Registrar en log
        self.log_notification(&notification).await?;
        
        Ok(())
    }
    
    fn format_toast_content(&self, notification: &Notification) -> String {
        match &notification.notification_type {
            NotificationType::ThreatDetected { path, threat_name, risk_level } => {
                format!("¡Amenaza detectada!\nArchivo: {}\nTipo: {}\nNivel de riesgo: {}/100", 
                    path, threat_name, risk_level)
            },
            NotificationType::SystemAlert { message, code } => {
                format!("{}\nCódigo: {}", message, code)
            },
            NotificationType::UpdateAvailable { component, version } => {
                format!("Actualización disponible para {}\nVersión: {}", component, version)
            },
            NotificationType::ScanComplete { files_scanned, threats_found, duration_secs } => {
                format!("Escaneo completado\nArchivos analizados: {}\nAmenazas encontradas: {}\nDuración: {}s",
                    files_scanned, threats_found, duration_secs)
            },
        }
    }
    
    async fn log_notification(&self, notification: &Notification) -> Result<(), std::io::Error> {
        let log_entry = serde_json::to_string(&notification)?;
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
            
        writeln!(file, "{}", log_entry)?;
        Ok(())
    }
    
    pub async fn get_notifications(&self, limit: Option<usize>) -> Vec<Notification> {
        let notifications = self.notifications.lock().await;
        let limit = limit.unwrap_or(self.max_history);
        notifications.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
    
    pub async fn acknowledge_notification(&self, notification_id: &str) -> bool {
        let mut notifications = self.notifications.lock().await;
        if let Some(notification) = notifications.iter_mut().find(|n| n.id == notification_id) {
            notification.acknowledged = true;
            true
        } else {
            false
        }
    }
    
    pub async fn clear_acknowledged(&self) {
        let mut notifications = self.notifications.lock().await;
        notifications.retain(|n| !n.acknowledged);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::time::sleep;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_notification_manager() {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("notifications.log");
        
        let manager = NotificationManager::new(
            "AmaruTest",
            log_path.clone(),
            100
        ).await.unwrap();
        
        // Probar notificación de amenaza
        let threat_notification = NotificationType::ThreatDetected {
            path: "C:\\test.exe".to_string(),
            threat_name: "TestMalware".to_string(),
            risk_level: 85,
        };
        
        manager.notify(threat_notification, NotificationPriority::High).await.unwrap();
        
        // Verificar historial
        let notifications = manager.get_notifications(None).await;
        assert_eq!(notifications.len(), 1);
        
        // Verificar log
        let log_content = fs::read_to_string(&log_path).unwrap();
        assert!(log_content.contains("TestMalware"));
        
        // Probar reconocimiento
        let notification_id = notifications[0].id.clone();
        assert!(manager.acknowledge_notification(&notification_id).await);
        
        // Limpiar reconocidas
        manager.clear_acknowledged().await;
        assert_eq!(manager.get_notifications(None).await.len(), 0);
    }
    
    #[tokio::test]
    async fn test_notification_priority() {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().join("notifications.log");
        
        let manager = NotificationManager::new(
            "AmaruTest",
            log_path,
            100
        ).await.unwrap();
        
        // Probar diferentes prioridades
        let notifications = vec![
            (NotificationType::SystemAlert {
                message: "Test Critical".to_string(),
                code: "CRIT001".to_string(),
            }, NotificationPriority::Critical),
            (NotificationType::UpdateAvailable {
                component: "YARA".to_string(),
                version: "1.0.1".to_string(),
            }, NotificationPriority::Low),
        ];
        
        for (notification_type, priority) in notifications {
            manager.notify(notification_type, priority).await.unwrap();
            // Pequeña pausa para evitar solapamiento de notificaciones
            sleep(Duration::from_millis(500)).await;
        }
        
        let history = manager.get_notifications(None).await;
        assert_eq!(history.len(), 2);
    }
} 