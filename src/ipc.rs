use std::io::{Read, Write};
use std::time::Duration;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use named_pipe::PipeClient;
use thiserror::Error;
use chrono::{DateTime, Utc};

use crate::core_services::IntegratedScanResult;

const PIPE_NAME: &str = r"\\.\pipe\amaru-service";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("Error de conexión: {0}")]
    ConnectionError(#[from] std::io::Error),
    #[error("Error de serialización: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Timeout en la operación")]
    Timeout,
    #[error("Conexión cerrada por el servidor")]
    ConnectionClosed,
    #[error("Error del servicio: {0}")]
    ServiceError(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcCommand {
    GetStatus,
    StartScan { path: String },
    StopScan,
    GetScanProgress,
    UpdateRules,
    GetServiceStats,
    
    // Nuevos comandos para servicios core
    IntegratedScan { path: String },
    EnableIntegratedRealtime,
    DisableIntegratedRealtime,
    CheckUpdates,
    QuarantineFile { path: String, reason: String },
    RestoreFromQuarantine { entry_id: String },
    GetQuarantineList,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    Status {
        is_running: bool,
        uptime_secs: u64,
        files_monitored: usize,
        threats_detected: usize,
    },
    ScanProgress {
        files_scanned: usize,
        files_total: usize,
        current_file: String,
    },
    ServiceStats {
        cpu_usage: f32,
        memory_usage: u64,
        scan_queue_size: usize,
    },
    Error(String),
    Ok,
    
    // Nuevas respuestas para servicios core
    IntegratedScanResult(IntegratedScanResult),
    QuarantineList(Vec<QuarantineEntry>),
    UpdateStatus {
        available: bool,
        component: Option<String>,
        version: Option<String>,
        size: Option<u64>,
    },
    RealtimeStatus {
        enabled: bool,
        monitored_paths: Vec<String>,
    },
}

/// Entrada de cuarentena para IPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub reason: String,
    pub quarantine_date: DateTime<Utc>,
    pub file_size: u64,
    pub hash: String,
}

pub struct IpcClient {
    client: PipeClient,
    timeout: Duration,
}

impl IpcClient {
    pub fn connect() -> Result<Self, IpcError> {
        Self::connect_with_timeout(DEFAULT_TIMEOUT)
    }
    
    pub fn connect_with_timeout(timeout: Duration) -> Result<Self, IpcError> {
        let client = PipeClient::connect(PIPE_NAME)?;
        
        // Configurar timeout para operaciones de lectura/escritura
        client.set_read_timeout(Some(timeout))?;
        client.set_write_timeout(Some(timeout))?;
        
        Ok(Self { client, timeout })
    }
    
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), IpcError> {
        self.client.set_read_timeout(Some(timeout))?;
        self.client.set_write_timeout(Some(timeout))?;
        self.timeout = timeout;
        Ok(())
    }
    
    pub fn send_command(&mut self, command: IpcCommand) -> Result<IpcResponse, IpcError> {
        // Serializar comando
        let command_json = serde_json::to_string(&command)?;
        
        // Enviar comando
        self.client.write_all(command_json.as_bytes())
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::TimedOut => IpcError::Timeout,
                std::io::ErrorKind::BrokenPipe => IpcError::ConnectionClosed,
                _ => IpcError::ConnectionError(e),
            })?;
        
        // Leer respuesta
        let mut buffer = [0; 8192]; // Aumentado para respuestas más grandes
        let bytes_read = self.client.read(&mut buffer)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::TimedOut => IpcError::Timeout,
                std::io::ErrorKind::BrokenPipe => IpcError::ConnectionClosed,
                _ => IpcError::ConnectionError(e),
            })?;
        
        if bytes_read == 0 {
            return Err(IpcError::ConnectionClosed);
        }
        
        // Deserializar respuesta
        let response: IpcResponse = serde_json::from_slice(&buffer[..bytes_read])?;
        
        // Manejar errores del servicio
        match response {
            IpcResponse::Error(msg) => Err(IpcError::ServiceError(msg)),
            _ => Ok(response),
        }
    }
    
    pub fn get_status(&mut self) -> Result<IpcResponse, IpcError> {
        self.send_command(IpcCommand::GetStatus)
    }
    
    pub fn start_scan(&mut self, path: String) -> Result<IpcResponse, IpcError> {
        self.send_command(IpcCommand::StartScan { path })
    }
    
    pub fn stop_scan(&mut self) -> Result<IpcResponse, IpcError> {
        self.send_command(IpcCommand::StopScan)
    }
    
    pub fn get_scan_progress(&mut self) -> Result<IpcResponse, IpcError> {
        self.send_command(IpcCommand::GetScanProgress)
    }
    
    pub fn update_rules(&mut self) -> Result<IpcResponse, IpcError> {
        self.send_command(IpcCommand::UpdateRules)
    }
    
    pub fn get_service_stats(&mut self) -> Result<IpcResponse, IpcError> {
        self.send_command(IpcCommand::GetServiceStats)
    }
    
    // Nuevos métodos para los servicios core
    
    /// Realiza un análisis integrado de un archivo utilizando todos los servicios core
    pub fn integrated_scan(&mut self, path: String) -> Result<IntegratedScanResult, IpcError> {
        match self.send_command(IpcCommand::IntegratedScan { path })? {
            IpcResponse::IntegratedScanResult(result) => Ok(result),
            _ => Err(IpcError::ServiceError("Respuesta inesperada del servicio".to_string())),
        }
    }
    
    /// Habilita la protección en tiempo real integrada
    pub fn enable_integrated_realtime(&mut self) -> Result<bool, IpcError> {
        match self.send_command(IpcCommand::EnableIntegratedRealtime)? {
            IpcResponse::RealtimeStatus { enabled, .. } => Ok(enabled),
            _ => Err(IpcError::ServiceError("Respuesta inesperada del servicio".to_string())),
        }
    }
    
    /// Deshabilita la protección en tiempo real integrada
    pub fn disable_integrated_realtime(&mut self) -> Result<bool, IpcError> {
        match self.send_command(IpcCommand::DisableIntegratedRealtime)? {
            IpcResponse::RealtimeStatus { enabled, .. } => Ok(!enabled),
            _ => Err(IpcError::ServiceError("Respuesta inesperada del servicio".to_string())),
        }
    }
    
    /// Verifica si hay actualizaciones disponibles
    pub fn check_updates(&mut self) -> Result<(bool, Option<String>, Option<String>), IpcError> {
        match self.send_command(IpcCommand::CheckUpdates)? {
            IpcResponse::UpdateStatus { available, component, version, size } => {
                Ok((available, component, version))
            },
            _ => Err(IpcError::ServiceError("Respuesta inesperada del servicio".to_string())),
        }
    }
    
    /// Coloca un archivo en cuarentena
    pub fn quarantine_file(&mut self, path: String, reason: String) -> Result<(), IpcError> {
        match self.send_command(IpcCommand::QuarantineFile { path, reason })? {
            IpcResponse::Ok => Ok(()),
            _ => Err(IpcError::ServiceError("Respuesta inesperada del servicio".to_string())),
        }
    }
    
    /// Restaura un archivo de cuarentena
    pub fn restore_from_quarantine(&mut self, entry_id: String) -> Result<String, IpcError> {
        match self.send_command(IpcCommand::RestoreFromQuarantine { entry_id })? {
            IpcResponse::Ok => Ok("Archivo restaurado correctamente".to_string()),
            _ => Err(IpcError::ServiceError("Respuesta inesperada del servicio".to_string())),
        }
    }
    
    /// Obtiene la lista de archivos en cuarentena
    pub fn get_quarantine_list(&mut self) -> Result<Vec<QuarantineEntry>, IpcError> {
        match self.send_command(IpcCommand::GetQuarantineList)? {
            IpcResponse::QuarantineList(entries) => Ok(entries),
            _ => Err(IpcError::ServiceError("Respuesta inesperada del servicio".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_timeout() {
        let mut client = IpcClient::connect_with_timeout(Duration::from_millis(100))
            .expect("Failed to connect");
            
        // Simular timeout
        let result = client.get_status();
        assert!(matches!(result, Err(IpcError::Timeout)));
    }
    
    #[test]
    fn test_connection_closed() {
        let mut client = IpcClient::connect().expect("Failed to connect");
        
        // Simular cierre de conexión
        thread::sleep(Duration::from_millis(100));
        let result = client.get_status();
        assert!(matches!(result, Err(IpcError::ConnectionClosed)));
    }
} 