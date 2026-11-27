use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{io, sync::mpsc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::core_services::IntegratedScanResult;

pub(crate) const PIPE_NAME: &str = r"\\.\pipe\amaru-service";
pub(crate) const STATUS_PIPE_NAME: &str = r"\\.\pipe\amaru-protection-status";
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
    GetRealtimeStatus,
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
    DeleteQuarantinedFile { entry_id: String },
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
        start_time: DateTime<Utc>,
        files_scanned: usize,
        files_total: usize,
        current_file: String,
    },
    ScanIdle,
    ScanFinished {
        files_scanned: usize,
        files_total: usize,
        files_failed: usize,
        files_skipped: usize,
        threats_detected: usize,
        quarantined: usize,
        cancelled: bool,
        last_error: Option<String>,
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

pub(crate) const MAX_COMMAND_BYTES: usize = 64 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

// The original protocol sends one JSON value at a time and waits for the response.
// Pipe reads have arbitrary boundaries, including in the middle of a UTF-8 sequence.
pub(crate) async fn read_json<T: DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> Result<T, IpcError> {
    let mut data = Vec::new();
    let mut buf = [0; 8192];
    loop {
        let count = stream.read(&mut buf).await?;
        if count == 0 {
            return Err(IpcError::ConnectionClosed);
        }
        if data.len() + count > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPC message exceeds size limit",
            )
            .into());
        }
        data.extend_from_slice(&buf[..count]);
        match serde_json::from_slice(&data) {
            Ok(value) => return Ok(value),
            Err(error) if error.is_eof() => {}
            Err(error) => return Err(error.into()),
        }
    }
}

async fn open_pipe(name: &str, timeout: Duration) -> Result<NamedPipeClient, IpcError> {
    tokio::time::timeout(timeout, async {
        loop {
            match ClientOptions::new()
                .write(name != STATUS_PIPE_NAME)
                .open(name)
            {
                Ok(client) => {
                    if name == PIPE_NAME || name == STATUS_PIPE_NAME {
                        verify_service_peer(&client)?;
                    }
                    return Ok(client);
                }
                Err(err) if err.raw_os_error() == Some(231) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(err) => return Err(err.into()),
            }
        }
    })
    .await
    .map_err(|_| IpcError::Timeout)?
}

/// Authenticated local users may read this one-byte snapshot without administrative rights.
pub async fn read_realtime_status() -> Result<bool, IpcError> {
    let mut pipe = open_pipe(STATUS_PIPE_NAME, DEFAULT_TIMEOUT).await?;
    match tokio::time::timeout(DEFAULT_TIMEOUT, pipe.read_u8())
        .await
        .map_err(|_| IpcError::Timeout)??
    {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid protection status").into()),
    }
}

fn verify_service_peer(pipe: &NamedPipeClient) -> Result<(), IpcError> {
    use std::os::windows::io::AsRawHandle;
    let mut pid = 0;
    let success = unsafe {
        winapi::um::winbase::GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &mut pid)
    };
    if success == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let status = crate::service::get_service_status()
        .map_err(|err| IpcError::ServiceError(err.to_string()))?;
    if status.process_id != Some(pid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Pipe does not belong to the registered Amaru service",
        )
        .into());
    }
    Ok(())
}

type Request = (
    IpcCommand,
    Duration,
    mpsc::Sender<Result<IpcResponse, IpcError>>,
);

pub struct IpcClient {
    requests: mpsc::Sender<Request>,
    timeout: Duration,
}

impl IpcClient {
    pub fn connect() -> Result<Self, IpcError> {
        Self::connect_with_timeout(DEFAULT_TIMEOUT)
    }

    pub fn connect_with_timeout(timeout: Duration) -> Result<Self, IpcError> {
        Self::connect_to(PIPE_NAME.to_owned(), timeout)
    }

    fn connect_to(name: String, timeout: Duration) -> Result<Self, IpcError> {
        let (connected, ready) = mpsc::channel();
        let (requests, receive) = mpsc::channel::<Request>();
        // Keep the synchronous public API usable both inside and outside Tokio.
        std::thread::Builder::new()
            .name("amaru-ipc-client".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        let _ = connected.send(Err(err.into()));
                        return;
                    }
                };
                let mut pipe = match runtime.block_on(open_pipe(&name, timeout)) {
                    Ok(pipe) => pipe,
                    Err(err) => {
                        let _ = connected.send(Err(err));
                        return;
                    }
                };
                if connected.send(Ok(())).is_err() {
                    return;
                }
                for (command, deadline, reply) in receive {
                    let result = runtime.block_on(async {
                        tokio::time::timeout(deadline, async {
                            let bytes = serde_json::to_vec(&command)?;
                            if bytes.len() > MAX_COMMAND_BYTES {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "IPC command too large",
                                )
                                .into());
                            }
                            pipe.write_all(&bytes).await?;
                            read_json(&mut pipe, MAX_RESPONSE_BYTES).await
                        })
                        .await
                        .unwrap_or(Err(IpcError::Timeout))
                    });
                    let broken = result.is_err();
                    let _ = reply.send(result);
                    // A timed-out or malformed frame cannot be reused for the next command.
                    if broken {
                        break;
                    }
                }
            })?;
        ready.recv().map_err(|_| IpcError::ConnectionClosed)??;
        Ok(Self { requests, timeout })
    }

    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), IpcError> {
        self.timeout = timeout;
        Ok(())
    }

    pub fn send_command(&mut self, command: IpcCommand) -> Result<IpcResponse, IpcError> {
        let (reply, response) = mpsc::channel();
        self.requests
            .send((command, self.timeout, reply))
            .map_err(|_| IpcError::ConnectionClosed)?;
        match response.recv().map_err(|_| IpcError::ConnectionClosed)?? {
            IpcResponse::Error(msg) => Err(IpcError::ServiceError(msg)),
            value => Ok(value),
        }
    }

    pub fn get_status(&mut self) -> Result<IpcResponse, IpcError> {
        self.send_command(IpcCommand::GetStatus)
    }

    pub fn start_scan(&mut self, path: String) -> Result<IpcResponse, IpcError> {
        self.send_command(IpcCommand::StartScan {
            path: std::path::absolute(path)?.to_string_lossy().into_owned(),
        })
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
        let path = std::path::absolute(path)?.to_string_lossy().into_owned();
        match self.send_command(IpcCommand::IntegratedScan { path })? {
            IpcResponse::IntegratedScanResult(result) => Ok(result),
            _ => Err(IpcError::ServiceError(
                "Respuesta inesperada del servicio".to_string(),
            )),
        }
    }

    /// Consulta estado y rutas de protección con permisos administrativos.
    pub fn get_realtime_status(&mut self) -> Result<(bool, Vec<String>), IpcError> {
        match self.send_command(IpcCommand::GetRealtimeStatus)? {
            IpcResponse::RealtimeStatus {
                enabled,
                monitored_paths,
            } => Ok((enabled, monitored_paths)),
            _ => Err(IpcError::ServiceError(
                "Unexpected realtime status response".into(),
            )),
        }
    }

    pub fn enable_integrated_realtime(&mut self) -> Result<bool, IpcError> {
        match self.send_command(IpcCommand::EnableIntegratedRealtime)? {
            IpcResponse::RealtimeStatus { enabled, .. } => Ok(enabled),
            _ => Err(IpcError::ServiceError(
                "Respuesta inesperada del servicio".to_string(),
            )),
        }
    }

    /// Deshabilita la protección en tiempo real integrada
    pub fn disable_integrated_realtime(&mut self) -> Result<bool, IpcError> {
        match self.send_command(IpcCommand::DisableIntegratedRealtime)? {
            IpcResponse::RealtimeStatus { enabled, .. } => Ok(!enabled),
            _ => Err(IpcError::ServiceError(
                "Respuesta inesperada del servicio".to_string(),
            )),
        }
    }

    /// Verifica si hay actualizaciones disponibles
    pub fn check_updates(&mut self) -> Result<(bool, Option<String>, Option<String>), IpcError> {
        match self.send_command(IpcCommand::CheckUpdates)? {
            IpcResponse::UpdateStatus {
                available,
                component,
                version,
                ..
            } => Ok((available, component, version)),
            _ => Err(IpcError::ServiceError(
                "Respuesta inesperada del servicio".to_string(),
            )),
        }
    }

    /// Coloca un archivo en cuarentena
    pub fn quarantine_file(&mut self, path: String, reason: String) -> Result<(), IpcError> {
        let path = std::path::absolute(path)?.to_string_lossy().into_owned();
        match self.send_command(IpcCommand::QuarantineFile { path, reason })? {
            IpcResponse::Ok => Ok(()),
            _ => Err(IpcError::ServiceError(
                "Respuesta inesperada del servicio".to_string(),
            )),
        }
    }

    /// Restaura un archivo de cuarentena
    pub fn restore_from_quarantine(&mut self, entry_id: String) -> Result<String, IpcError> {
        match self.send_command(IpcCommand::RestoreFromQuarantine { entry_id })? {
            IpcResponse::Ok => Ok("Archivo restaurado correctamente".to_string()),
            _ => Err(IpcError::ServiceError(
                "Respuesta inesperada del servicio".to_string(),
            )),
        }
    }

    pub fn delete_quarantined_file(&mut self, entry_id: String) -> Result<(), IpcError> {
        match self.send_command(IpcCommand::DeleteQuarantinedFile { entry_id })? {
            IpcResponse::Ok => Ok(()),
            _ => Err(IpcError::ServiceError(
                "Respuesta inesperada del servicio".into(),
            )),
        }
    }

    /// Obtiene la lista de archivos en cuarentena
    pub fn get_quarantine_list(&mut self) -> Result<Vec<QuarantineEntry>, IpcError> {
        match self.send_command(IpcCommand::GetQuarantineList)? {
            IpcResponse::QuarantineList(entries) => Ok(entries),
            _ => Err(IpcError::ServiceError(
                "Respuesta inesperada del servicio".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::windows::named_pipe::ServerOptions;

    // Both peers use their real Windows pipe implementations and the service stays untouched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fragmented_large_responses_and_reused_connections() {
        let name = format!(r"\\.\pipe\amaru-test-{}-large", std::process::id());
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let peer = tokio::spawn(async move {
            server.connect().await.unwrap();
            let long = "a".repeat(32000);
            for _ in 0..2 {
                assert!(matches!(
                    read_json::<IpcCommand>(&mut server, MAX_COMMAND_BYTES)
                        .await
                        .unwrap(),
                    IpcCommand::GetStatus
                ));
                let response = serde_json::to_vec(&IpcResponse::Error(long.clone())).unwrap();
                for chunk in response.chunks(407) {
                    server.write_all(chunk).await.unwrap();
                }
            }
        });
        tokio::task::spawn_blocking(move || {
            let mut client = IpcClient::connect_to(name, Duration::from_secs(5)).unwrap();
            for _ in 0..2 {
                assert!(matches!(client.get_status(), Err(IpcError::ServiceError(s)) if s.len() == 32000));
            }
        }).await.unwrap();
        peer.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_request_closes_the_connection() {
        let name = format!(r"\\.\pipe\amaru-test-{}-timeout", std::process::id());
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        tokio::task::spawn_blocking(move || {
            let mut client = IpcClient::connect_to(name, Duration::from_secs(2)).unwrap();
            client.set_timeout(Duration::from_millis(50)).unwrap();
            assert!(matches!(client.get_status(), Err(IpcError::Timeout)));
            assert!(matches!(
                client.get_status(),
                Err(IpcError::ConnectionClosed)
            ));
        })
        .await
        .unwrap();
        drop(server);
    }
}
