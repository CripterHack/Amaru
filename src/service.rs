use std::{
    ffi::OsString,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
        RwLock,
    },
    time::Duration,
    path::PathBuf,
};
use log::{error, info, warn, debug};
use tokio::runtime::Runtime;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandler},
    service_dispatcher,
};
use named_pipe::{PipeServer, PipeClient};
use serde_json;
use std::sync::mpsc;
use crate::config::Config;
use amaru_realtime_monitor::{RealtimeMonitor, MonitorConfig, MonitorError, FileEvent, FileEventType, EventAction};
use amaru_yara_engine::{YaraEngine, YaraConfig, ScanResult};
use amaru_yara_engine::heuristic::{HeuristicEngine, HeuristicConfig};
use crate::{
    Amaru, AmaruError, Event,
    core_services::{CoreServices, CoreNotification, IntegratedScanResult},
    resource_manager::{ResourceManager, TaskType, SystemPriority}
};

const SERVICE_NAME: &str = "AmaruAntivirus";
const SERVICE_DISPLAY_NAME: &str = "Amaru Antivirus Real-time Protection";
const SERVICE_DESCRIPTION: &str = "Provides real-time protection against malware and suspicious activity";
const PIPE_NAME: &str = r"\\.\pipe\amaru-service";

/// Código de salida personalizado para el servicio cuando ocurre un error
const SERVICE_ERROR_EXIT_CODE: u32 = 1;

pub struct ServiceConfig {
    pub yara_rules_path: String,
    pub monitored_paths: Vec<String>,
    pub auto_quarantine: bool,
}

struct ServiceState {
    runtime: Runtime,
    exit_flag: Arc<AtomicBool>,
    config: ServiceConfig,
}

define_windows_service!(ffi_service_main, service_main);

pub fn run_service() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(arguments: Vec<OsString>) {
    info!("Iniciando servicio Amaru...");
    
    if let Err(e) = run_service_main(arguments) {
        error!("Error en el servicio: {}", e);
    }
}

fn run_service_main(arguments: Vec<OsString>) -> windows_service::Result<()> {
    let exit_flag = Arc::new(AtomicBool::new(false));
    let exit_flag_clone = exit_flag.clone();

    let event_handler = move |control_event| -> ServiceControlHandler::ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                info!("Recibida señal de detención");
                exit_flag_clone.store(true, Ordering::SeqCst);
                ServiceControlHandler::ServiceControlHandlerResult::NoError
            }
            ServiceControl::Pause => {
                info!("Servicio pausado");
                // Implementar lógica de pausa
                ServiceControlHandler::ServiceControlHandlerResult::NoError
            }
            ServiceControl::Continue => {
                info!("Servicio continuado");
                // Implementar lógica de continuación
                ServiceControlHandler::ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandler::ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandler::ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let runtime = Runtime::new().expect("Failed to create Tokio runtime");
    let exit_flag_clone = exit_flag.clone();

    // Iniciar servidor IPC
    runtime.block_on(async {
        let server = start_ipc_server(exit_flag_clone).await;
        if let Err(e) = server {
            error!("Error iniciando servidor IPC: {}", e);
        }
    });

    // Esperar señal de salida
    while !exit_flag.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

async fn start_ipc_server(exit_flag: Arc<AtomicBool>) -> std::io::Result<()> {
    let server = PipeServer::new(PIPE_NAME)?;
    
    while !exit_flag.load(Ordering::SeqCst) {
        let connection = server.connect()?;
        tokio::spawn(handle_client(connection));
    }
    
    Ok(())
}

async fn handle_client(mut connection: PipeServer) -> std::io::Result<()> {
    let mut buffer = [0; 4096];
    
    loop {
        let bytes_read = connection.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        let message = String::from_utf8_lossy(&buffer[..bytes_read]);
        let response = match serde_json::from_str::<IpcCommand>(&message) {
            Ok(command) => handle_command(command),
            Err(e) => IpcResponse::Error(format!("Error al parsear comando: {}", e)),
        };
        
        // Serializar y enviar respuesta
        let response_json = serde_json::to_string(&response)
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Error al serializar respuesta: {}", e)
            ))?;
            
        connection.write_all(response_json.as_bytes())?;
    }
    
    Ok(())
}

fn handle_command(command: IpcCommand) -> IpcResponse {
    match command {
        IpcCommand::GetStatus => {
            // Implementar obtención de estado real del servicio
            IpcResponse::Status {
                is_running: true,
                uptime_secs: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                files_monitored: 0, // TODO: Implementar contador real
                threats_detected: 0, // TODO: Implementar contador real
            }
        }
        IpcCommand::StartScan { path } => {
            info!("Iniciando escaneo de {}", path);
            // TODO: Implementar inicio de escaneo
            IpcResponse::Ok
        }
        IpcCommand::StopScan => {
            info!("Deteniendo escaneo");
            // TODO: Implementar detención de escaneo
            IpcResponse::Ok
        }
        IpcCommand::GetScanProgress => {
            // TODO: Implementar obtención de progreso real
            IpcResponse::ScanProgress {
                files_scanned: 0,
                files_total: 0,
                current_file: String::new(),
            }
        }
        IpcCommand::UpdateRules => {
            info!("Actualizando reglas YARA");
            // TODO: Implementar actualización de reglas
            IpcResponse::Ok
        }
        IpcCommand::GetServiceStats => {
            // TODO: Implementar obtención de estadísticas reales
            IpcResponse::ServiceStats {
                cpu_usage: 0.0,
                memory_usage: 0,
                scan_queue_size: 0,
            }
        }
    }
}

pub fn install_service() -> windows_service::Result<()> {
    use windows_service::{
        service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let service_binary_path = std::env::current_exe()
        .unwrap()
        .with_file_name("amaru-service.exe");

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description(SERVICE_DESCRIPTION)?;

    Ok(())
}

pub fn uninstall_service() -> windows_service::Result<()> {
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;

    Ok(())
}

pub fn start_service() -> windows_service::Result<()> {
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start(&[])?;

    Ok(())
}

pub fn stop_service() -> windows_service::Result<()> {
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
    service.stop()?;

    Ok(())
}

pub fn get_service_status() -> windows_service::Result<ServiceStatus> {
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)?;
    service.query_status()
}

/// Gestiona el servicio de Windows para protección en tiempo real
pub struct AmaruService {
    /// Canal para señalar el apagado del servicio
    shutdown_tx: mpsc::Sender<()>,
    /// Handle de estado del servicio
    status_handle: windows_service::service_control_handler::ServiceStatusHandle,
    /// Gestor de recursos para optimizar rendimiento
    resource_manager: Option<Arc<ResourceManager>>,
}

impl AmaruService {
    /// Ejecuta el servicio
    pub fn run(config_path: &str) -> windows_service::Result<()> {
        // Cargar configuración
        let config = match Config::load_from_file(config_path) {
            Ok(config) => config,
            Err(e) => {
                error!("Error al cargar configuración: {}", e);
                return Err(windows_service::Error::ServiceSpecificError(1));
            }
        };
        
        // Inicializar logging
        if let Err(e) = crate::logging::init_service_logger(&config.logs_path) {
            eprintln!("Error al inicializar el logger: {}", e);
        }
        
        info!("Iniciando servicio Amaru Antivirus");
        
        // Crear canales para el apagado
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        
        // Registrar handler de control de servicio
        let event_handler = move |control_event| -> windows_service::Result<ServiceControlHandlerResult> {
            match control_event {
                // Notificación de apagado
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    info!("Recibida solicitud de detener el servicio");
                    shutdown_tx.send(()).ok();
                    Ok(ServiceControlHandlerResult::NoError)
                }
                // Ignorar otros eventos
                _ => Ok(ServiceControlHandlerResult::NoError),
            }
        };
        
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
        
        // Actualizar estado a "iniciando"
        Self::update_service_status(
            &status_handle,
            ServiceState::StartPending,
            0,
        )?;
        
        // Crear e inicializar el gestor de recursos
        let resource_manager = Arc::new(ResourceManager::new(config.performance_config.clone()));
        
        // Aplicar prioridad del proceso según configuración
        if let Err(e) = resource_manager.apply_process_priority() {
            warn!("No se pudo establecer la prioridad del proceso: {}", e);
        }
        
        // Iniciar monitoreo de recursos en segundo plano
        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            resource_manager.start_monitoring().await;
        });
        
        // Configurar monitor en tiempo real
        let monitor_config = MonitorConfig {
            monitored_paths: config.monitored_paths.clone(),
            exclude_patterns: config.scan_config.exclude_paths.clone(),
            recursive: true,
            buffer_size: if config.performance_config.low_resource_mode { 1024 } else { 4096 },
            polling_interval_ms: if config.performance_config.low_resource_mode { 1000 } else { 250 },
        };
        
        // Inicializar motor YARA
        let yara_config = YaraConfig {
            rules_path: config.yara_rules_path.clone(),
            timeout_ms: 3000,
        };
        
        let yara_engine = match YaraEngine::new(yara_config) {
            Ok(engine) => Arc::new(engine),
            Err(err) => {
                error!("Error al inicializar motor YARA: {}", err);
                return Err(windows_service::Error::ServiceSpecificError(2));
            }
        };
        
        // Inicializar motor heurístico si está habilitado
        let heuristic_engine = if config.heuristic_analysis {
            match HeuristicEngine::new(HeuristicConfig {
                max_file_size: config.scan_config.max_file_size,
                min_detection_score: config.heuristic_threshold as f32,
                enable_behavioral_analysis: true,
                entropy_weight: 0.3,
                strings_weight: 0.25,
                imports_weight: 0.3,
                sections_weight: 0.15,
                ..HeuristicConfig::default()
            }) {
                Ok(engine) => Some(Arc::new(engine)),
                Err(err) => {
                    warn!("Error al inicializar motor heurístico: {}", err);
                    None
                }
            }
        } else {
            None
        };
        
        // Inicializar el monitor
        let mut monitor = match runtime.block_on(async { RealtimeMonitor::new(monitor_config).await })
        {
            Ok(monitor) => monitor,
            Err(err) => {
                error!("Error al inicializar monitor: {}", err);
                return Err(windows_service::Error::ServiceSpecificError(3));
            }
        };
        
        // Configurar callback optimizado del monitor usando el gestor de recursos
        let resource_manager_clone = resource_manager.clone();
        let yara_engine_clone = yara_engine.clone();
        let heuristic_engine_clone = heuristic_engine.clone();
        let config_clone = config.clone();
        
        monitor.set_event_callback(move |event: FileEvent| {
            // Ignorar eventos que no sean de creación o modificación
            match event.event_type {
                FileEventType::Created | FileEventType::Modified => {},
                _ => return EventAction::Continue,
            }
            
            // Verificar extensiones antes de proceder
            let file_path = match event.path.to_str() {
                Some(path) => path,
                None => return EventAction::Continue,
            };
            
            // Verificar si la extensión está en la lista de extensiones a escanear
            let extension = match std::path::Path::new(file_path).extension() {
                Some(ext) => ext.to_string_lossy().to_lowercase(),
                None => return EventAction::Continue,
            };
            
            if !config_clone.scan_config.scan_extensions.iter().any(|ext| ext == &extension) {
                return EventAction::Continue;
            }
            
            let yara_engine = yara_engine_clone.clone();
            let heuristic_engine = heuristic_engine_clone.clone();
            let file_path_clone = event.path.clone();
            let resource_manager = resource_manager_clone.clone();
            
            // Usar el gestor de recursos para procesar el evento con límites y prioridades
            tokio::spawn(async move {
                let scan_result = match resource_manager.execute(TaskType::Scan, move || {
                    yara_engine.scan_file(&file_path_clone)
                }).await {
                    Ok(result) => result,
                    Err(e) => {
                        warn!("Error al escanear archivo {}: {}", file_path_clone.display(), e);
                        return;
                    }
                };
                
                // Si hay coincidencias YARA, procesar
                if !scan_result.matches.is_empty() {
                    info!(
                        "Amenaza detectada en {}: {} coincidencias YARA",
                        file_path_clone.display(),
                        scan_result.matches.len()
                    );
                    
                    // Enviar notificación
                    Self::notify_threat_detected(
                        &file_path_clone, 
                        &scan_result, 
                        None, 
                        config_clone.auto_quarantine
                    );
                    
                    return;
                }
                
                // Si no hay coincidencias YARA y el análisis heurístico está habilitado, proceder
                if let Some(heuristic) = &heuristic_engine {
                    let h_result = match resource_manager.execute(TaskType::Analysis, move || {
                        heuristic.analyze_file(&file_path_clone)
                    }).await {
                        Ok(result) => result,
                        Err(e) => {
                            warn!("Error en análisis heurístico de {}: {}", file_path_clone.display(), e);
                            return;
                        }
                    };
                    
                    if let Some(result) = h_result {
                        if result.confidence > config_clone.heuristic_threshold as f32 {
                            info!(
                                "Amenaza detectada en {} mediante análisis heurístico (confianza: {:.1}%)",
                                file_path_clone.display(),
                                result.confidence * 100.0
                            );
                            
                            // Enviar notificación
                            Self::notify_threat_detected(
                                &file_path_clone, 
                                &scan_result, 
                                Some(&result), 
                                config_clone.auto_quarantine
                            );
                            
                            return;
                        }
                    }
                }
            });
            
            EventAction::Continue
        });
        
        // Actualizar estado a "ejecutando"
        Self::update_service_status(
            &status_handle,
            ServiceState::Running,
            0,
        )?;
        
        // Iniciar el monitor
        if let Err(e) = runtime.block_on(async { monitor.start().await }) {
            error!("Error al iniciar el monitor: {}", e);
            return Err(windows_service::Error::ServiceSpecificError(4));
        }
        
        info!("Servicio iniciado y monitor en tiempo real activo");
        
        // Iniciar servidor pipe para IPC
        let pipe_server = match PipeServer::new(PIPE_NAME) {
            Ok(server) => server,
            Err(e) => {
                error!("Error al crear servidor pipe: {}", e);
                return Err(windows_service::Error::ServiceSpecificError(5));
            }
        };
        
        // Limpiar tareas antiguas periódicamente
        let resource_manager_cleanup = resource_manager.clone();
        runtime.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                resource_manager_cleanup.cleanup_stale_tasks().await;
            }
        });
        
        // Programar tareas de mantenimiento
        runtime.block_on(async {
            resource_manager.schedule_periodic_task(
                TaskType::Integrity, 
                Duration::from_secs(3600), // Cada hora
                || {
                    info!("Ejecutando verificación de integridad programada");
                    // Aquí iría el código de verificación de integridad
                }
            ).await;
        });
        
        // Esperar señal de apagado
        drop(shutdown_rx.recv());
        
        // Detener el monitor
        if let Err(e) = runtime.block_on(async { monitor.stop().await }) {
            error!("Error al detener el monitor: {}", e);
        }
        
        // Detener el gestor de recursos
        resource_manager.shutdown();
        
        // Actualizar estado a "detenido"
        Self::update_service_status(
            &status_handle,
            ServiceState::Stopped,
            0,
        )?;
        
        info!("Servicio detenido correctamente");
        Ok(())
    }

    /// Notifica sobre la detección de una amenaza
    fn notify_threat_detected(path: &std::path::Path, yara_result: &ScanResult, heuristic_result: Option<&amaru_yara_engine::heuristic::HeuristicResult>, auto_quarantine: bool) {
        info!("Amenaza detectada en archivo: {}", path.display());
        
        // Implementar notificación
        
        // Si auto-cuarentena está habilitado, mover a cuarentena
        if auto_quarantine {
            info!("Moviendo archivo a cuarentena: {}", path.display());
            // Implementar cuarentena
        }
    }
    
    /// Actualiza el estado del servicio
    fn update_service_status(
        handle: &windows_service::service_control_handler::ServiceStatusHandle,
        state: ServiceState,
        exit_code: u32,
    ) -> windows_service::Result<()> {
        handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(exit_code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(0),
            process_id: None,
        })
    }
}

// Función intermediaria para la función principal del servicio
extern "system" fn ffi_service_main(_: u32, _: *mut *mut u16) {
    if let Err(e) = service_main() {
        error!("Error en el servicio: {}", e);
    }
}

// Función principal del servicio
fn service_main() -> Result<(), Box<dyn std::error::Error>> {
    // Crear canal para enviar señal de apagado
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    
    // Registrar handler de control
    let status_handle = service_control_handler::register(SERVICE_NAME, move |control_event| {
        match control_event {
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;
    
    // Crear instancia del servicio
    let service = AmaruService {
        shutdown_tx,
        status_handle,
    };
    
    // Actualizar estado a en proceso de inicio
    service.update_service_status(ServiceState::StartPending)?;
    
    // Ejecutar el servicio
    match service.run() {
        Ok(()) => {
            service.update_service_status(ServiceState::Stopped)?;
            Ok(())
        }
        Err(err) => {
            error!("Error en el servicio: {}", err);
            
            let failed_status = ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::ServiceSpecific(SERVICE_ERROR_EXIT_CODE),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            };
            
            status_handle.set_service_status(failed_status)?;
            Err(err)
        }
    }
}

/// Ejecuta el servicio de Amaru
pub fn run() -> windows_service::Result<()> {
    // Configurar registro
    configure_logging();
    
    // Cargar configuración
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            error!("Error al cargar la configuración: {}", e);
            return Err(windows_service::Error::ServiceSpecific(1));
        }
    };
    
    // Configurar runtime de Tokio
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Error al inicializar el runtime de Tokio: {}", e);
            return Err(windows_service::Error::ServiceSpecific(2));
        }
    };
    
    // Inicializar Amaru en el runtime
    let amaru = match runtime.block_on(async {
        let mut amaru = Amaru::new(config).await?;
        
        // Inicializar motores y servicios core
        amaru.init_heuristic_engine(None)?;
        amaru.init_core_services().await?;
        
        // Habilitar protección en tiempo real integrada si está configurada
        if amaru.config.realtime_protection_enabled {
            info!("Habilitando protección en tiempo real integrada...");
            match amaru.enable_integrated_realtime_protection().await {
                Ok(_) => info!("Protección en tiempo real integrada habilitada correctamente"),
                Err(e) => warn!("No se pudo habilitar la protección en tiempo real integrada: {}", e),
            }
        }
        
        Ok::<_, AmaruError>(amaru)
    }) {
        Ok(amaru) => amaru,
        Err(e) => {
            error!("Error al inicializar Amaru: {}", e);
            return Err(windows_service::Error::ServiceSpecific(3));
        }
    };
    
    // Crear objeto compartido para el servicio
    let service_context = Arc::new(ServiceContext {
        amaru: RwLock::new(amaru),
        status_handle: RwLock::new(None),
        shutdown_requested: AtomicBool::new(false),
        scan_in_progress: AtomicBool::new(false),
        runtime: Arc::new(runtime),
    });
    
    // Iniciar manejo del servicio
    service_dispatcher::start(SERVICE_NAME, move |control_events, status_handle| {
        run_service(control_events, status_handle, service_context.clone())
    })
}

/// Maneja los comandos recibidos a través del pipe nombrado
fn handle_command(service_context: &ServiceContext, command: &str) -> Result<String, AmaruError> {
    let parts: Vec<&str> = command.trim().split(' ').collect();
    if parts.is_empty() {
        return Ok("ERROR: Comando vacío".to_string());
    }
    
    match parts[0] {
        "STATUS" => {
            let amaru = service_context.amaru.read().unwrap();
            let status = service_context.runtime.block_on(amaru.get_service_state())?;
            
            // Serializar a JSON
            serde_json::to_string(&status)
                .map_err(|e| AmaruError::Internal(format!("Error al serializar estado: {}", e)))
        },
        "SCAN" => {
            if parts.len() < 2 {
                return Ok("ERROR: Falta la ruta a escanear".to_string());
            }
            
            let path = parts[1];
            
            if service_context.scan_in_progress.load(Ordering::SeqCst) {
                return Ok("ERROR: Ya hay un escaneo en progreso".to_string());
            }
            
            service_context.scan_in_progress.store(true, Ordering::SeqCst);
            
            // Iniciar escaneo en un nuevo hilo
            let service_context_clone = service_context.clone();
            service_context.runtime.spawn(async move {
                let scan_path = PathBuf::from(path);
                info!("Iniciando escaneo de: {}", scan_path.display());
                
                let result = {
                    let amaru = service_context_clone.amaru.read().unwrap();
                    amaru.integrated_scan_file(&scan_path).await
                };
                
                match result {
                    Ok(scan_result) => {
                        if scan_result.confidence >= 70 {
                            info!("¡Amenaza detectada! Tipo: {}, Confianza: {}%, Descripción: {}", 
                                scan_result.threat_type, scan_result.confidence, scan_result.description);
                            
                            // Si está configurado, poner en cuarentena automáticamente
                            let amaru = service_context_clone.amaru.read().unwrap();
                            if amaru.config.auto_quarantine && scan_result.confidence >= 85 {
                                match amaru.integrated_quarantine_file(&scan_path, &scan_result.description).await {
                                    Ok(_) => info!("Archivo puesto en cuarentena: {}", scan_path.display()),
                                    Err(e) => error!("Error al poner en cuarentena: {}", e),
                                }
                            }
                        } else {
                            info!("Archivo analizado sin amenazas críticas: {}", scan_path.display());
                        }
                    },
                    Err(e) => {
                        error!("Error al escanear archivo: {}", e);
                    }
                }
                
                service_context_clone.scan_in_progress.store(false, Ordering::SeqCst);
            });
            
            Ok("OK: Escaneo iniciado".to_string())
        },
        "STOP_SCAN" => {
            if !service_context.scan_in_progress.load(Ordering::SeqCst) {
                return Ok("ERROR: No hay un escaneo en progreso".to_string());
            }
            
            // Aquí solo marcamos que se ha solicitado detener, la lógica
            // real de detención debe implementarse en el loop de escaneo
            service_context.scan_in_progress.store(false, Ordering::SeqCst);
            
            Ok("OK: Deteniendo escaneo".to_string())
        },
        "UPDATE" => {
            // Iniciar actualización en un nuevo hilo
            let service_context_clone = service_context.clone();
            service_context.runtime.spawn(async move {
                let amaru = service_context_clone.amaru.read().unwrap();
                match amaru.check_core_updates().await {
                    Ok(true) => info!("Actualizaciones aplicadas correctamente"),
                    Ok(false) => info!("No hay actualizaciones disponibles o no se aplicaron automáticamente"),
                    Err(e) => error!("Error al verificar/aplicar actualizaciones: {}", e),
                }
            });
            
            Ok("OK: Verificación de actualizaciones iniciada".to_string())
        },
        "QUARANTINE" => {
            if parts.len() < 2 {
                return Ok("ERROR: Falta la ruta del archivo a poner en cuarentena".to_string());
            }
            
            let path = parts[1];
            let reason = if parts.len() > 2 { parts[2] } else { "Cuarentena manual" };
            
            // Ejecutar en el runtime de Tokio
            let result = service_context.runtime.block_on(async {
                let amaru = service_context.amaru.read().unwrap();
                amaru.integrated_quarantine_file(path, reason).await
            });
            
            match result {
                Ok(_) => Ok("OK: Archivo puesto en cuarentena".to_string()),
                Err(e) => Ok(format!("ERROR: {}", e)),
            }
        },
        "RESTORE" => {
            if parts.len() < 2 {
                return Ok("ERROR: Falta el ID del archivo a restaurar".to_string());
            }
            
            let entry_id = parts[1];
            
            // Ejecutar en el runtime de Tokio
            let result = service_context.runtime.block_on(async {
                let amaru = service_context.amaru.read().unwrap();
                amaru.integrated_restore_file(entry_id).await
            });
            
            match result {
                Ok(path) => Ok(format!("OK: Archivo restaurado a {}", path.display())),
                Err(e) => Ok(format!("ERROR: {}", e)),
            }
        },
        "ENABLE_REALTIME" => {
            // Ejecutar en el runtime de Tokio
            let result = service_context.runtime.block_on(async {
                let mut amaru = service_context.amaru.write().unwrap();
                amaru.enable_integrated_realtime_protection().await
            });
            
            match result {
                Ok(true) => Ok("OK: Protección en tiempo real habilitada".to_string()),
                Ok(false) => Ok("INFO: La protección en tiempo real ya estaba habilitada".to_string()),
                Err(e) => Ok(format!("ERROR: {}", e)),
            }
        },
        "DISABLE_REALTIME" => {
            // Ejecutar en el runtime de Tokio
            let result = service_context.runtime.block_on(async {
                let mut amaru = service_context.amaru.write().unwrap();
                amaru.disable_integrated_realtime_protection().await
            });
            
            match result {
                Ok(true) => Ok("OK: Protección en tiempo real deshabilitada".to_string()),
                Ok(false) => Ok("INFO: La protección en tiempo real ya estaba deshabilitada".to_string()),
                Err(e) => Ok(format!("ERROR: {}", e)),
            }
        },
        "STATS" => {
            // Obtener estadísticas del servicio
            let amaru = service_context.amaru.read().unwrap();
            let stats = service_context.runtime.block_on(amaru.get_service_stats())?;
            
            // Serializar a JSON
            serde_json::to_string(&stats)
                .map_err(|e| AmaruError::Internal(format!("Error al serializar estadísticas: {}", e)))
        },
        "INTEGRATED_SCAN" => {
            if parts.len() < 2 {
                return Ok("ERROR: Falta la ruta a escanear".to_string());
            }
            
            let path = parts[1];
            
            // Ejecutar análisis integrado y devolver resultado completo
            let result = service_context.runtime.block_on(async {
                let amaru = service_context.amaru.read().unwrap();
                amaru.integrated_scan_file(path).await
            });
            
            match result {
                Ok(scan_result) => {
                    // Devolver el resultado serializado
                    serde_json::to_string(&scan_result)
                        .map_err(|e| AmaruError::Internal(format!("Error al serializar resultado: {}", e)))
                },
                Err(e) => Ok(format!("ERROR: {}", e)),
            }
        },
        "CHECK_UPDATES" => {
            // Verificar actualizaciones y devolver el estado
            let result = service_context.runtime.block_on(async {
                let amaru = service_context.amaru.read().unwrap();
                amaru.check_core_updates().await
            });
            
            match result {
                Ok(true) => Ok(r#"{"status":"available"}"#.to_string()),
                Ok(false) => Ok(r#"{"status":"up-to-date"}"#.to_string()),
                Err(e) => Ok(format!("ERROR: {}", e)),
            }
        },
        "GET_QUARANTINE_LIST" => {
            // Obtener lista de archivos en cuarentena
            let result = service_context.runtime.block_on(async {
                let amaru = service_context.amaru.read().unwrap();
                // Aquí implementaremos una función para obtener la lista de cuarentena
                // Por ahora devolvemos un error
                Err::<Vec<crate::ipc::QuarantineEntry>, AmaruError>(AmaruError::Internal(
                    "Función no implementada".to_string()
                ))
            });
            
            match result {
                Ok(entries) => {
                    // Devolver la lista serializada
                    serde_json::to_string(&entries)
                        .map_err(|e| AmaruError::Internal(format!("Error al serializar lista de cuarentena: {}", e)))
                },
                Err(e) => Ok(format!("ERROR: {}", e)),
            }
        },
        _ => Ok(format!("ERROR: Comando desconocido: {}", parts[0])),
    }
} 