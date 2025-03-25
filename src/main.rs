use clap::{Parser, Subcommand};
use std::path::PathBuf;
use log::{info, error, warn};
use std::time::Instant;
use std::process;
use std::fs;
use serde_json::json;
use chrono;
use rand;
use serde_json;
use md5;
use sha256;
use std::sync::Arc;
use windows_service::{
    service::{ServiceAccess, ServiceState},
    service_manager::{ServiceManager, ServiceManagerAccess}
};
use std::thread;

// Importar los módulos internos
use amaru_yara_engine::{YaraEngine, YaraConfig, ScanResult};
use amaru_yara_engine::heuristic::{HeuristicEngine, HeuristicConfig};
use amaru_radare2_analyzer::{Radare2Analyzer, Radare2Config};
use amaru_realtime_monitor::{RealtimeMonitor, MonitorConfig};

/// Amaru: Next Generation Antivirus
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan files or directories
    Scan {
        /// Path to scan
        #[arg(short, long)]
        path: PathBuf,
        
        /// Scan recursively
        #[arg(short, long, default_value_t = true)]
        recursive: bool,
        
        /// Use heuristic analysis
        #[arg(short = 'h', long, default_value_t = true)]
        heuristic: bool,
        
        /// Use Radare2 for static analysis
        #[arg(short = 'd', long, default_value_t = false)]
        radare2: bool,
    },
    
    /// Control real-time monitoring service
    Monitor {
        /// Action to perform with the service
        #[arg(short, long, value_enum)]
        action: MonitorAction,
    },
    
    /// Update virus signatures and YARA rules
    Update {
        /// Update YARA rules
        #[arg(short, long, default_value_t = false)]
        rules: bool,
        
        /// Update ClamAV database
        #[arg(short, long, default_value_t = false)]
        clamav: bool,
        
        /// Update heuristic patterns
        #[arg(short = 'h', long, default_value_t = false)]
        heuristic: bool,
    },
    
    /// Reload engine components
    Reload {
        /// Reload YARA rules
        #[arg(short, long, default_value_t = false)]
        rules: bool,
    },
    
    /// Analyze a file with advanced techniques
    Analyze {
        /// File to analyze
        #[arg(short, long)]
        file: PathBuf,
        
        /// Use Radare2
        #[arg(short, long, default_value_t = true)]
        radare2: bool,
        
        /// Use heuristic analysis
        #[arg(short = 'h', long, default_value_t = true)]
        heuristic: bool,
    },
    
    /// Start, stop or check service status
    Service {
        /// Service action
        #[arg(short, long, value_enum)]
        action: ServiceAction,
    },
    
    /// Configure autostart options
    Autostart {
        /// Enable or disable autostart
        #[arg(short, long)]
        enable: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum MonitorAction {
    Start,
    Stop,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ServiceAction {
    Install,
    Uninstall,
    Start,
    Stop,
    Restart,
    Status,
}

const SERVICE_NAME: &str = "AmaruAntivirus";
const DISPLAY_NAME: &str = "Amaru Antivirus Service";
const DESCRIPTION: &str = "Amaru Antivirus real-time protection service";

// Configura el allocator global para optimizar la gestión de memoria
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use amaru::{Amaru, AmaruConfig, AmaruError};
use log::{error, info, LevelFilter};
use std::env;
use std::path::Path;
use std::process;
use std::sync::Arc;
use tokio::runtime::Builder;
use parking_lot::RwLock;
use std::thread;
use rayon::ThreadPoolBuilder;
use sysinfo::{System, SystemExt};

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Configurar logging
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .init();
    
    info!("Iniciando Amaru Antivirus...");
    
    // Obtener ruta de configuración desde args o usar default
    let config_path = match env::args().nth(1) {
        Some(path) => path,
        None => "config.toml".to_string(),
    };

    // Configurar optimizaciones para rendimiento basado en sistema
    optimize_for_system();
    
    // Cargar configuración
    let config = match AmaruConfig::from_file(&config_path) {
        Ok(cfg) => Arc::new(RwLock::new(cfg)),
        Err(e) => {
            error!("Error al cargar configuración: {}", e);
            info!("Usando configuración por defecto");
            Arc::new(RwLock::new(AmaruConfig::default()))
        }
    };
    
    // Inicializar motor con configuración optimizada
    let amaru = match Amaru::new(config.clone()) {
        Ok(instance) => instance,
        Err(e) => {
            error!("Error al inicializar Amaru: {}", e);
            process::exit(1);
        }
    };
    
    // Inicializar y actualizar firmas YARA si es necesario
    if Path::new("signatures").exists() {
        if let Err(e) = amaru.update_yara_rules() {
            error!("Error al actualizar reglas YARA: {}", e);
        } else {
            info!("Reglas YARA actualizadas correctamente");
        }
    }
    
    // Inicializar motor heurístico si está configurado
    let config_read = config.read();
    if config_read.enable_heuristic_engine {
        if let Err(e) = amaru.init_heuristic_engine() {
            error!("Error al inicializar motor heurístico: {}", e);
        } else {
            info!("Motor heurístico inicializado correctamente");
        }
    }
    
    // Iniciar protección en tiempo real si está habilitada
    if config_read.enable_realtime_protection {
        match amaru.enable_realtime_protection() {
            Ok(_) => info!("Protección en tiempo real iniciada correctamente"),
            Err(e) => error!("Error al iniciar protección en tiempo real: {}", e),
        }
    }
    drop(config_read);
    
    // Continuar con la lógica principal de la aplicación...
    // ...
    
    Ok(())
}

/// Optimiza los parámetros del sistema basado en los recursos disponibles
fn optimize_for_system() {
    // Obtener información del sistema
    let mut system = System::new_all();
    system.refresh_all();
    
    // Configurar número óptimo de hilos para operaciones paralelas
    let available_cpus = num_cpus::get();
    let physical_cores = num_cpus::get_physical();
    
    // Usar 75% de cores físicos para análisis para no saturar el sistema
    let optimal_threads = std::cmp::max(1, (physical_cores as f32 * 0.75) as usize);
    
    // Configurar pool global de rayon
    ThreadPoolBuilder::new()
        .num_threads(optimal_threads)
        .thread_name(|i| format!("amaru-worker-{}", i))
        .build_global()
        .unwrap();
    
    // Ajustar prioridad del proceso para análisis en segundo plano
    #[cfg(target_os = "windows")]
    unsafe {
        use winapi::um::processthreadsapi::{GetCurrentProcess, SetPriorityClass};
        use winapi::um::winbase::PROCESS_MODE_BACKGROUND_BEGIN;
        
        // Comprobar si estamos en modo de bajo consumo
        if cfg!(feature = "low_power") {
            SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
        }
    }
    
    // Configurar reserva de memoria para caché si hay suficiente RAM disponible
    let total_memory = system.total_memory() / 1024 / 1024; // En MB
    if total_memory > 4096 {  // Si hay más de 4GB
        // Prealocar hasta 256MB para caché en sistemas con memoria suficiente
        mimalloc::set_option(mimalloc::Option::ReserveSize, 256 * 1024 * 1024);
    } else {
        // Sistemas con poca memoria: optimizar para consumo reducido
        mimalloc::set_option(mimalloc::Option::ReserveSize, 64 * 1024 * 1024);
    }
    
    info!("Sistema optimizado: {} hilos de análisis configurados", optimal_threads);
}

// Módulo para manejo de servicios de Windows
mod service {
    use super::*;
    use std::ffi::OsString;
    use windows_service::{
        service::{
            ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType,
            ServiceState, ServiceStatus, ServiceType,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    
    pub fn install_service(
        service_name: &str, 
        display_name: &str, 
        description: &str, 
        executable_path: &str
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
        let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
        
        let service_binary_path = OsString::from(format!("\"{}\" service", executable_path));
        
        let service_info = ServiceInfo {
            name: OsString::from(service_name),
            display_name: OsString::from(display_name),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: service_binary_path,
            launch_arguments: vec![],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        
        let service = service_manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
        service.set_description(description)?;
        
        Ok(())
    }
    
    pub fn uninstall_service(service_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let manager_access = ServiceManagerAccess::CONNECT;
        let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
        
        let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
        let service = service_manager.open_service(service_name, service_access)?;
        
        // Intentar detener el servicio si está en ejecución
        let status = service.query_status()?;
        if status.current_state != ServiceState::Stopped {
            service.stop()?;
            
            // Esperar a que se detenga
            let mut attempts = 0;
            while service.query_status()?.current_state != ServiceState::Stopped && attempts < 10 {
                thread::sleep(std::time::Duration::from_millis(500));
                attempts += 1;
            }
        }
        
        // Eliminar el servicio
        service.delete()?;
        
        Ok(())
    }
    
    pub fn start_service(service_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let manager_access = ServiceManagerAccess::CONNECT;
        let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
        
        let service = service_manager.open_service(service_name, ServiceAccess::START)?;
        service.start(&[])?;
        
        Ok(())
    }
    
    pub fn stop_service(service_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let manager_access = ServiceManagerAccess::CONNECT;
        let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
        
        let service = service_manager.open_service(service_name, ServiceAccess::STOP)?;
        service.stop()?;
        
        Ok(())
    }
    
    pub fn restart_service(service_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        stop_service(service_name)?;
        
        // Esperar un momento para asegurar que el servicio se detuvo
        thread::sleep(std::time::Duration::from_secs(2));
        
        start_service(service_name)?;
        
        Ok(())
    }
    
    pub fn get_service_status(service_name: &str) -> Result<ServiceState, Box<dyn std::error::Error>> {
        let manager_access = ServiceManagerAccess::CONNECT;
        let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
        
        let service = service_manager.open_service(service_name, ServiceAccess::QUERY_STATUS)?;
        let status = service.query_status()?;
        
        Ok(status.current_state)
    }
    
    pub fn set_autostart(service_name: &str, enable: bool) -> Result<(), Box<dyn std::error::Error>> {
        let manager_access = ServiceManagerAccess::CONNECT;
        let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
        
        let service = service_manager.open_service(service_name, ServiceAccess::CHANGE_CONFIG)?;
        
        let start_type = if enable {
            ServiceStartType::AutoStart
        } else {
            ServiceStartType::DemandStart
        };
        
        service.change_config(
            None,
            Some(start_type),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;
        
        Ok(())
    }
}

// Módulo para configuración del sistema
mod config {
    use std::io;
    use winreg::{enums::*, RegKey};
    
    // Configurar inicio automático en el registro de Windows
    pub fn set_registry_autostart(enable: bool) -> io::Result<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Run";
        let (key, _) = hkcu.create_subkey(path)?;
        
        let exe_path = std::env::current_exe()?;
        let exe_path_str = exe_path.to_string_lossy().to_string();
        
        if enable {
            key.set_value("AmaruAntivirus", &exe_path_str)?;
        } else {
            // Si existe la clave, eliminarla
            if key.get_value::<String, _>("AmaruAntivirus").is_ok() {
                key.delete_value("AmaruAntivirus")?;
            }
        }
        
        Ok(())
    }
    
    // Verificar si el inicio automático está habilitado
    pub fn is_autostart_enabled() -> io::Result<bool> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Run";
        
        if let Ok(key) = hkcu.open_subkey(path) {
            if let Ok(_) = key.get_value::<String, _>("AmaruAntivirus") {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
}

// Punto de entrada principal
#[tokio::main]
async fn main() {
    // Iniciar la aplicación con gestión de errores
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
