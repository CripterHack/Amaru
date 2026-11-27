mod cli;
mod eicar_self_test;

use amaru::{Amaru, Config};
use clap::Parser;
use cli::{Cli, Commands, MonitorAction, ServiceAction};
use log::{info, LevelFilter};
use rayon::ThreadPoolBuilder;
use std::{env, path::Path, process};
use sysinfo::{System, SystemExt};

fn control_service(action: ServiceAction) -> Result<(), Box<dyn std::error::Error>> {
    use amaru::service;
    match action {
        ServiceAction::Install => service::install_service()?,
        ServiceAction::Uninstall => service::uninstall_service()?,
        ServiceAction::Start => service::start_service()?,
        ServiceAction::Stop => service::stop_service()?,
        ServiceAction::Restart => service::restart_service()?,
        ServiceAction::Status => println!("{:?}", service::get_service_status()?.current_state),
    }
    Ok(())
}

fn default_config_path() -> std::path::PathBuf {
    env::current_exe()
        .ok()
        .map(|exe| exe.with_file_name("config.toml"))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| "config.toml".into())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder().filter_level(LevelFilter::Info).init();
    let args: Vec<_> = env::args_os().skip(1).collect();
    let config_path = match args.as_slice() {
        [] => default_config_path(),
        [path] if Path::new(path).extension().is_some_and(|ext| ext == "toml") => path.into(),
        _ => match Cli::parse().command {
            Commands::ServiceRun => return Ok(amaru::service::run_service()?),
            Commands::Service { action } => return control_service(action),
            Commands::Monitor { action } => {
                let action = match action {
                    MonitorAction::Start => ServiceAction::Start,
                    MonitorAction::Stop => ServiceAction::Stop,
                    MonitorAction::Status => ServiceAction::Status,
                };
                return control_service(action);
            }
            Commands::Autostart { enable } => return Ok(amaru::service::set_autostart(enable)?),
            Commands::TestEicar { config } => {
                let path = config.unwrap_or_else(default_config_path);
                return eicar_self_test::run(&path);
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "This command is awaiting integration with the Windows backend",
                )
                .into())
            }
        },
    };

    optimize_for_system()?;
    let mut config = Config::load(&config_path)?;
    config.yara_rules_path = config_path.with_file_name(config.yara_rules_path);
    let monitor = config.realtime_protection;
    let mut amaru = Amaru::new(config).await?;
    if monitor {
        amaru.enable_realtime_protection().await?;
        tokio::signal::ctrl_c().await?;
        amaru.disable_realtime_protection().await?;
    }
    Ok(())
}

/// Optimiza los parámetros del sistema basado en los recursos disponibles
fn optimize_for_system() -> Result<(), rayon::ThreadPoolBuildError> {
    // Obtener información del sistema
    let mut system = System::new_all();
    system.refresh_all();

    // Configurar número óptimo de hilos para operaciones paralelas
    let physical_cores = num_cpus::get_physical();

    // Usar 75% de cores físicos para análisis para no saturar el sistema
    let optimal_threads = std::cmp::max(1, (physical_cores as f32 * 0.75) as usize);

    // Configurar pool global de rayon
    ThreadPoolBuilder::new()
        .num_threads(optimal_threads)
        .thread_name(|i| format!("amaru-worker-{}", i))
        .build_global()?;

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
    let reserve_bytes = if total_memory > 4096 { 256 } else { 64 } * 1024 * 1024;
    let mut arena = 0;
    // A nonexclusive arena supplies allocations to the application's global mimalloc allocator.
    let status = unsafe {
        libmimalloc_sys::mi_reserve_os_memory_ex(reserve_bytes, false, false, false, &mut arena)
    };
    if status != 0 {
        log::warn!(
            "mimalloc could not reserve {} bytes (error {})",
            reserve_bytes,
            status
        );
    }

    info!(
        "Sistema optimizado: {} hilos de análisis configurados",
        optimal_threads
    );
    Ok(())
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
