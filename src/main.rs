mod cli;
mod eicar_self_test;

use amaru::{Amaru, Config};
use clap::Parser;
use cli::{Cli, Commands};
#[cfg(windows)]
use cli::{MonitorAction, ServiceAction};
use log::{info, LevelFilter};
use rayon::ThreadPoolBuilder;
use std::{env, path::Path, process};
use sysinfo::{System, SystemExt};

#[cfg(windows)]
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

type CliResult = Result<(), Box<dyn std::error::Error>>;

fn load_config(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    let mut config = Config::load(path)?;
    config.yara_rules_path = path.with_file_name(config.yara_rules_path);
    config.quarantine_config.quarantine_path =
        path.with_file_name(config.quarantine_config.quarantine_path);
    Ok(config)
}

async fn scan(
    amaru: &Amaru,
    path: &Path,
    recursive: bool,
    heuristic: bool,
    radare2: bool,
    detailed: bool,
) -> CliResult {
    let metadata = std::fs::metadata(path)?;
    if detailed && !metadata.is_file() {
        return Err(format!("Expected a file to analyze: {}", path.display()).into());
    }
    let walk = walkdir::WalkDir::new(path).max_depth(if recursive { usize::MAX } else { 1 });
    let mut errors = 0;
    for entry in walk {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("{error}");
                errors += 1;
                continue;
            }
        };
        if !entry.file_type().is_file() && !(entry.depth() == 0 && metadata.is_file()) {
            continue;
        }
        match amaru
            .scan_file_with_options(entry.path(), heuristic, radare2)
            .await
        {
            Ok(result) => {
                let rules: Vec<_> = result
                    .yara_matches
                    .iter()
                    .map(|m| m.rule_name.as_str())
                    .collect();
                println!(
                    "{}  {:?}  {}",
                    result.path.display(),
                    result.risk_level,
                    rules.join(", ")
                );
                if detailed {
                    println!("SHA-256  {}", result.sha256);
                    if let Some(report) = result.static_analysis {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    }
                    if let Some(report) = result.heuristic_result {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    }
                    if let Some(report) = result.behaviors {
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    }
                }
            }
            Err(error) => {
                eprintln!("{}: {error}", entry.path().display());
                errors += 1;
            }
        }
    }
    if errors > 0 {
        return Err(format!("Scan incomplete: {errors} error(s)").into());
    }
    Ok(())
}

async fn update(config_path: &Path, rules: bool, clamav: bool, heuristic: bool) -> CliResult {
    if heuristic {
        return Err(
            "Heuristic patterns are compiled into Amaru and update with the application".into(),
        );
    }
    if rules || !clamav {
        let (tx, _rx) = tokio::sync::mpsc::channel(32);
        let services = amaru::CoreServices::new(load_config(config_path)?, tx)?;
        if services.update_rules().await? {
            println!("Signed YARA rule update applied.");
        } else {
            println!("YARA rules are current.");
        }
    }
    if clamav {
        let status = tokio::process::Command::new("freshclam")
            .status()
            .await
            .map_err(|err| format!("Could not start ClamAV freshclam: {err}"))?;
        if !status.success() {
            return Err(format!("freshclam failed ({status})").into());
        }
    }
    Ok(())
}

async fn execute(cli: Cli) -> CliResult {
    let config_path = cli.config.unwrap_or_else(default_config_path);
    match cli.command {
        Commands::Schedule(options) => {
            let desktop = env::current_exe()?.with_file_name("amaru-antivirus.exe");
            let schedule = if options.status {
                amaru::scheduler::read(&desktop)?
            } else if options.disable {
                amaru::scheduler::remove(&desktop)?
            } else {
                amaru::scheduler::set(&desktop, &options.schedule()?)?
            };
            println!("{}", serde_json::to_string(&schedule)?);
            Ok(())
        }
        Commands::TestEicar => eicar_self_test::run(&config_path),
        Commands::Scan {
            path,
            recursive,
            heuristic,
            radare2,
        } => {
            let amaru = Amaru::new(load_config(&config_path)?).await?;
            let heuristic = heuristic.unwrap_or(amaru.config().heuristic_analysis);
            scan(&amaru, &path, recursive, heuristic, radare2, false).await
        }
        Commands::Analyze {
            file,
            heuristic,
            radare2,
        } => {
            let amaru = Amaru::new(load_config(&config_path)?).await?;
            let heuristic = heuristic.unwrap_or(amaru.config().heuristic_analysis);
            scan(&amaru, &file, false, heuristic, radare2, true).await
        }
        Commands::Update {
            rules,
            clamav,
            heuristic,
        } => update(&config_path, rules, clamav, heuristic).await,
        Commands::Reload { rules } => {
            if !rules {
                return Err("Specify --rules to reload YARA signatures".into());
            }
            #[cfg(windows)]
            {
                let mut client = Amaru::create_ipc_client()?;
                client.update_rules()?;
                println!("The Windows service reloaded its YARA rules.");
                Ok(())
            }
            #[cfg(not(windows))]
            {
                Err("Reloading a running service requires Windows".into())
            }
        }
        #[cfg(windows)]
        Commands::ServiceRun => Ok(amaru::service::run_service()?),
        #[cfg(windows)]
        Commands::Service { action } => control_service(action),
        #[cfg(windows)]
        Commands::Monitor { action } => control_service(match action {
            MonitorAction::Start => ServiceAction::Start,
            MonitorAction::Stop => ServiceAction::Stop,
            MonitorAction::Status => ServiceAction::Status,
        }),
        #[cfg(windows)]
        Commands::Autostart { enable } => Ok(amaru::service::set_autostart(enable)?),
        #[cfg(not(windows))]
        Commands::ServiceRun
        | Commands::Service { .. }
        | Commands::Monitor { .. }
        | Commands::Autostart { .. } => Err("Service control and autostart require Windows".into()),
    }
}

async fn run() -> CliResult {
    env_logger::builder().filter_level(LevelFilter::Info).init();
    let args: Vec<_> = env::args_os().skip(1).collect();
    let path = match args.as_slice() {
        [] => default_config_path(),
        [path] if Path::new(path).extension().is_some_and(|ext| ext == "toml") => path.into(),
        _ => return execute(Cli::parse()).await,
    };
    optimize_for_system()?;
    let config = load_config(&path)?;
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

    #[cfg(feature = "optimize_memory")]
    {
        let memory_mib = system.total_memory() / (1024 * 1024);
        let reserve_bytes = if memory_mib > 4096 { 256 } else { 64 } * 1024 * 1024;
        let mut arena = Default::default();
        // The nonexclusive arena is available to the global allocator.
        let status = unsafe {
            libmimalloc_sys::mi_reserve_os_memory_ex(reserve_bytes, false, false, false, &mut arena)
        };
        if status != 0 {
            log::warn!("mimalloc could not reserve {reserve_bytes} bytes (error {status})");
        }
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
