use clap::{Parser, Subcommand};
use std::io::{self, Write};
use tokio::sync::mpsc;

use amaru::{AmaruError, Config, CoreNotification, CoreServices};

#[derive(Parser)]
#[command(
    name = "Amaru Core Services",
    about = "Ejemplo de uso de los servicios core integrados de Amaru",
    version = "1.0.0"
)]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: std::path::PathBuf,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Escanear un archivo con todos los servicios core
    Scan {
        /// Ruta al archivo a escanear
        #[arg(required = true)]
        path: String,
    },
    /// Habilitar la protección en tiempo real integrada
    EnableRealtime,
    /// Deshabilitar la protección en tiempo real integrada
    DisableRealtime,
    /// Verificar actualizaciones disponibles
    CheckUpdates,
    /// Poner un archivo en cuarentena
    Quarantine {
        /// Ruta al archivo a poner en cuarentena
        #[arg(required = true)]
        path: String,
        /// Razón para la cuarentena
        #[arg(default_value = "Cuarentena manual")]
        reason: String,
    },
    /// Restaurar un archivo de cuarentena
    Restore {
        /// ID del archivo a restaurar
        #[arg(required = true)]
        entry_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), AmaruError> {
    // Configurar registro
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    let config = Config::load(cli.config)?;
    let (notif_tx, mut notif_rx) = mpsc::channel(100);
    let mut services = CoreServices::new(config, notif_tx)?;

    // Iniciar receptor de notificaciones en un hilo separado
    let notifications = tokio::spawn(async move {
        while let Some(notification) = notif_rx.recv().await {
            match notification {
                CoreNotification::ThreatDetected {
                    path,
                    threat_type,
                    confidence,
                    description,
                    ..
                } => {
                    println!("🔴 AMENAZA DETECTADA:");
                    println!("  - Archivo: {}", path);
                    println!("  - Tipo: {}", threat_type);
                    println!("  - Confianza: {}%", confidence);
                    println!("  - Descripción: {}", description);
                }
                CoreNotification::FileQuarantined {
                    original_path,
                    reason,
                    ..
                } => {
                    println!("🟠 ARCHIVO EN CUARENTENA:");
                    println!("  - Archivo: {}", original_path);
                    println!("  - Razón: {}", reason);
                }
                CoreNotification::FileRestored { original_path, .. } => {
                    println!("🟢 ARCHIVO RESTAURADO:");
                    println!("  - Archivo: {}", original_path);
                }
                CoreNotification::UpdateAvailable {
                    component,
                    version,
                    size,
                    ..
                } => {
                    println!("🔵 ACTUALIZACIÓN DISPONIBLE:");
                    println!("  - Componente: {}", component);
                    println!("  - Versión: {}", version);
                    if let Some(bytes) = size {
                        println!("  - Tamaño: {bytes} bytes");
                    }
                }
                CoreNotification::UpdateApplied {
                    component, version, ..
                } => {
                    println!("🟢 ACTUALIZACIÓN APLICADA:");
                    println!("  - Componente: {}", component);
                    println!("  - Versión: {}", version);
                }
                CoreNotification::RealtimeProtectionStatus {
                    enabled,
                    monitored_paths,
                    ..
                } => {
                    if enabled {
                        println!("🟢 PROTECCIÓN EN TIEMPO REAL ACTIVADA");
                        println!("  - Rutas monitoreadas: {}", monitored_paths.join(", "));
                    } else {
                        println!("🔴 PROTECCIÓN EN TIEMPO REAL DESACTIVADA");
                    }
                }
            }
        }
    });

    match cli.command {
        Some(Commands::Scan { path }) => {
            println!("Escaneando archivo: {}", path);

            // Realizar escaneo integrado
            let result = services.scan_file(&path).await?;

            println!("\nResultado del escaneo:");
            println!("Archivo: {}", result.path);
            println!("Confianza: {}%", result.confidence);
            println!("Tipo de amenaza: {}", result.threat_type);
            println!("Descripción: {}", result.description);
            println!("Tiempo de escaneo: {}ms", result.scan_time_ms);

            if !result.yara_matches.is_empty() {
                println!("\nCoincidencias YARA:");
                for (i, m) in result.yara_matches.iter().enumerate() {
                    println!("{}. Regla: {}", i + 1, m.rule_name);
                    if let Some(desc) = m.meta.get("description") {
                        println!("   Descripción: {}", desc);
                    }
                }
            }

            if let Some(ref heuristic) = result.heuristic_result {
                println!("\nResultado heurístico:");
                println!("Score: {}", heuristic.score);
                println!("Confianza: {:?}", heuristic.confidence);
                println!("Descripción: {}", heuristic.description);
            }

            if let Some(ref behaviors) = result.behaviors {
                println!("\nComportamientos detectados:");
                for (i, behavior) in behaviors.iter().enumerate() {
                    println!("{}. Tipo: {:?}", i + 1, behavior.behavior_type);
                    println!("   Confianza: {}%", behavior.confidence);
                    println!("   Descripción: {}", behavior.description);
                }
            }
        }
        Some(Commands::EnableRealtime) => {
            println!("Habilitando protección en tiempo real integrada...");
            let result = services.enable_realtime_protection().await?;
            if result {
                println!("✅ Protección en tiempo real habilitada correctamente.");
                println!("Presione Entrar para detener el monitor.");
                io::stdin().read_line(&mut String::new())?;
            } else {
                println!("ℹ️ La protección en tiempo real ya estaba habilitada.");
            }
        }
        Some(Commands::DisableRealtime) => {
            println!("Deshabilitando protección en tiempo real integrada...");
            let result = services.disable_realtime_protection().await?;
            if result {
                println!("✅ Protección en tiempo real deshabilitada correctamente.");
            } else {
                println!("ℹ️ La protección en tiempo real ya estaba deshabilitada.");
            }
        }
        Some(Commands::CheckUpdates) => {
            println!("Verificando actualizaciones disponibles...");
            let result = services.check_updates().await?;
            if result {
                println!("✅ Se ha encontrado una actualización.");
            } else {
                println!(
                    "ℹ️ Sin actualización disponible o sin clave de verificación configurada."
                );
            }
        }
        Some(Commands::Quarantine { path, reason }) => {
            println!("Poniendo en cuarentena el archivo: {}", path);
            println!("Razón: {}", reason);

            let entry = services.quarantine_file(&path, &reason)?;
            println!(
                "✅ Archivo en cuarentena. ID de restauración {}",
                entry.quarantine_name
            );
        }
        Some(Commands::Restore { entry_id }) => {
            println!("Restaurando archivo con ID: {}", entry_id);

            let path = services.restore_from_quarantine(&entry_id)?;
            println!("✅ Archivo restaurado a: {}", path.display());
        }
        None => {
            // Modo interactivo
            println!("Modo interactivo de Amaru Core Services. Escriba 'help' para ver los comandos disponibles.");

            loop {
                print!("> ");
                io::stdout().flush()?;

                let mut input = String::new();
                if io::stdin().read_line(&mut input)? == 0 {
                    break;
                }
                let input = input.trim();

                match input {
                    "help" => {
                        println!("Comandos disponibles:");
                        println!("  scan <ruta>            - Escanear un archivo con todos los servicios core");
                        println!("  enable-realtime        - Habilitar la protección en tiempo real integrada");
                        println!("  disable-realtime       - Deshabilitar la protección en tiempo real integrada");
                        println!(
                            "  check-updates          - Verificar actualizaciones disponibles"
                        );
                        println!("  quarantine <ruta>      - Poner un archivo en cuarentena");
                        println!("  restore <id>           - Restaurar un archivo de cuarentena");
                        println!("  exit                   - Salir del programa");
                    }
                    "exit" | "quit" => {
                        println!("Saliendo...");
                        break;
                    }
                    cmd if cmd.starts_with("scan ") => {
                        let path = cmd[5..].trim();
                        if path.is_empty() {
                            println!("❌ Error: Debe proporcionar una ruta al archivo.");
                            continue;
                        }

                        println!("Escaneando archivo: {}", path);

                        match services.scan_file(path).await {
                            Ok(result) => {
                                println!("\nResultado del escaneo:");
                                println!("Archivo: {}", result.path);
                                println!("Confianza: {}%", result.confidence);
                                println!("Tipo de amenaza: {}", result.threat_type);
                                println!("Descripción: {}", result.description);
                                println!("Tiempo de escaneo: {}ms", result.scan_time_ms);
                            }
                            Err(e) => {
                                println!("❌ Error al escanear: {}", e);
                            }
                        }
                    }
                    "enable-realtime" => {
                        println!("Habilitando protección en tiempo real integrada...");
                        match services.enable_realtime_protection().await {
                            Ok(result) => {
                                if result {
                                    println!(
                                        "✅ Protección en tiempo real habilitada correctamente."
                                    );
                                } else {
                                    println!(
                                        "ℹ️ La protección en tiempo real ya estaba habilitada."
                                    );
                                }
                            }
                            Err(e) => {
                                println!("❌ Error al habilitar la protección: {}", e);
                            }
                        }
                    }
                    "disable-realtime" => {
                        println!("Deshabilitando protección en tiempo real integrada...");
                        match services.disable_realtime_protection().await {
                            Ok(result) => {
                                if result {
                                    println!(
                                        "✅ Protección en tiempo real deshabilitada correctamente."
                                    );
                                } else {
                                    println!(
                                        "ℹ️ La protección en tiempo real ya estaba deshabilitada."
                                    );
                                }
                            }
                            Err(e) => {
                                println!("❌ Error al deshabilitar la protección: {}", e);
                            }
                        }
                    }
                    "check-updates" => {
                        println!("Verificando actualizaciones disponibles...");
                        match services.check_updates().await {
                            Ok(result) => {
                                if result {
                                    println!("✅ Se ha encontrado una actualización.");
                                } else {
                                    println!("ℹ️ Sin actualización disponible o sin clave de verificación configurada.");
                                }
                            }
                            Err(e) => {
                                println!("❌ Error al verificar actualizaciones: {}", e);
                            }
                        }
                    }
                    cmd if cmd.starts_with("quarantine ") => {
                        let parts: Vec<&str> = cmd[11..].trim().split(' ').collect();
                        if parts.is_empty() {
                            println!("❌ Error: Debe proporcionar una ruta al archivo.");
                            continue;
                        }

                        let path = parts[0];
                        let reason = if parts.len() > 1 {
                            parts[1..].join(" ")
                        } else {
                            "Cuarentena manual".to_string()
                        };

                        println!("Poniendo en cuarentena el archivo: {}", path);
                        println!("Razón: {}", reason);

                        match services.quarantine_file(path, &reason) {
                            Ok(entry) => {
                                println!(
                                    "✅ Archivo en cuarentena. ID de restauración {}",
                                    entry.quarantine_name
                                );
                            }
                            Err(e) => {
                                println!("❌ Error al poner en cuarentena: {}", e);
                            }
                        }
                    }
                    cmd if cmd.starts_with("restore ") => {
                        let entry_id = cmd[8..].trim();
                        if entry_id.is_empty() {
                            println!("❌ Error: Debe proporcionar un ID de archivo en cuarentena.");
                            continue;
                        }

                        println!("Restaurando archivo con ID: {}", entry_id);

                        match services.restore_from_quarantine(entry_id) {
                            Ok(path) => {
                                println!("✅ Archivo restaurado a: {}", path.display());
                            }
                            Err(e) => {
                                println!("❌ Error al restaurar: {}", e);
                            }
                        }
                    }
                    _ => {
                        println!("❌ Comando desconocido. Escriba 'help' para ver los comandos disponibles.");
                    }
                }
            }
        }
    }

    services.disable_realtime_protection().await?;
    drop(services);
    notifications
        .await
        .map_err(|e| AmaruError::Internal(e.to_string()))?;
    Ok(())
}
