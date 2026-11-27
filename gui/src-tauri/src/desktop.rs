#[path = "preferences.rs"]
mod preferences;
use crate::session::{self, Job, Progress, Record};
use amaru::{Amaru, Config};
pub(crate) use preferences::run_scheduled;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use sysinfo::{CpuExt, System, SystemExt};
use tauri::{command, Manager, State, Window};

struct Desktop {
    engine: Result<Amaru, String>,
    data: PathBuf,
    active: Mutex<Option<Job>>,
    system: Mutex<System>,
}
impl Desktop {
    fn engine(&self) -> Result<&Amaru, String> {
        self.engine.as_ref().map_err(Clone::clone)
    }
}

async fn load_engine(install: &Path, data: &Path) -> Result<Amaru, String> {
    let mut config = Config::load(install.join("config.toml"))
        .map_err(|e| format!("Cannot load config.toml: {e}"))?;
    config.yara_rules_path = install.join(config.yara_rules_path);
    if config.quarantine_config.quarantine_path.is_relative() {
        config.quarantine_config.quarantine_path =
            data.join(&config.quarantine_config.quarantine_path);
    }
    Amaru::new(config).await.map_err(|e| e.to_string())
}

#[command]
async fn get_protection_status() -> Result<Value, String> {
    let enabled = amaru::ipc::read_realtime_status()
        .await
        .map_err(|e| format!("Windows service unavailable: {e}"))?;
    Ok(
        json!({"enabled":enabled, "monitored_paths":[], "scanning_enabled":enabled,
        "last_updated":null, "version":env!("CARGO_PKG_VERSION")}),
    )
}

#[command]
async fn toggle_protection(enable: bool, window: Window) -> Result<(), String> {
    let status = tauri::async_runtime::spawn_blocking(move || {
        let mut client = Amaru::create_ipc_client().map_err(|e| e.to_string())?;
        let applied = if enable {
            client.enable_integrated_realtime()
        } else {
            client.disable_integrated_realtime()
        }
        .map_err(|e| e.to_string())?;
        if !applied {
            return Err("Service did not apply protection change".to_owned());
        }
        client.get_realtime_status().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    window
        .emit(
            "protection-status-changed",
            json!({"enabled":status.0,"monitoredPaths":status.1}),
        )
        .map_err(|e| e.to_string())
}

#[command]
async fn toggle_protection_feature(
    feature_id: String,
    enable: bool,
    window: Window,
) -> Result<(), String> {
    if feature_id == "realtime" {
        toggle_protection(enable, window).await
    } else {
        Err(format!(
            "The installed service has no control for {feature_id}"
        ))
    }
}

#[command]
fn get_scan_progress(state: State<'_, Arc<Desktop>>) -> Option<Progress> {
    state
        .active
        .lock()
        .unwrap()
        .as_ref()
        .map(|job| job.progress.clone())
}

#[command]
fn cancel_scan(state: State<'_, Arc<Desktop>>) -> Result<(), String> {
    let active = state.active.lock().unwrap();
    active
        .as_ref()
        .ok_or("No scan in progress")?
        .cancel
        .store(true, Ordering::Release);
    Ok(())
}

fn start(
    window: Window,
    state: Arc<Desktop>,
    kind: &str,
    roots: Vec<PathBuf>,
) -> Result<(), String> {
    let engine = state.engine()?.clone();
    if roots.is_empty() {
        return Err("No scan paths are available".into());
    }
    let job = Job::new();
    let id = job.progress.id;
    let cancel = job.cancel.clone();
    {
        let mut active = state.active.lock().unwrap();
        if active.is_some() {
            return Err("A scan is already in progress".into());
        }
        *active = Some(job);
    }
    let kind = kind.to_owned();
    tauri::async_runtime::spawn(async move {
        let record = session::run(
            &engine,
            id,
            kind,
            roots,
            &state.data,
            &cancel,
            |progress| {
                if let Some(job) = state.active.lock().unwrap().as_mut() {
                    job.progress = progress.clone();
                }
                let _ = window.emit("scan-progress", progress);
            },
            |threat| {
                let _ = window.emit("threat-detected", threat);
            },
        )
        .await;
        let saved = session::save(&state.data.join("history"), &record);
        let mut active = state.active.lock().unwrap();
        *active = None;
        if let Err(error) = saved {
            let _ = window.emit("scan-error", format!("History save failed: {error}"));
        }
        let _ = window.emit("scan-completed", record);
    });
    Ok(())
}

#[command]
fn start_quick_scan(window: Window, state: State<'_, Arc<Desktop>>) -> Result<(), String> {
    let paths = preferences::quick_paths(&state.data)?;
    start(window, state.inner().clone(), "quick", paths)
}
#[command]
fn start_full_scan(window: Window, state: State<'_, Arc<Desktop>>) -> Result<(), String> {
    let system_drive = std::env::var("SystemDrive").map_err(|e| e.to_string())?;
    start(
        window,
        state.inner().clone(),
        "full",
        vec![PathBuf::from(format!("{system_drive}\\"))],
    )
}
#[command]
fn start_custom_scan(
    path: PathBuf,
    window: Window,
    state: State<'_, Arc<Desktop>>,
) -> Result<(), String> {
    if !path.is_absolute() || !path.exists() {
        return Err("Choose an existing absolute path".into());
    }
    start(window, state.inner().clone(), "custom", vec![path])
}
#[command]
fn get_scan_history(state: State<'_, Arc<Desktop>>) -> Result<Vec<Record>, String> {
    session::history(&state.data.join("history")).map_err(|e| e.to_string())
}
#[command]
fn get_activity_log(state: State<'_, Arc<Desktop>>) -> Result<Vec<Value>, String> {
    Ok(get_scan_history(state)?.into_iter().take(20).map(|r| json!({"id":r.id,"type":"scan",
        "message":format!("{} scan {} ({} files, {} findings)",r.scan_type,r.status,r.files_scanned,r.threats_found),
        "date":r.completed_at,"status":if r.status=="completed" {"success"} else {"warning"}})).collect())
}
#[command]
fn get_threat_statistics(state: State<'_, Arc<Desktop>>) -> Result<Value, String> {
    let quarantine = state
        .engine()?
        .quarantine()
        .list_entries()
        .map_err(|e| e.to_string())?;
    let quarantined = quarantine.len();
    let isolated: std::collections::HashSet<_> = quarantine
        .into_iter()
        .map(|entry| (entry.original_path, entry.original_hash))
        .collect();
    let records = get_scan_history(state)?;
    let mut recent = Vec::new();
    let mut by_type = std::collections::BTreeMap::<String, u64>::new();
    let mut by_month = std::collections::BTreeMap::<String, u64>::new();
    let mut total = 0;
    for record in records {
        for mut threat in record.detected_threats.into_iter().rev() {
            threat.in_quarantine = isolated.contains(&(threat.path.clone(), threat.sha256.clone()));
            total += 1;
            *by_type.entry(threat.name.clone()).or_default() += 1;
            *by_month
                .entry(threat.detected_at.format("%Y-%m").to_string())
                .or_default() += 1;
            if recent.len() < 10 {
                recent.push(threat);
            }
        }
    }
    Ok(
        json!({"in_quarantine":quarantined, "total_detected":total,"recent_threats":recent,"threats_by_type":by_type,"threats_by_month":by_month}),
    )
}

#[command]
fn get_quarantined_files(state: State<'_, Arc<Desktop>>) -> Result<Vec<Value>, String> {
    Ok(state.engine()?.quarantine().list_entries().map_err(|e|e.to_string())?.into_iter().map(|q| json!({
        "id":q.quarantine_name, "fileName":q.original_path.file_name().map(|n|n.to_string_lossy()),
        "originalPath":q.original_path,"threatType":q.reason,"detectionDate":q.quarantine_date,"fileSize":q.file_size
    })).collect())
}
#[command]
fn quarantine_detection(
    session_id: uuid::Uuid,
    threat_id: uuid::Uuid,
    state: State<'_, Arc<Desktop>>,
) -> Result<(), String> {
    let path = state
        .data
        .join("history")
        .join(format!("{session_id}.json"));
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let record: Record = serde_json::from_reader(file).map_err(|error| error.to_string())?;
    let threat = record
        .detected_threats
        .iter()
        .find(|t| t.id == threat_id)
        .ok_or("Detection no longer available")?;
    state
        .engine()?
        .quarantine()
        .quarantine_if_unchanged(&threat.path, &threat.name, &threat.sha256)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[command]
fn restore_quarantined_file(id: String, state: State<'_, Arc<Desktop>>) -> Result<(), String> {
    state
        .engine()?
        .restore_quarantined(&id)
        .map(|_| ())
        .map_err(|e| e.to_string())
}
#[command]
fn delete_quarantined_file(id: String, state: State<'_, Arc<Desktop>>) -> Result<(), String> {
    state
        .engine()?
        .quarantine()
        .delete_file_by_id(&id)
        .map_err(|e| e.to_string())
}
#[command]
async fn update_signatures(state: State<'_, Arc<Desktop>>) -> Result<(), String> {
    state
        .engine()?
        .update_yara_rules()
        .await
        .map_err(|e| e.to_string())
}
#[command]
fn get_system_resources(state: State<'_, Arc<Desktop>>) -> Value {
    let mut sys = state.system.lock().unwrap();
    sys.refresh_cpu();
    sys.refresh_memory();
    json!({"cpu_usage": sys.global_cpu_info().cpu_usage(), "memory_usage":100.0*sys.used_memory() as f64/sys.total_memory().max(1) as f64})
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data = app
                .path_resolver()
                .app_local_data_dir()
                .ok_or("Local app data directory is unavailable")?;
            let exe = std::env::current_exe()?;
            let install = exe.parent().ok_or("Executable directory is unavailable")?;
            #[cfg(debug_assertions)]
            let install = if install.join("config.toml").is_file() {
                install
            } else {
                Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
            };
            let engine = tauri::async_runtime::block_on(load_engine(install, &data));
            app.manage(Arc::new(Desktop {
                engine,
                data,
                active: Mutex::new(None),
                system: Mutex::new(System::new()),
            }));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            preferences::get_quick_paths,
            preferences::save_quick_paths,
            preferences::get_schedule,
            preferences::set_schedule,
            quarantine_detection,
            get_protection_status,
            toggle_protection,
            toggle_protection_feature,
            start_quick_scan,
            start_full_scan,
            start_custom_scan,
            cancel_scan,
            get_scan_progress,
            get_scan_history,
            get_activity_log,
            get_threat_statistics,
            get_quarantined_files,
            restore_quarantined_file,
            delete_quarantined_file,
            update_signatures,
            get_system_resources
        ])
        .run(tauri::generate_context!())
        .expect("Failed to start Amaru Desktop");
}
