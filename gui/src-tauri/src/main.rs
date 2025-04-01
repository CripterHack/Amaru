#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

use std::sync::Arc;
use std::path::PathBuf;
use tauri::{State, Manager, Window, command};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::time::Duration;

// Import Amaru core libraries
use amaru::{Amaru, Config, Event, ScanResult, RiskLevel, ThreatType};
use amaru::quarantine::QuarantineEntry;

// State management
struct AppState {
  amaru: Arc<RwLock<Amaru>>,
  is_scanning: Arc<RwLock<bool>>,
}

// Types for frontend communication
#[derive(Serialize, Deserialize, Clone)]
struct ProtectionStatus {
  enabled: bool,
  monitored_paths: Vec<String>,
  scanning_enabled: bool,
  last_updated: Option<DateTime<Utc>>,
  version: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ScanHistoryEntry {
  id: String,
  scan_type: String,
  start_time: DateTime<Utc>,
  completed_at: DateTime<Utc>,
  duration: u64,
  files_scanned: u64,
  threats_found: u32,
  items_quarantined: u32,
  detected_threats: Vec<ThreatEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ThreatEntry {
  id: String,
  name: String,
  path: String,
  risk_level: String,
  description: String,
  detected_at: DateTime<Utc>,
  in_quarantine: bool,
  action: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ThreatStatistics {
  total_detected: u32,
  in_quarantine: u32,
  recent_threats: Vec<ThreatEntry>,
  threats_by_type: std::collections::HashMap<String, u32>,
  threats_by_month: std::collections::HashMap<String, u32>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ActivityLogEntry {
  id: String,
  #[serde(rename = "type")]
  entry_type: String,
  message: String,
  date: DateTime<Utc>,
  status: String,
}

// Event handlers
fn handle_events(window: Window, event_receiver: std::sync::mpsc::Receiver<Event>) {
  std::thread::spawn(move || {
    for event in event_receiver {
      match event {
        Event::ThreatDetected { path, threat_type, confidence, timestamp, .. } => {
          let _ = window.emit("threat-detected", ThreatEntry {
            id: uuid::Uuid::new_v4().to_string(),
            name: format!("{:?}", threat_type),
            path: path.clone(),
            risk_level: get_risk_level_string(confidence),
            description: format!("Detected {:?} with {}% confidence", threat_type, confidence),
            detected_at: timestamp,
            in_quarantine: false,
            action: Some("Detected".to_string()),
          });
        },
        Event::ScanProgress { progress, current_file, .. } => {
          let _ = window.emit("scan-progress", serde_json::json!({
            "progress": progress,
            "currentFile": current_file
          }));
        },
        Event::ScanCompleted { result, .. } => {
          let _ = window.emit("scan-completed", convert_scan_result(result));
        },
        Event::ProtectionStatusChanged { enabled, monitored_paths, .. } => {
          let _ = window.emit("protection-status-changed", serde_json::json!({
            "enabled": enabled,
            "monitoredPaths": monitored_paths
          }));
        },
        _ => {}
      }
    }
  });
}

fn get_risk_level_string(confidence: u8) -> String {
  match confidence {
    0..=25 => "low".to_string(),
    26..=50 => "medium".to_string(),
    51..=75 => "high".to_string(),
    _ => "critical".to_string(),
  }
}

fn convert_scan_result(result: ScanResult) -> ScanHistoryEntry {
  let threats: Vec<ThreatEntry> = result.threats.iter().map(|threat| {
    ThreatEntry {
      id: uuid::Uuid::new_v4().to_string(),
      name: format!("{:?}", threat.threat_type),
      path: threat.path.clone(),
      risk_level: format!("{:?}", threat.risk_level).to_lowercase(),
      description: threat.description.clone(),
      detected_at: threat.timestamp,
      in_quarantine: threat.in_quarantine,
      action: Some(threat.action.clone()),
    }
  }).collect();

  ScanHistoryEntry {
    id: uuid::Uuid::new_v4().to_string(),
    scan_type: result.scan_type.to_lowercase(),
    start_time: result.start_time,
    completed_at: result.end_time,
    duration: result.duration_ms,
    files_scanned: result.files_scanned,
    threats_found: threats.len() as u32,
    items_quarantined: result.items_quarantined as u32,
    detected_threats: threats,
  }
}

// Commands

#[command]
async fn get_protection_status(state: State<'_, AppState>) -> Result<ProtectionStatus, String> {
  let amaru = state.amaru.read().await;
  let status = amaru.get_protection_status().await.map_err(|e| e.to_string())?;
  
  Ok(ProtectionStatus {
    enabled: status.enabled,
    monitored_paths: status.monitored_paths,
    scanning_enabled: status.scanning_enabled,
    last_updated: status.last_updated,
    version: status.version,
  })
}

#[command]
async fn enable_protection(state: State<'_, AppState>) -> Result<(), String> {
  let mut amaru = state.amaru.write().await;
  amaru.enable_realtime_protection().await.map_err(|e| e.to_string())?;
  Ok(())
}

#[command]
async fn disable_protection(state: State<'_, AppState>) -> Result<(), String> {
  let mut amaru = state.amaru.write().await;
  amaru.disable_realtime_protection().await.map_err(|e| e.to_string())?;
  Ok(())
}

#[command]
async fn toggle_protection(state: State<'_, AppState>, enable: bool) -> Result<(), String> {
  let mut amaru = state.amaru.write().await;
  
  if enable {
    amaru.enable_realtime_protection().await.map_err(|e| e.to_string())?;
  } else {
    amaru.disable_realtime_protection().await.map_err(|e| e.to_string())?;
  }
  
  Ok(())
}

#[command]
async fn toggle_protection_feature(state: State<'_, AppState>, feature_id: String, enable: bool) -> Result<(), String> {
  let mut amaru = state.amaru.write().await;
  
  amaru.toggle_protection_feature(&feature_id, enable).await
    .map_err(|e| e.to_string())?;
  
  Ok(())
}

#[command]
async fn start_quick_scan(state: State<'_, AppState>, window: Window) -> Result<(), String> {
  // Check if already scanning
  {
    let is_scanning = state.is_scanning.read().await;
    if *is_scanning {
      return Err("A scan is already in progress".to_string());
    }
  }
  
  // Set scanning flag
  {
    let mut is_scanning = state.is_scanning.write().await;
    *is_scanning = true;
  }
  
  // Get common scan paths
  let paths = vec![
    dirs::home_dir().unwrap_or_default().join("Downloads"),
    dirs::home_dir().unwrap_or_default().join("Desktop"),
    dirs::home_dir().unwrap_or_default().join("Documents"),
  ];
  
  // Get Amaru instance and run scan
  let amaru_clone = state.amaru.clone();
  let is_scanning_clone = state.is_scanning.clone();
  let window_clone = window.clone();
  
  tauri::async_runtime::spawn(async move {
    let amaru = amaru_clone.read().await;
    let result = amaru.scan_paths(&paths, true).await;
    
    // Reset scanning flag
    {
      let mut is_scanning = is_scanning_clone.write().await;
      *is_scanning = false;
    }
    
    // Emit result
    if let Ok(scan_result) = result {
      let _ = window_clone.emit("scan-completed", convert_scan_result(scan_result));
    } else {
      let _ = window_clone.emit("scan-error", result.err().unwrap().to_string());
    }
  });
  
  Ok(())
}

#[command]
async fn start_full_scan(state: State<'_, AppState>, window: Window) -> Result<(), String> {
  // Check if already scanning
  {
    let is_scanning = state.is_scanning.read().await;
    if *is_scanning {
      return Err("A scan is already in progress".to_string());
    }
  }
  
  // Set scanning flag
  {
    let mut is_scanning = state.is_scanning.write().await;
    *is_scanning = true;
  }
  
  // Get system drives
  let paths = vec![
    PathBuf::from("C:\\"),
  ];
  
  // Get Amaru instance and run scan
  let amaru_clone = state.amaru.clone();
  let is_scanning_clone = state.is_scanning.clone();
  let window_clone = window.clone();
  
  tauri::async_runtime::spawn(async move {
    let amaru = amaru_clone.read().await;
    let result = amaru.scan_paths(&paths, true).await;
    
    // Reset scanning flag
    {
      let mut is_scanning = is_scanning_clone.write().await;
      *is_scanning = false;
    }
    
    // Emit result
    if let Ok(scan_result) = result {
      let _ = window_clone.emit("scan-completed", convert_scan_result(scan_result));
    } else {
      let _ = window_clone.emit("scan-error", result.err().unwrap().to_string());
    }
  });
  
  Ok(())
}

#[command]
async fn cancel_scan(state: State<'_, AppState>) -> Result<(), String> {
  let mut amaru = state.amaru.write().await;
  amaru.cancel_scan().await.map_err(|e| e.to_string())?;
  
  // Reset scanning flag
  {
    let mut is_scanning = state.is_scanning.write().await;
    *is_scanning = false;
  }
  
  Ok(())
}

#[command]
async fn get_scan_history(state: State<'_, AppState>) -> Result<Vec<ScanHistoryEntry>, String> {
  let amaru = state.amaru.read().await;
  let history = amaru.get_scan_history(10).await.map_err(|e| e.to_string())?;
  
  Ok(history.into_iter().map(convert_scan_result).collect())
}

#[command]
async fn get_threat_statistics(state: State<'_, AppState>) -> Result<ThreatStatistics, String> {
  let amaru = state.amaru.read().await;
  let stats = amaru.get_threat_statistics().await.map_err(|e| e.to_string())?;
  
  // Convert threats to ThreatEntry objects
  let recent_threats = stats.recent_threats.iter().map(|threat| {
    ThreatEntry {
      id: uuid::Uuid::new_v4().to_string(),
      name: format!("{:?}", threat.threat_type),
      path: threat.path.clone(),
      risk_level: format!("{:?}", threat.risk_level).to_lowercase(),
      description: threat.description.clone(),
      detected_at: threat.timestamp,
      in_quarantine: threat.in_quarantine,
      action: Some(threat.action.clone()),
    }
  }).collect();
  
  Ok(ThreatStatistics {
    total_detected: stats.total_detected,
    in_quarantine: stats.in_quarantine,
    recent_threats,
    threats_by_type: stats.threats_by_type,
    threats_by_month: stats.threats_by_month,
  })
}

#[command]
async fn update_signatures(state: State<'_, AppState>, window: Window) -> Result<(), String> {
  let mut amaru = state.amaru.write().await;
  
  // Start update in background
  tauri::async_runtime::spawn(async move {
    let result = amaru.update_signatures().await;
    
    if let Ok(update_result) = result {
      let _ = window.emit("signatures-updated", update_result);
    } else {
      let _ = window.emit("update-error", result.err().unwrap().to_string());
    }
  });
  
  Ok(())
}

#[command]
async fn get_quarantined_files(state: State<'_, AppState>) -> Result<Vec<QuarantineEntry>, String> {
  let amaru = state.amaru.read().await;
  let quarantined = amaru.get_quarantined_files().await.map_err(|e| e.to_string())?;
  Ok(quarantined)
}

#[command]
async fn delete_quarantined_file(state: State<'_, AppState>, id: String) -> Result<(), String> {
  let mut amaru = state.amaru.write().await;
  amaru.delete_from_quarantine(&id).await.map_err(|e| e.to_string())?;
  Ok(())
}

#[command]
async fn restore_quarantined_file(state: State<'_, AppState>, id: String) -> Result<(), String> {
  let mut amaru = state.amaru.write().await;
  amaru.restore_from_quarantine(&id).await.map_err(|e| e.to_string())?;
  Ok(())
}

#[command]
async fn get_system_resources() -> Result<serde_json::Value, String> {
  #[cfg(target_os = "windows")]
  {
    // Use WMI to get system information on Windows
    let cpu_usage = get_cpu_usage().await?;
    let memory_usage = get_memory_usage().await?;
    
    Ok(serde_json::json!({
      "cpu_usage": cpu_usage,
      "memory_usage": memory_usage
    }))
  }
  
  #[cfg(not(target_os = "windows"))]
  {
    // Simplified version for non-Windows platforms
    // In a real implementation, this would use platform-specific APIs
    Ok(serde_json::json!({
      "cpu_usage": 0.0,
      "memory_usage": 0.0
    }))
  }
}

#[cfg(target_os = "windows")]
async fn get_cpu_usage() -> Result<f64, String> {
  // Simplified example - in a real implementation, this would use WMI or other Windows APIs
  // to get actual CPU usage
  
  // For testing purposes, return a random value between 0 and 100
  let mut rng = rand::thread_rng();
  let usage = rng.gen_range(0.0..100.0);
  
  Ok(usage)
}

#[cfg(target_os = "windows")]
async fn get_memory_usage() -> Result<f64, String> {
  // Simplified example - in a real implementation, this would use Windows API
  // to get actual memory usage
  
  use winapi::um::sysinfoapi::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
  use std::mem::{size_of, zeroed};
  
  unsafe {
    let mut mem_info: MEMORYSTATUSEX = zeroed();
    mem_info.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    
    if GlobalMemoryStatusEx(&mut mem_info) == 0 {
      return Err("Failed to get memory information".into());
    }
    
    // Return memory usage percentage
    Ok(mem_info.dwMemoryLoad as f64)
  }
}

#[command]
async fn get_activity_log(state: State<'_, AppState>) -> Result<Vec<ActivityLogEntry>, String> {
  let amaru = state.amaru.read().await;
  amaru.get_activity_log().await
    .map_err(|e| e.to_string())
}

// Start the resource monitoring in a background task
fn start_resource_monitoring(window: Window) {
  tauri::async_runtime::spawn(async move {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    
    loop {
      interval.tick().await;
      
      match get_system_resources().await {
        Ok(resources) => {
          let _ = window.emit("system-resource-update", resources);
        },
        Err(e) => {
          eprintln!("Failed to get system resources: {}", e);
        }
      }
    }
  });
}

fn main() {
  let config = load_config();
  
  // Create tokio runtime for async initialization
  let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
  
  // Initialize Amaru in the runtime
  let amaru = rt.block_on(async {
    Amaru::new(config).await.expect("Failed to initialize Amaru")
  });
  
  // Get event channel
  let (event_sender, event_receiver) = std::sync::mpsc::channel();
  rt.block_on(async {
    amaru.set_event_sender(event_sender).await.expect("Failed to set event sender");
  });
  
  // Create application state
  let app_state = AppState {
    amaru: Arc::new(RwLock::new(amaru)),
    is_scanning: Arc::new(RwLock::new(false)),
  };
  
  tauri::Builder::default()
    .manage(app_state)
    .setup(|app| {
      // Setup event handling
      let window = app.get_window("main").unwrap();
      handle_events(window.clone(), event_receiver);
      
      // Start resource monitoring
      start_resource_monitoring(window);
      
      Ok(())
    })
    .invoke_handler(tauri::generate_handler![
      get_protection_status,
      enable_protection,
      disable_protection,
      toggle_protection,
      toggle_protection_feature,
      start_quick_scan,
      start_full_scan,
      cancel_scan,
      get_scan_history,
      get_threat_statistics,
      update_signatures,
      get_quarantined_files,
      delete_quarantined_file,
      restore_quarantined_file,
      get_system_resources,
      get_activity_log,
    ])
    .run(tauri::generate_context!())
    .expect("Error while running tauri application");
}

fn load_config() -> Config {
  // Load from settings file or use defaults
  let mut config = Config::default();
  
  // Set paths based on executable location
  let exe_dir = std::env::current_exe()
    .unwrap_or_default()
    .parent()
    .unwrap_or(&PathBuf::from("."))
    .to_path_buf();
  
  config.yara_rules_path = exe_dir.join("signatures");
  config.quarantine_config.quarantine_path = exe_dir.join("quarantine");
  
  // Add system protection paths
  config.monitored_paths = vec![
    dirs::home_dir().unwrap_or_default(),
    PathBuf::from("C:\\Program Files"),
    PathBuf::from("C:\\Windows\\System32"),
  ];
  
  // Load custom config if it exists
  if let Ok(config_file) = std::fs::read_to_string(exe_dir.join("amaru.config.json")) {
    if let Ok(custom_config) = serde_json::from_str::<Config>(&config_file) {
      config = custom_config;
    }
  }
  
  config
} 