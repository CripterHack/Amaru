use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use notify_debouncer_mini::{new_debouncer, DebouncedEvent};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use crossbeam_channel::{unbounded, Receiver, Sender};
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;
use dashmap::DashMap;
use regex;

/// Errors that can occur during real-time monitoring
#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("Failed to initialize watcher: {0}")]
    WatcherInitError(String),
    
    #[error("Failed to add path to watch: {0}")]
    WatchPathError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Notify error: {0}")]
    NotifyError(String),
    
    #[error("Channel send error: {0}")]
    ChannelError(String),
}

/// Monitor state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorState {
    Running,
    Paused,
    Stopped,
}

/// File event representing a file change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: PathBuf,
    pub event_type: FileEventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub process_info: Option<ProcessInfo>,
}

/// Type of file event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileEventType {
    Created,
    Modified,
    Deleted,
    Renamed(PathBuf), // Nueva ubicación en caso de renombrado
}

/// Action to take after processing a file event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAction {
    /// Continue monitoring
    Continue,
    
    /// Pause monitoring
    Pause,
    
    /// Stop monitoring
    Stop,
}

/// Configuration for the real-time monitor
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Paths to monitor
    pub paths: Vec<PathBuf>,
    
    /// File extensions to monitor (empty means all)
    pub extensions_filter: Vec<String>,
    
    /// Paths to ignore
    pub ignore_paths: Vec<PathBuf>,
    
    /// Delay between receiving an event and processing it (in milliseconds)
    pub event_delay_ms: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            paths: vec![],
            extensions_filter: vec![],
            ignore_paths: vec![],
            event_delay_ms: 500,
        }
    }
}

/// Real-time file monitoring service
pub struct RealTimeMonitor {
    state: Arc<Mutex<MonitorState>>,
    config: MonitorConfig,
    event_sender: Sender<FileEvent>,
    event_receiver: Receiver<FileEvent>,
    stats: Arc<Mutex<MonitorStats>>,
    watcher: RecommendedWatcher,
    watched_paths: Arc<DashMap<PathBuf, RecursiveMode>>,
    filters: Arc<Filters>,
}

/// Statistics for the monitor
#[derive(Debug, Clone, Default)]
pub struct MonitorStats {
    pub files_monitored: usize,
    pub events_processed: usize,
    pub threats_detected: usize,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: PathBuf,
    pub command_line: String,
}

#[derive(Debug, Clone)]
struct Filters {
    exclude_paths: Vec<PathBuf>,
    exclude_patterns: Vec<regex::Regex>,
    include_extensions: Vec<String>,
    max_file_size: u64,
}

impl RealTimeMonitor {
    /// Create a new real-time monitor with the given configuration
    pub fn new(config: MonitorConfig) -> Result<Self, MonitorError> {
        let (sender, receiver) = unbounded();
        
        // Validate config
        if config.paths.is_empty() {
            return Err(MonitorError::WatchPathError("No paths specified to monitor".to_string()));
        }
        
        // Check that paths exist
        for path in &config.paths {
            if !path.exists() {
                return Err(MonitorError::WatchPathError(format!("Path does not exist: {:?}", path)));
            }
        }
        
        let (event_tx, event_rx) = mpsc::channel(1000);
        let watched_paths = Arc::new(DashMap::new());
        let watched_paths_clone = Arc::clone(&watched_paths);

        let filters = Arc::new(Filters {
            exclude_paths: Vec::new(),
            exclude_patterns: Vec::new(),
            include_extensions: vec!["exe".to_string(), "dll".to_string(), "sys".to_string()],
            max_file_size: 100 * 1024 * 1024, // 100MB por defecto
        });

        let filters_clone = Arc::clone(&filters);
        let event_tx_clone = event_tx.clone();

        let watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if let Some(file_event) = process_event(event, &filters_clone) {
                        if let Err(e) = event_tx_clone.send(file_event) {
                            error!("Error enviando evento: {}", e);
                        }
                    }
                }
                Err(e) => error!("Error de monitoreo: {}", e),
            }
        })?;

        Ok(Self {
            state: Arc::new(Mutex::new(MonitorState::Stopped)),
            config,
            event_sender: sender,
            event_receiver: receiver,
            stats: Arc::new(Mutex::new(MonitorStats::default())),
            watcher,
            watched_paths: watched_paths_clone,
            filters,
        })
    }
    
    /// Start monitoring with a callback function for processing events
    ///
    /// Begins real-time monitoring of configured paths and processes file events
    /// using the provided callback function.
    ///
    /// # Arguments
    /// * `on_event` - Callback function that processes file events and returns an action
    ///
    /// # Returns
    /// Success if monitoring started, error otherwise
    ///
    /// # Errors
    /// Returns an error if:
    /// - Monitor is already running
    /// - Failed to add watch paths
    /// - Failed to start watcher
    pub fn start<F>(&mut self, on_event: F) -> Result<(), MonitorError> 
    where
        F: Fn(FileEvent) -> EventAction + Send + 'static,
    {
        // Update state to running
        {
            let mut state = self.state.lock().unwrap();
            match *state {
                MonitorState::Running => {
                    info!("Real-time monitor is already running");
                    return Ok(());
                }
                MonitorState::Paused => {
                    *state = MonitorState::Running;
                    info!("Resuming real-time monitor");
                    return Ok(());
                }
                MonitorState::Stopped => {
                    *state = MonitorState::Running;
                }
            }
        }
        
        // Reset statistics
        {
            let mut stats = self.stats.lock().unwrap();
            *stats = MonitorStats::default();
            stats.start_time = Some(chrono::Utc::now());
        }
        
        info!("Starting real-time file monitor with {} paths", self.config.paths.len());
        
        // Create a channel for receiving events from the watcher
        let (tx, rx) = unbounded();
        let tx_clone = tx.clone();
        
        // Set up debouncer for file events
        let mut debouncer = new_debouncer(
            Duration::from_millis(self.config.event_delay_ms),
            None,
            move |res: Result<Vec<DebouncedEvent>, _>| {
                match res {
                    Ok(events) => {
                        for event in events {
                            if let Err(e) = tx_clone.send(event) {
                                error!("Failed to send event: {}", e);
                            }
                        }
                    }
                    Err(e) => error!("Debouncer error: {}", e),
                }
            },
        ).map_err(|e| MonitorError::WatcherInitError(format!("Failed to create debouncer: {}", e)))?;
        
        // Add paths to watcher
        for path in &self.config.paths {
            info!("Adding watch path: {}", path.display());
            if !path.exists() {
                warn!("Watch path does not exist: {}", path.display());
                continue;
            }
            
            // Determine if path should be watched recursively
            let recursive = path.is_dir();
            let mode = if recursive {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            };
            
            // Add path to watcher
            match debouncer.watcher().watch(path, mode) {
                Ok(_) => {
                    debug!("Successfully added watch for {}", path.display());
                    self.watched_paths.insert(path.clone(), mode);
                }
                Err(e) => {
                    error!("Failed to watch path {}: {}", path.display(), e);
                    // Continue with other paths instead of failing completely
                }
            }
        }
        
        // Check if we have any paths being watched
        if self.watched_paths.is_empty() {
            return Err(MonitorError::WatchPathError("No valid paths could be added to watch".to_string()));
        }
        
        // Get clones of what we need for the thread
        let event_receiver = rx;
        let state = Arc::clone(&self.state);
        let stats = Arc::clone(&self.stats);
        let filters = Arc::clone(&self.filters);
        let watched_paths = Arc::clone(&self.watched_paths);
        
        // Spawn thread to process events
        std::thread::Builder::new()
            .name("realtime-monitor".to_string())
            .spawn(move || {
                info!("Real-time monitor thread started");
                
                'monitor_loop: while let Ok(event) = event_receiver.recv() {
                    // Check if we should continue processing
                    let current_state = *state.lock().unwrap();
                    if current_state != MonitorState::Running {
                        if current_state == MonitorState::Stopped {
                            break 'monitor_loop;
                        }
                        // Skip if paused
                        continue;
                    }
                    
                    // Extract path from event
                    let path = event.path;
                    
                    // Skip if path doesn't match our filters
                    if !Self::should_process_file(&path, &filters) {
                        continue;
                    }
                    
                    // Create FileEvent from notify event
                    let file_event = match event.event {
                        notify::event::Event::Create(create) => {
                            debug!("File created: {}", path.display());
                            FileEvent {
                                path: path.clone(),
                                event_type: FileEventType::Created,
                                timestamp: chrono::Utc::now(),
                                process_info: Self::get_process_info(&path),
                            }
                        }
                        notify::event::Event::Modify(modify) => {
                            debug!("File modified: {}", path.display());
                            FileEvent {
                                path: path.clone(),
                                event_type: FileEventType::Modified,
                                timestamp: chrono::Utc::now(),
                                process_info: Self::get_process_info(&path),
                            }
                        }
                        notify::event::Event::Remove(remove) => {
                            debug!("File deleted: {}", path.display());
                            FileEvent {
                                path: path.clone(),
                                event_type: FileEventType::Deleted,
                                timestamp: chrono::Utc::now(),
                                process_info: None, // Process info not available for deleted files
                            }
                        }
                        notify::event::Event::Rename(rename) => {
                            debug!("File renamed: {} -> {}", 
                                rename.from.display(), rename.to.display());
                            FileEvent {
                                path: rename.from.clone(),
                                event_type: FileEventType::Renamed(rename.to.clone()),
                                timestamp: chrono::Utc::now(),
                                process_info: Self::get_process_info(&rename.to),
                            }
                        }
                        _ => continue, // Skip other events
                    };
                    
                    // Update statistics
                    {
                        let mut stats_guard = stats.lock().unwrap();
                        stats_guard.events_processed += 1;
                    }
                    
                    // Process the event with the callback
                    match on_event(file_event) {
                        EventAction::Continue => {
                            // Continue monitoring
                        }
                        EventAction::Pause => {
                            // Pause monitoring
                            let mut state_guard = state.lock().unwrap();
                            *state_guard = MonitorState::Paused;
                            info!("Real-time monitor paused by event handler");
                        }
                        EventAction::Stop => {
                            // Stop monitoring
                            let mut state_guard = state.lock().unwrap();
                            *state_guard = MonitorState::Stopped;
                            info!("Real-time monitor stopped by event handler");
                            break 'monitor_loop;
                        }
                    }
                }
                
                info!("Real-time monitor thread exiting");
            })
            .map_err(|e| MonitorError::WatcherInitError(format!("Failed to spawn monitor thread: {}", e)))?;
        
        info!("Real-time monitor started successfully");
        Ok(())
    }
    
    /// Stop monitoring
    pub fn stop(&self) -> Result<(), MonitorError> {
        let mut state = self.state.lock().unwrap();
        *state = MonitorState::Stopped;
        info!("Real-time monitoring stopped");
        Ok(())
    }
    
    /// Pause monitoring temporarily
    pub fn pause(&self) -> Result<(), MonitorError> {
        let mut state = self.state.lock().unwrap();
        *state = MonitorState::Paused;
        info!("Real-time monitoring paused");
        Ok(())
    }
    
    /// Resume monitoring after pause
    pub fn resume(&self) -> Result<(), MonitorError> {
        let mut state = self.state.lock().unwrap();
        *state = MonitorState::Running;
        info!("Real-time monitoring resumed");
        Ok(())
    }
    
    /// Get the current state of the monitor
    pub fn get_state(&self) -> MonitorState {
        *self.state.lock().unwrap()
    }
    
    /// Get a clone of the current monitoring stats
    pub fn get_stats(&self) -> MonitorStats {
        self.stats.lock().unwrap().clone()
    }
    
    /// Increment the threats detected counter
    pub fn increment_threats_detected(&self) {
        let mut stats = self.stats.lock().unwrap();
        stats.threats_detected += 1;
    }
    
    /// Get the event receiver for direct access to events
    pub fn get_event_receiver(&self) -> Receiver<FileEvent> {
        self.event_receiver.clone()
    }
    
    /// Check if a file should be processed based on filters
    fn should_process_file(path: &Path, filters: &Arc<Filters>) -> bool {
        // Skip if path is a directory
        if path.is_dir() {
            return false;
        }
        
        // Skip if path is in exclude list
        for exclude in &filters.exclude_paths {
            if path.starts_with(exclude) {
                debug!("Skipping excluded path: {}", path.display());
                return false;
            }
        }
        
        // Skip if path matches exclude patterns
        for pattern in &filters.exclude_patterns {
            if pattern.is_match(&path.display().to_string()) {
                debug!("Skipping path matching exclude pattern: {}", path.display());
                return false;
            }
        }
        
        // Skip if file is too large
        if let Ok(metadata) = path.metadata() {
            if metadata.len() > filters.max_file_size {
                debug!("Skipping large file: {} ({} bytes)", path.display(), metadata.len());
                return false;
            }
        }
        
        // Check extension if filter is specified
        if !filters.include_extensions.is_empty() {
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if !filters.include_extensions.iter().any(|e| e.to_lowercase() == ext_str) {
                    return false;
                }
            } else {
                // No extension, skip if we're filtering by extension
                return false;
            }
        }
        
        true
    }
    
    /// Get process information for a file event
    #[cfg(target_os = "windows")]
    fn get_process_info(path: &Path) -> Option<ProcessInfo> {
        use std::process::Command;
        
        // Try to get process info using Windows Management Instrumentation
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                &format!(
                    "Get-WmiObject Win32_Process | Where-Object {{$_.CommandLine -like '*{}*'}} | Select-Object ProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json",
                    path.display()
                ),
            ])
            .output()
            .ok()?;
        
        if !output.status.success() {
            return None;
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            return None;
        }
        
        // Parse JSON output
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&stdout) {
            // Check if array or single object
            let process_obj = if value.is_array() {
                value.get(0)?
            } else {
                &value
            };
            
            // Extract fields
            let pid = process_obj.get("ProcessId")?.as_u64()? as u32;
            let name = process_obj.get("Name")?.as_str()?.to_string();
            let path_str = process_obj.get("ExecutablePath")?.as_str()?;
            let cmd_line = process_obj.get("CommandLine")?.as_str()?.to_string();
            
            return Some(ProcessInfo {
                pid,
                name,
                path: PathBuf::from(path_str),
                command_line: cmd_line,
            });
        }
        
        None
    }
    
    /// Add a path to the monitored paths
    pub fn add_watch_path(&mut self, path: PathBuf) -> Result<(), MonitorError> {
        if !path.exists() {
            return Err(MonitorError::WatchPathError(format!("Path does not exist: {:?}", path)));
        }
        
        self.config.paths.push(path);
        
        // If we're already monitoring, we need to restart
        if *self.state.lock().unwrap() == MonitorState::Running {
            warn!("Added new watch path, but monitoring needs to be restarted for it to take effect");
        }
        
        self.watcher.watch(&path, RecursiveMode::Recursive)?;
        self.watched_paths.insert(path, RecursiveMode::Recursive);
        
        Ok(())
    }
    
    /// Remove a path from the monitored paths
    pub fn remove_watch_path(&mut self, path: &Path) -> Result<(), MonitorError> {
        self.config.paths.retain(|p| p != path);
        
        // If we're already monitoring, we need to restart
        if *self.state.lock().unwrap() == MonitorState::Running {
            warn!("Removed watch path, but monitoring needs to be restarted for it to take effect");
        }
        
        self.watcher.unwatch(path)?;
        self.watched_paths.remove(path);
        
        Ok(())
    }
}

fn process_event(event: Event, filters: &Filters) -> Option<FileEvent> {
    let paths: Vec<_> = event.paths.iter().collect();
    if paths.is_empty() {
        return None;
    }

    let path = paths[0];

    // Verificar exclusiones
    if filters.exclude_paths.iter().any(|p| path.starts_with(p)) {
        return None;
    }

    if filters.exclude_patterns.iter().any(|r| r.is_match(&path.to_string_lossy())) {
        return None;
    }

    // Verificar extensión
    if let Some(ext) = path.extension() {
        if !filters.include_extensions.iter().any(|e| e == &ext.to_string_lossy()) {
            return None;
        }
    } else {
        return None;
    }

    // Verificar tamaño
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() > filters.max_file_size {
            return None;
        }
    }

    let event_type = match event.kind {
        notify::EventKind::Create(_) => FileEventType::Created,
        notify::EventKind::Modify(_) => FileEventType::Modified,
        notify::EventKind::Remove(_) => FileEventType::Deleted,
        notify::EventKind::Rename(_, _) => {
            if paths.len() > 1 {
                FileEventType::Renamed(paths[1].to_path_buf())
            } else {
                return None;
            }
        }
        _ => return None,
    };

    let process_info = get_process_info(path);

    Some(FileEvent {
        path: path.to_path_buf(),
        event_type,
        timestamp: chrono::Utc::now(),
        process_info,
    })
}

#[cfg(windows)]
fn get_process_info(path: &Path) -> Option<ProcessInfo> {
    use windows::Win32::System::ProcessStatus::{K32EnumProcesses, K32GetModuleFileNameExW};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
    
    let mut processes = [0u32; 1024];
    let mut needed = 0;
    
    unsafe {
        if !K32EnumProcesses(
            processes.as_mut_ptr(),
            (processes.len() * std::mem::size_of::<u32>()) as u32,
            &mut needed,
        ).as_bool() {
            return None;
        }
    }

    let count = needed as usize / std::mem::size_of::<u32>();
    
    for &pid in &processes[..count] {
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                let mut path_buf = [0u16; 260];
                if K32GetModuleFileNameExW(handle, None, &mut path_buf).0 > 0 {
                    let path_str = String::from_utf16_lossy(&path_buf[..]);
                    if path_str.contains(path.to_string_lossy().as_ref()) {
                        return Some(ProcessInfo {
                            pid,
                            name: path.file_name()?.to_string_lossy().into_owned(),
                            path: PathBuf::from(path_str.trim_matches('\0')),
                            command_line: String::new(), // TODO: Implementar obtención de command line
                        });
                    }
                }
            }
        }
    }
    
    None
}

#[cfg(not(windows))]
fn get_process_info(_path: &Path) -> Option<ProcessInfo> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    
    #[test]
    fn test_monitor_state_transitions() {
        let config = MonitorConfig {
            paths: vec![std::env::current_dir().unwrap()],
            ..Default::default()
        };
        
        let monitor = RealTimeMonitor::new(config).unwrap();
        assert_eq!(monitor.get_state(), MonitorState::Stopped);
        
        let _ = monitor.pause();
        assert_eq!(monitor.get_state(), MonitorState::Paused);
        
        let _ = monitor.resume();
        assert_eq!(monitor.get_state(), MonitorState::Running);
        
        let _ = monitor.stop();
        assert_eq!(monitor.get_state(), MonitorState::Stopped);
    }
    
    #[test]
    fn test_should_monitor_file() {
        let extensions = Arc::new(vec!["exe".to_string(), "dll".to_string()]);
        let ignore_paths = Arc::new(vec![PathBuf::from("C:\\Windows\\Temp")]);
        
        // Should monitor .exe file
        assert!(RealTimeMonitor::should_process_file(
            &PathBuf::from("C:\\test.exe"),
            &extensions,
            &ignore_paths
        ));
        
        // Should not monitor .txt file
        assert!(!RealTimeMonitor::should_process_file(
            &PathBuf::from("C:\\test.txt"),
            &extensions,
            &ignore_paths
        ));
        
        // Should not monitor file in ignore path
        assert!(!RealTimeMonitor::should_process_file(
            &PathBuf::from("C:\\Windows\\Temp\\test.exe"),
            &extensions,
            &ignore_paths
        ));
    }
} 