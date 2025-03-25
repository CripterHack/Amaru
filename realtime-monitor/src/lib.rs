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
    pub fn start<F>(&mut self, on_event: F) -> Result<(), MonitorError> 
    where
        F: Fn(FileEvent) -> EventAction + Send + 'static,
    {
        // Update state to running
        {
            let mut state = self.state.lock().unwrap();
            *state = MonitorState::Running;
            
            // Update stats
            let mut stats = self.stats.lock().unwrap();
            stats.start_time = Some(chrono::Utc::now());
        }
        
        // Create a clone of the sender for the watcher
        let event_sender = self.event_sender.clone();
        
        // Create a debounced watcher to reduce duplicate events
        let (tx, rx) = std::sync::mpsc::channel();
        
        let mut debouncer = new_debouncer(
            Duration::from_millis(self.config.event_delay_ms),
            None,
            tx,
        )
        .map_err(|e| MonitorError::WatcherInitError(e.to_string()))?;
        
        // Add paths to watch
        for path in &self.config.paths {
            info!("Watching path: {}", path.display());
            self.watcher.watch(path, RecursiveMode::Recursive)?;
            self.watched_paths.insert(path.clone(), RecursiveMode::Recursive);
        }
        
        // Create clones for the watcher thread
        let extensions_filter = self.config.extensions_filter.clone();
        let ignore_paths = self.config.ignore_paths.clone();
        
        // Create a thread to forward events from the debouncer to our channel
        let extensions_filter_arc = Arc::new(extensions_filter);
        let ignore_paths_arc = Arc::new(ignore_paths);
        
        std::thread::spawn(move || {
            for result in rx {
                match result {
                    Ok(events) => {
                        for event in events {
                            // Check if the file should be monitored based on extension
                            let should_monitor = Self::should_monitor_file(
                                &event.path,
                                &extensions_filter_arc,
                                &ignore_paths_arc,
                            );
                            
                            if should_monitor {
                                // Simplify event type detection based on file existence
                                let event_type = if event.path.exists() {
                                    EventType::Modify
                                } else {
                                    EventType::Delete
                                };
                                
                                let file_event = FileEvent {
                                    path: event.path,
                                    event_type,
                                    timestamp: chrono::Utc::now(),
                                    process_info: None,
                                };
                                
                                if let Err(e) = event_sender.send(file_event) {
                                    error!("Failed to send file event: {}", e);
                                }
                            }
                        }
                    },
                    Err(e) => {
                        error!("Watch error: {:?}", e);
                    }
                }
            }
        });
        
        // Set up event processing thread
        let event_receiver = self.event_receiver.clone();
        let state_arc = self.state.clone();
        let stats_arc = self.stats.clone();
        
        std::thread::spawn(move || {
            while *state_arc.lock().unwrap() != MonitorState::Stopped {
                // Check if we're paused
                if *state_arc.lock().unwrap() == MonitorState::Paused {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                
                // Wait for an event with timeout
                match event_receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(event) => {
                        // Update stats
                        {
                            let mut stats = stats_arc.lock().unwrap();
                            stats.events_processed += 1;
                        }
                        
                        // Process the event
                        let action = on_event(event);
                        
                        // Handle action
                        match action {
                            EventAction::Continue => {
                                // Continue processing
                            },
                            EventAction::Pause => {
                                let mut state = state_arc.lock().unwrap();
                                *state = MonitorState::Paused;
                                info!("Monitoring paused by event handler");
                            },
                            EventAction::Stop => {
                                let mut state = state_arc.lock().unwrap();
                                *state = MonitorState::Stopped;
                                info!("Monitoring stopped by event handler");
                                break;
                            }
                        }
                    },
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        // No events received, continue
                    },
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        error!("Event channel disconnected");
                        break;
                    }
                }
            }
            
            info!("Monitor event processing thread stopped");
        });
        
        info!("Real-time monitoring started");
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
    
    /// Check if a file should be monitored based on extension and ignore paths
    fn should_monitor_file(
        path: &Path,
        extensions_filter: &Arc<Vec<String>>,
        ignore_paths: &Arc<Vec<PathBuf>>,
    ) -> bool {
        // Check if path is in ignore list
        for ignore_path in ignore_paths.iter() {
            if path.starts_with(ignore_path) {
                return false;
            }
        }
        
        // If no extension filter is set, monitor all files
        if extensions_filter.is_empty() {
            return true;
        }
        
        // Check file extension
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            extensions_filter.iter().any(|filter| &ext_str == filter)
        } else {
            false
        }
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
        assert!(RealTimeMonitor::should_monitor_file(
            &PathBuf::from("C:\\test.exe"),
            &extensions,
            &ignore_paths
        ));
        
        // Should not monitor .txt file
        assert!(!RealTimeMonitor::should_monitor_file(
            &PathBuf::from("C:\\test.txt"),
            &extensions,
            &ignore_paths
        ));
        
        // Should not monitor file in ignore path
        assert!(!RealTimeMonitor::should_monitor_file(
            &PathBuf::from("C:\\Windows\\Temp\\test.exe"),
            &extensions,
            &ignore_paths
        ));
    }
} 