use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use notify_debouncer_mini::{new_debouncer, DebouncedEvent};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use crossbeam_channel::{unbounded, Receiver, Sender};
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

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
#[derive(Debug, Clone)]
pub struct FileEvent {
    pub path: PathBuf,
    pub event_type: EventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Type of file event
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventType {
    Create,
    Modify,
    Delete,
    Rename(Option<PathBuf>), // The "to" path for renames
    Access,
    Other,
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
}

/// Statistics for the monitor
#[derive(Debug, Clone, Default)]
pub struct MonitorStats {
    pub files_monitored: usize,
    pub events_processed: usize,
    pub threats_detected: usize,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
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
        
        Ok(Self {
            state: Arc::new(Mutex::new(MonitorState::Stopped)),
            config,
            event_sender: sender,
            event_receiver: receiver,
            stats: Arc::new(Mutex::new(MonitorStats::default())),
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
            debouncer
                .watcher()
                .watch(path, RecursiveMode::Recursive)
                .map_err(|e| MonitorError::WatchPathError(e.to_string()))?;
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
        
        Ok(())
    }
    
    /// Remove a path from the monitored paths
    pub fn remove_watch_path(&mut self, path: &Path) -> Result<(), MonitorError> {
        self.config.paths.retain(|p| p != path);
        
        // If we're already monitoring, we need to restart
        if *self.state.lock().unwrap() == MonitorState::Running {
            warn!("Removed watch path, but monitoring needs to be restarted for it to take effect");
        }
        
        Ok(())
    }
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