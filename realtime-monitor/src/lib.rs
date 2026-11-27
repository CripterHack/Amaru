use crossbeam_channel::{bounded, Receiver, Sender};
use log::{error, warn};
use notify::{
    event::{ModifyKind, RenameMode},
    Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use notify_debouncer_full::{new_debouncer, DebounceEventResult, Debouncer, FileIdMap};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
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

type FileWatcher = Debouncer<RecommendedWatcher, FileIdMap>;

/// Real-time file monitoring service.
pub struct RealTimeMonitor {
    config: MonitorConfig,
    state: Arc<Mutex<MonitorState>>,
    stats: Arc<Mutex<MonitorStats>>,
    watcher: Arc<Mutex<Option<FileWatcher>>>,
    registered: HashSet<PathBuf>,
    subscribers: Arc<OnceLock<(Sender<FileEvent>, Receiver<FileEvent>)>>,
}

/// Spelling used by the Amaru core.
pub type RealtimeMonitor = RealTimeMonitor;

impl RealTimeMonitor {
    pub fn new(config: MonitorConfig) -> Result<Self, MonitorError> {
        if config.paths.is_empty() {
            return Err(MonitorError::WatchPathError(
                "No watch paths supplied".into(),
            ));
        }
        for path in &config.paths {
            if !path.exists() {
                return Err(MonitorError::WatchPathError(path.display().to_string()));
            }
        }
        Ok(Self {
            config,
            state: Arc::new(Mutex::new(MonitorState::Stopped)),
            stats: Arc::new(Mutex::new(MonitorStats::default())),
            watcher: Arc::new(Mutex::new(None)),
            registered: HashSet::new(),
            subscribers: Arc::new(OnceLock::new()),
        })
    }

    pub fn start<F>(&mut self, on_event: F) -> Result<(), MonitorError>
    where
        F: Fn(FileEvent) -> EventAction + Send + 'static,
    {
        if self.watcher.lock().unwrap().is_some() && self.get_state() != MonitorState::Stopped {
            return self.resume();
        }
        // Each watcher owns its state. Events finishing after a restart cannot
        // pause or stop the replacement watcher.
        self.state = Arc::new(Mutex::new(MonitorState::Stopped));
        self.stats = Arc::new(Mutex::new(MonitorStats::default()));
        self.watcher = Arc::new(Mutex::new(None));
        self.registered.clear();
        let slot = Arc::downgrade(&self.watcher);
        let state = Arc::clone(&self.state);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();
        let subscribers = Arc::clone(&self.subscribers);
        let delay = Duration::from_millis(config.event_delay_ms.max(1));
        let mut watcher = new_debouncer(delay, None, move |batch: DebounceEventResult| {
            let events = match batch {
                Ok(events) => events,
                Err(errors) => {
                    for error in errors {
                        error!("File watcher: {error}");
                    }
                    return;
                }
            };
            #[cfg(windows)]
            let mut processes = None;
            for event in events {
                if *state.lock().unwrap() != MonitorState::Running {
                    break;
                }
                if let Some(event) = file_event(event.event, &config) {
                    #[cfg(windows)]
                    let event = with_process_info(event, &mut processes);
                    if *state.lock().unwrap() != MonitorState::Running {
                        break;
                    }
                    stats.lock().unwrap().events_processed += 1;
                    if let Some((sender, _)) = subscribers.get() {
                        if sender.try_send(event.clone()).is_err() {
                            log::debug!("Direct event receiver is full");
                        }
                    }
                    let action = on_event(event);
                    let mut current = state.lock().unwrap();
                    match action {
                        EventAction::Stop => {
                            *current = MonitorState::Stopped;
                            drop(current);
                            if let Some(slot) = slot.upgrade() {
                                slot.lock().unwrap().take();
                            }
                        }
                        EventAction::Pause if *current == MonitorState::Running => {
                            *current = MonitorState::Paused
                        }
                        _ => {}
                    }
                }
            }
        })
        .map_err(|error| MonitorError::WatcherInitError(error.to_string()))?;

        for path in &self.config.paths {
            if self.registered.contains(path) {
                continue;
            }
            match watch_path(&mut watcher, path) {
                Ok(()) => {
                    self.registered.insert(path.clone());
                }
                Err(error) => warn!("Could not monitor {}: {error}", path.display()),
            }
        }
        if self.registered.is_empty() {
            return Err(MonitorError::WatchPathError(
                "No watch paths could be registered".into(),
            ));
        }
        *self.stats.lock().unwrap() = MonitorStats {
            start_time: Some(chrono::Utc::now()),
            files_monitored: self.registered.len(),
            ..Default::default()
        };
        *self.watcher.lock().unwrap() = Some(watcher);
        *self.state.lock().unwrap() = MonitorState::Running;
        Ok(())
    }

    pub fn stop(&self) -> Result<(), MonitorError> {
        *self.state.lock().unwrap() = MonitorState::Stopped;
        self.watcher.lock().unwrap().take();
        Ok(())
    }

    pub fn pause(&self) -> Result<(), MonitorError> {
        *self.state.lock().unwrap() = MonitorState::Paused;
        Ok(())
    }

    pub fn resume(&self) -> Result<(), MonitorError> {
        *self.state.lock().unwrap() = MonitorState::Running;
        Ok(())
    }

    pub fn get_state(&self) -> MonitorState {
        *self.state.lock().unwrap()
    }

    pub fn get_stats(&self) -> MonitorStats {
        self.stats.lock().unwrap().clone()
    }

    pub fn increment_threats_detected(&self) {
        self.stats.lock().unwrap().threats_detected += 1;
    }

    /// Subscribe to future events. Clones share a 1024-event queue. If observers
    /// fall behind, new notifications still reach the primary callback.
    pub fn get_event_receiver(&self) -> Receiver<FileEvent> {
        self.subscribers.get_or_init(|| bounded(1024)).1.clone()
    }

    pub fn add_watch_path(&mut self, path: PathBuf) -> Result<(), MonitorError> {
        if !path.exists() {
            return Err(MonitorError::WatchPathError(path.display().to_string()));
        }
        if !self.registered.contains(&path) {
            if let Some(watcher) = self.watcher.lock().unwrap().as_mut() {
                watch_path(watcher, &path)?;
                self.registered.insert(path.clone());
                self.stats.lock().unwrap().files_monitored = self.registered.len();
            }
        }
        if !self.config.paths.contains(&path) {
            self.config.paths.push(path);
        }
        Ok(())
    }

    pub fn remove_watch_path(&mut self, path: &Path) -> Result<(), MonitorError> {
        if self.registered.contains(path) {
            if let Some(watcher) = self.watcher.lock().unwrap().as_mut() {
                watcher
                    .watcher()
                    .unwatch(path)
                    .map_err(|error| MonitorError::WatchPathError(error.to_string()))?;
                watcher.cache().remove_root(path);
            }
            self.registered.remove(path);
            self.stats.lock().unwrap().files_monitored = self.registered.len();
        }
        self.config.paths.retain(|watched| watched != path);
        Ok(())
    }
}

fn watch_path(watcher: &mut FileWatcher, path: &Path) -> Result<(), MonitorError> {
    let mode = if path.is_dir() {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };
    watcher
        .watcher()
        .watch(path, mode)
        .map_err(|error| MonitorError::WatchPathError(error.to_string()))?;
    watcher.cache().add_root(path, mode);
    Ok(())
}

fn file_event(event: Event, config: &MonitorConfig) -> Option<FileEvent> {
    let path = event.paths.first()?;
    let event_type = match event.kind {
        EventKind::Create(notify::event::CreateKind::Folder)
        | EventKind::Remove(notify::event::RemoveKind::Folder) => return None,
        EventKind::Create(_) | EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
            FileEventType::Created
        }
        EventKind::Remove(_) | EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
            FileEventType::Deleted
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            FileEventType::Renamed(event.paths.get(1)?.clone())
        }
        EventKind::Modify(_) => FileEventType::Modified,
        _ => return None,
    };

    // A rename into a monitored extension must be checked at its destination.
    let target = match &event_type {
        FileEventType::Renamed(destination) => destination,
        _ => path,
    };
    if config
        .ignore_paths
        .iter()
        .any(|excluded| target.starts_with(excluded))
    {
        return None;
    }
    if !config.extensions_filter.is_empty()
        && !target
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                config
                    .extensions_filter
                    .iter()
                    .any(|allowed| ext.eq_ignore_ascii_case(allowed))
            })
    {
        return None;
    }
    if let Ok(metadata) = target.metadata() {
        if metadata.is_dir() || metadata.len() > 100 * 1024 * 1024 {
            return None;
        }
    }
    Some(FileEvent {
        path: path.clone(),
        event_type,
        timestamp: chrono::Utc::now(),
        process_info: None,
    })
}

/// notify reports paths, not writer PIDs. Attach a process only when its image
/// or an argument names the file, using one native process snapshot per batch.
#[cfg(windows)]
fn with_process_info(mut event: FileEvent, snapshot: &mut Option<sysinfo::System>) -> FileEvent {
    use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};

    let target = match &event.event_type {
        FileEventType::Deleted => return event,
        FileEventType::Renamed(target) => target,
        _ => &event.path,
    };
    let processes = snapshot.get_or_insert_with(|| {
        let mut system = System::new();
        system.refresh_processes_specifics(ProcessRefreshKind::new());
        system
    });
    let path = target.to_string_lossy();
    event.process_info = processes
        .processes()
        .values()
        .find(|p| p.exe() == target || p.cmd().iter().any(|arg| arg.eq_ignore_ascii_case(&path)))
        .map(|p| ProcessInfo {
            pid: p.pid().as_u32(),
            name: p.name().to_owned(),
            path: p.exe().to_owned(),
            command_line: p.cmd().join(" "),
        });
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn receives_filtered_events_after_start_and_after_restart() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let ignored = root.join("excluded");
        fs::create_dir(&ignored).unwrap();
        let mut monitor = RealTimeMonitor::new(MonitorConfig {
            paths: vec![root.clone()],
            extensions_filter: vec!["txt".into()],
            ignore_paths: vec![ignored.clone()],
            event_delay_ms: 20,
        })
        .unwrap();
        let receiver = monitor.get_event_receiver();
        for name in ["first.TXT", "second.txt"] {
            let (tx, rx) = unbounded();
            monitor
                .start(move |event| {
                    tx.send(event.path).unwrap();
                    EventAction::Stop
                })
                .unwrap();
            fs::write(ignored.join("sample.txt"), b"ignored").unwrap();
            fs::write(root.join("other.bin"), b"ignored").unwrap();
            let expected = root.join(name);
            fs::write(&expected, b"test").unwrap();
            assert_eq!(rx.recv_timeout(Duration::from_secs(15)).unwrap(), expected);
            assert_eq!(
                receiver.recv_timeout(Duration::from_secs(15)).unwrap().path,
                expected
            );
            monitor.stop().unwrap();
            assert_eq!(monitor.get_state(), MonitorState::Stopped);
            assert_eq!(monitor.get_stats().events_processed, 1);
        }
    }

    #[test]
    fn handles_extension_changes_on_rename_and_files_without_extensions() {
        let config = MonitorConfig {
            extensions_filter: vec!["exe".into()],
            ..Default::default()
        };
        let rename = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path("download.tmp".into())
            .add_path("program.EXE".into());
        let event = file_event(rename, &config).unwrap();
        assert!(
            matches!(event.event_type, FileEventType::Renamed(p) if p == Path::new("program.EXE"))
        );
        let delete = Event::new(EventKind::Remove(notify::event::RemoveKind::File))
            .add_path("extensionless".into());
        assert!(file_event(delete.clone(), &config).is_none());
        assert!(matches!(
            file_event(delete, &MonitorConfig::default())
                .unwrap()
                .event_type,
            FileEventType::Deleted
        ));
    }

    #[test]
    fn monitors_paths_added_while_running() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        let mut monitor = RealTimeMonitor::new(MonitorConfig {
            paths: vec![first.path().to_owned()],
            event_delay_ms: 10,
            ..Default::default()
        })
        .unwrap();
        monitor.start(|_| EventAction::Continue).unwrap();
        monitor.pause().unwrap();
        assert_eq!(monitor.get_state(), MonitorState::Paused);
        monitor.resume().unwrap();
        let second_path = second.path().canonicalize().unwrap();
        monitor.add_watch_path(second_path.clone()).unwrap();
        monitor.remove_watch_path(first.path()).unwrap();
        let events = monitor.get_event_receiver();
        let expected = second_path.join("sample");
        fs::write(&expected, b"test").unwrap();
        assert_eq!(
            events.recv_timeout(Duration::from_secs(15)).unwrap().path,
            expected
        );
        assert_eq!(monitor.get_stats().files_monitored, 1);
        monitor.stop().unwrap();
    }
}
