//! One cancellable on-demand scan shared by all administrative IPC connections.
use super::Context;
use crate::ipc::IpcResponse;
use std::{
    io,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
    rc::Rc,
};
use tokio::{fs, task::JoinHandle};

#[derive(Default)]
pub(super) struct Session {
    active: bool,
    start_time: Option<chrono::DateTime<chrono::Utc>>,
    cancelled: bool,
    total: usize,
    scanned: usize,
    failed: usize,
    skipped: usize,
    detections: usize,
    quarantined: usize,
    current: String,
    last_error: Option<String>,
    task: Option<JoinHandle<()>>,
    pub(super) threats_detected: usize,
}

impl Session {
    pub(super) fn request_cancel(&mut self) -> io::Result<()> {
        if !self.active {
            return Err(io::Error::new(io::ErrorKind::NotFound, "No active scan"));
        }
        self.cancelled = true;
        Ok(())
    }

    pub(super) fn shutdown(&mut self) -> Option<JoinHandle<()>> {
        self.cancelled = true;
        self.task.take()
    }

    pub(super) fn pending(&self) -> usize {
        if self.active {
            self.total
                .saturating_sub(self.scanned + self.failed + self.skipped)
        } else {
            0
        }
    }

    pub(super) fn response(&self) -> IpcResponse {
        if self.active {
            IpcResponse::ScanProgress {
                start_time: self.start_time.expect("active scan has a start time"),
                files_scanned: self.scanned,
                files_total: self.total,
                current_file: self.current.clone(),
            }
        } else if self.start_time.is_some() {
            IpcResponse::ScanFinished {
                files_scanned: self.scanned,
                files_total: self.total,
                files_failed: self.failed,
                files_skipped: self.skipped,
                threats_detected: self.detections,
                quarantined: self.quarantined,
                cancelled: self.cancelled,
                last_error: self.last_error.clone(),
            }
        } else {
            IpcResponse::ScanIdle
        }
    }

    fn failure(&mut self, path: &Path, err: impl std::fmt::Display) {
        self.failed += 1;
        self.last_error = Some(format!("{}: {err}", path.display()));
    }
}

pub(super) async fn start(state: &Rc<Context>, root: PathBuf) -> io::Result<()> {
    if !root.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Service scans require an absolute path",
        ));
    }
    fs::symlink_metadata(&root).await?;
    let mut session = state.scan.borrow_mut();
    if session.active {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "A scan is already running",
        ));
    }
    *session = Session {
        active: true,
        start_time: Some(chrono::Utc::now()),
        current: root.display().to_string(),
        threats_detected: session.threats_detected,
        ..Session::default()
    };
    let state = state.clone();
    session.task = Some(tokio::task::spawn_local(async move {
        run(&state, root).await;
        let mut session = state.scan.borrow_mut();
        session.current.clear();
        session.active = false;
    }));
    Ok(())
}

async fn run(state: &Context, root: PathBuf) {
    let mut directories = vec![root.clone()];
    let mut files = Vec::new();
    // Enumerate first so the progress denominator and the queue cover the same candidates.
    // Never descend through a junction or other reparse point.
    while let Some(path) = directories.pop() {
        if state.scan.borrow().cancelled {
            return;
        }
        let metadata = match fs::symlink_metadata(&path).await {
            Ok(metadata) => metadata,
            Err(err) => {
                let mut scan = state.scan.borrow_mut();
                scan.total += 1;
                scan.failure(&path, err);
                continue;
            }
        };
        let excluded = state
            .config
            .scan_config
            .exclude_paths
            .iter()
            .any(|p| path.starts_with(p))
            || path.starts_with(&state.config.quarantine_config.quarantine_path);
        if metadata.file_attributes() & 0x400 != 0 || excluded {
            let mut scan = state.scan.borrow_mut();
            scan.total += 1;
            scan.skipped += 1;
        } else if metadata.is_dir() {
            let result: io::Result<()> = async {
                let mut entries = fs::read_dir(&path).await?;
                while let Some(entry) = entries.next_entry().await? {
                    if state.scan.borrow().cancelled {
                        break;
                    }
                    directories.push(entry.path());
                }
                Ok(())
            }
            .await;
            if let Err(err) = result {
                let mut scan = state.scan.borrow_mut();
                scan.total += 1;
                scan.failure(&path, err);
            }
        } else {
            let config = &state.config.scan_config;
            let matching_extension = config.scan_extensions.is_empty()
                || path
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|ext| {
                        config.scan_extensions.iter().any(|allowed| {
                            ext.eq_ignore_ascii_case(allowed.trim_start_matches('.'))
                        })
                    });
            let mut scan = state.scan.borrow_mut();
            scan.total += 1;
            // An explicitly selected file can be scanned regardless of its extension.
            if metadata.is_file()
                && metadata.len() <= config.max_file_size
                && (path == root || matching_extension)
            {
                files.push(path);
            } else {
                scan.skipped += 1;
            }
        }
    }
    for path in files {
        if state.scan.borrow().cancelled {
            return;
        }
        state.scan.borrow_mut().current = path.display().to_string();
        let engine = state.amaru.read().await;
        match engine.scan_file(&path).await {
            Ok(result) => {
                let detected = result.threat_details.is_some();
                {
                    let mut scan = state.scan.borrow_mut();
                    scan.scanned += 1;
                    if detected {
                        scan.detections += 1;
                        scan.threats_detected += 1;
                    }
                }
                if detected
                    && !state.scan.borrow().cancelled
                    && state.config.should_auto_quarantine(result.risk_level)
                {
                    let reason = format!("Amaru scan: {:?} risk", result.risk_level);
                    match engine.quarantine_detected(&result, &reason) {
                        Ok(_) => state.scan.borrow_mut().quarantined += 1,
                        Err(err) => {
                            state.scan.borrow_mut().last_error =
                                Some(format!("Quarantine {}: {err}", path.display()))
                        }
                    }
                }
            }
            Err(crate::AmaruError::FileTooLarge(_)) => state.scan.borrow_mut().skipped += 1,
            Err(err) => state.scan.borrow_mut().failure(&path, err),
        }
        tokio::task::yield_now().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_scan_distinguishes_detections_and_quarantine() {
        let scan = Session {
            start_time: Some(chrono::Utc::now()),
            total: 4,
            scanned: 2,
            failed: 1,
            skipped: 1,
            detections: 1,
            quarantined: 0,
            ..Session::default()
        };
        assert!(matches!(
            scan.response(),
            IpcResponse::ScanFinished {
                files_scanned: 2,
                files_failed: 1,
                files_skipped: 1,
                threats_detected: 1,
                quarantined: 0,
                ..
            }
        ));
    }
}
