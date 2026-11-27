use amaru::{Amaru, AmaruError, ScanResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;
use walkdir::WalkDir;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Threat {
    pub session_id: Uuid,
    pub sha256: String,
    pub id: Uuid,
    pub name: String,
    pub path: PathBuf,
    pub risk_level: String,
    pub description: String,
    pub detected_at: DateTime<Utc>,
    pub in_quarantine: bool,
    pub action: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: Uuid,
    pub scan_type: String,
    pub status: String,
    pub start_time: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration: u64,
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub files_failed: u64,
    pub threats_found: usize,
    pub items_quarantined: usize,
    pub last_error: Option<String>,
    pub detected_threats: Vec<Threat>,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub id: Uuid,
    pub current_file: PathBuf,
    pub files_scanned: u64,
    pub files_skipped: u64,
    pub files_failed: u64,
    pub threats_found: usize,
    pub elapsed_ms: u64,
}

pub struct Job {
    pub progress: Progress,
    pub cancel: Arc<AtomicBool>,
}

impl Job {
    pub fn new() -> Self {
        Self {
            progress: Progress {
                id: Uuid::new_v4(),
                ..Progress::default()
            },
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

fn threat_from_file(file: ScanResult, session_id: Uuid) -> Option<Threat> {
    let details = file.threat_details?;
    let name = if details.matches.is_empty() {
        "Heuristic finding".into()
    } else {
        details.matches.join(", ")
    };
    Some(Threat {
        session_id,
        sha256: file.sha256.clone(),
        id: Uuid::new_v4(),
        name,
        path: file.path,
        risk_level: format!("{:?}", file.risk_level).to_lowercase(),
        description: format!("File SHA-256: {}", file.sha256),
        detected_at: Utc::now(),
        in_quarantine: false,
        action: "Detected".into(),
    })
}

pub async fn run(
    core: &Amaru,
    id: Uuid,
    kind: String,
    roots: Vec<PathBuf>,
    data_dir: &Path,
    cancel: &AtomicBool,
    mut report: impl FnMut(Progress),
    mut on_threat: impl FnMut(&Threat),
) -> Record {
    let start_time = Utc::now();
    let started = Instant::now();
    let mut progress = Progress {
        id,
        ..Progress::default()
    };
    let mut threats = Vec::new();
    let mut last_error = None;
    let mut last_report = started;
    let excluded = &core.config().scan_config.exclude_paths;
    'paths: for root in roots {
        let entries = WalkDir::new(root)
            .follow_root_links(false)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                let p = entry.path();
                !p.starts_with(data_dir)
                    && !p.starts_with(&core.config().quarantine_config.quarantine_path)
                    && !excluded.iter().any(|prefix| p.starts_with(prefix))
            });
        for item in entries {
            if cancel.load(Ordering::Acquire) {
                break 'paths;
            }
            let entry = match item {
                Ok(entry) => entry,
                Err(error) => {
                    progress.files_failed += 1;
                    last_error = Some(error.to_string());
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            progress.current_file = entry.path().into();
            match core.scan_file(entry.path()).await {
                Ok(file) => {
                    progress.files_scanned += 1;
                    if let Some(threat) = threat_from_file(file, id) {
                        on_threat(&threat);
                        threats.push(threat);
                        progress.threats_found = threats.len();
                    }
                }
                Err(AmaruError::FileTooLarge(_)) => progress.files_skipped += 1,
                Err(error) => {
                    progress.files_failed += 1;
                    last_error = Some(format!("{}: {error}", entry.path().display()));
                }
            }
            progress.elapsed_ms = started.elapsed().as_millis() as u64;
            if last_report.elapsed() >= Duration::from_millis(150) {
                report(progress.clone());
                last_report = Instant::now();
            }
        }
    }
    let status = if cancel.load(Ordering::Acquire) {
        "cancelled"
    } else if progress.files_failed > 0 {
        "partial"
    } else {
        "completed"
    };
    progress.elapsed_ms = started.elapsed().as_millis() as u64;
    report(progress.clone());
    Record {
        id,
        scan_type: kind,
        status: status.into(),
        start_time,
        completed_at: Utc::now(),
        duration: progress.elapsed_ms,
        files_scanned: progress.files_scanned,
        files_failed: progress.files_failed,
        files_skipped: progress.files_skipped,
        threats_found: threats.len(),
        items_quarantined: 0,
        last_error,
        detected_threats: threats,
    }
}

pub fn save(dir: &Path, record: &Record) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    serde_json::to_writer(&mut file, record)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(dir.join(format!("{}.json", record.id)))?;
    Ok(())
}

pub fn history(dir: &Path) -> io::Result<Vec<Record>> {
    let mut records = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(records),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            records.push(serde_json::from_reader(fs::File::open(path)?)?);
        }
    }
    records.sort_by_key(|r| std::cmp::Reverse(r.start_time));
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use amaru::Config;

    #[tokio::test]
    async fn session_reports_real_files_preserves_history_and_respects_cancel() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("samples");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("clean"), "ordinary text").unwrap();
        fs::write(
            source.join("sample"),
            include_bytes!("../../../test-eicar.txt"),
        )
        .unwrap();
        fs::write(source.join("large"), vec![0u8; 2048]).unwrap();

        let mut config = Config::default();
        config.monitored_paths.clear();
        config.heuristic_analysis = false;
        config.yara_rules_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../signatures");
        config.quarantine_config.quarantine_path = temp.path().join("quarantine");
        config.scan_config.max_file_size = 1024;
        let core = Amaru::new(config).await.unwrap();
        let data = temp.path().join("desktop");
        let cancel = AtomicBool::new(false);
        let id = Uuid::new_v4();
        let mut count = 0;
        let mut latest = Progress::default();
        let record = run(
            &core,
            id,
            "custom".into(),
            vec![source.clone(), source.join("missing")],
            &data,
            &cancel,
            |p| latest = p,
            |_| count += 1,
        )
        .await;
        assert_eq!(
            (
                record.files_scanned,
                record.files_skipped,
                record.files_failed,
                count
            ),
            (2, 1, 1, 1)
        );
        assert_eq!(record.status, "partial");
        assert_eq!((latest.files_scanned, latest.threats_found), (2, 1));
        let detection = &record.detected_threats[0];
        assert_eq!(detection.session_id, id);
        assert_eq!(detection.path, source.join("sample"));
        assert!(!detection.in_quarantine);
        assert!(detection.path.exists());
        save(&data, &record).unwrap();
        assert!(save(&data, &record).is_err());
        let stored = history(&data).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].detected_threats[0].sha256, detection.sha256);
        cancel.store(true, Ordering::Release);
        let cancelled = run(
            &core,
            Uuid::new_v4(),
            "quick".into(),
            vec![source],
            &data,
            &cancel,
            |_| (),
            |_| (),
        )
        .await;
        assert_eq!(cancelled.status, "cancelled");
        assert_eq!(cancelled.files_scanned, 0);
    }
}
