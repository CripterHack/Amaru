//! A single per-user Windows scheduled scan, shared by the desktop and CLI.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Schedule {
    pub frequency: String,
    pub time: String,
    /// Sunday = 0, as in Windows Task Scheduler.
    pub day: u8,
    /// An explicit target belongs to the task. A task without one uses the quick-scan preferences.
    #[serde(default)]
    pub path: Option<PathBuf>,
}

impl Schedule {
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.frequency.as_str(), "daily" | "weekly")
            || self.day > 6
            || (self.frequency == "daily" && self.day != 0)
        {
            return Err("Choose a daily or weekly schedule and a valid weekday".into());
        }
        let time = chrono::NaiveTime::parse_from_str(&self.time, "%H:%M")
            .map_err(|_| "Use a local time from 00:00 to 23:59 in HH:mm format".to_owned())?;
        if time.format("%H:%M").to_string() != self.time {
            return Err("Use HH:mm format for the local time".into());
        }
        if let Some(path) = &self.path {
            if !path.is_absolute() || path.to_str().is_none() || !(path.is_file() || path.is_dir())
            {
                return Err(
                    "The schedule target must be an existing absolute file or directory".into(),
                );
            }
        }
        Ok(())
    }
}

/// Decode the fixed argument format used by the scheduled desktop process.
pub fn scheduled_path(mut args: impl Iterator<Item = String>) -> Result<Option<PathBuf>, String> {
    let Some(flag) = args.next() else {
        return Ok(None);
    };
    let value = args.next().ok_or("Missing encoded schedule path")?;
    if flag != "--path-base64" || args.next().is_some() {
        return Err("Unexpected arguments for a scheduled scan".into());
    }
    let bytes = STANDARD
        .decode(&value)
        .map_err(|_| "Invalid encoded schedule path")?;
    let decoded = String::from_utf8(bytes).map_err(|_| "Invalid schedule path encoding")?;
    if decoded.contains('\0') {
        return Err("Invalid schedule path encoding".into());
    }
    let path = PathBuf::from(decoded);
    if !path.is_absolute() {
        return Err("Scheduled scan requires an absolute path".into());
    }
    Ok(Some(path))
}

pub fn read(desktop: &Path) -> Result<Option<Schedule>, String> {
    invoke("read", desktop, None)
}

pub fn set(desktop: &Path, schedule: &Schedule) -> Result<Option<Schedule>, String> {
    schedule.validate()?;
    #[cfg(windows)]
    if !desktop.is_file() {
        return Err(format!("Desktop executable missing: {}", desktop.display()));
    }
    invoke("set", desktop, Some(schedule))
}

pub fn remove(desktop: &Path) -> Result<Option<Schedule>, String> {
    invoke("remove", desktop, None)
}

#[cfg(windows)]
fn invoke(
    mode: &str,
    desktop: &Path,
    schedule: Option<&Schedule>,
) -> Result<Option<Schedule>, String> {
    use std::{os::windows::process::CommandExt, process::Command};
    let windows_dir = std::env::var_os("SystemRoot").ok_or("Windows directory unavailable")?;
    let shell = Path::new(&windows_dir).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut command = Command::new(shell);
    command
        .creation_flags(0x08000000)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("schedule.ps1"),
        ])
        .env("AMARU_SCHEDULE_EXE", desktop)
        .env("AMARU_SCHEDULE_MODE", mode)
        .env_remove("AMARU_SCHEDULE_PATH");
    if let Some(schedule) = schedule {
        command
            .env("AMARU_SCHEDULE_FREQUENCY", &schedule.frequency)
            .env("AMARU_SCHEDULE_TIME", &schedule.time)
            .env("AMARU_SCHEDULE_DAY", schedule.day.to_string());
        if let Some(path) = &schedule.path {
            command.env("AMARU_SCHEDULE_PATH", path);
        }
    }
    let output = command.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().into());
    }
    serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
}

#[cfg(not(windows))]
fn invoke(_: &str, _: &Path, _: Option<&Schedule>) -> Result<Option<Schedule>, String> {
    Err("Scheduled scans require Windows Task Scheduler".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scheduled_destination_survives_spaces_and_unicode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("área de pruebas (1)");
        let args = vec![
            "--path-base64".into(),
            STANDARD.encode(path.to_str().unwrap().as_bytes()),
        ];
        assert_eq!(scheduled_path(args.into_iter()).unwrap(), Some(path));
        assert!(
            scheduled_path(["--path-base64".into(), STANDARD.encode("relative")].into_iter())
                .is_err()
        );
        assert_eq!(scheduled_path(std::iter::empty()).unwrap(), None);
    }
}
