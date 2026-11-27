use super::{load_engine, Desktop};
use crate::{quick_paths as locations, session};
use serde::{Deserialize, Serialize};
use std::{
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicBool, Arc},
};
use tauri::{command, State};

pub(super) fn quick_paths(data: &Path) -> Result<Vec<PathBuf>, String> {
    locations::read(data).map_err(|e| e.to_string())
}

#[command]
pub(super) fn get_quick_paths(state: State<'_, Arc<Desktop>>) -> Result<Vec<PathBuf>, String> {
    quick_paths(&state.data)
}

#[command]
pub(super) fn save_quick_paths(
    paths: Option<Vec<PathBuf>>,
    state: State<'_, Arc<Desktop>>,
) -> Result<Vec<PathBuf>, String> {
    locations::save(&state.data, paths).map_err(|e| e.to_string())
}

#[derive(Serialize, Deserialize)]
pub(super) struct Schedule {
    frequency: String,
    time: String,
    day: u8,
}

async fn scheduler(
    mode: &'static str,
    schedule: Option<Schedule>,
) -> Result<Option<Schedule>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let executable = std::env::current_exe().map_err(|e| e.to_string())?;
        let windows_dir = std::env::var_os("SystemRoot").ok_or("Windows directory unavailable")?;
        let shell = Path::new(&windows_dir).join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
        let mut command = Command::new(shell);
        command
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                include_str!("schedule.ps1"),
            ])
            .env("AMARU_SCHEDULE_EXE", executable)
            .env("AMARU_SCHEDULE_MODE", mode);
        if let Some(schedule) = schedule {
            if !matches!(schedule.frequency.as_str(), "daily" | "weekly") || schedule.day > 6 {
                return Err("Choose a daily or weekly schedule and a valid weekday".into());
            }
            let time = chrono::NaiveTime::parse_from_str(&schedule.time, "%H:%M")
                .map_err(|e| e.to_string())?;
            command
                .env("AMARU_SCHEDULE_FREQUENCY", schedule.frequency)
                .env("AMARU_SCHEDULE_TIME", time.format("%H:%M").to_string())
                .env("AMARU_SCHEDULE_DAY", schedule.day.to_string());
        }
        let output = command.output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }
        serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[command]
pub(super) async fn get_schedule() -> Result<Option<Schedule>, String> {
    scheduler("read", None).await
}

#[command]
pub(super) async fn set_schedule(schedule: Option<Schedule>) -> Result<Option<Schedule>, String> {
    scheduler(if schedule.is_some() { "set" } else { "remove" }, schedule).await
}

pub(crate) fn run_scheduled() -> Result<(), String> {
    let context = tauri::generate_context!();
    let data = tauri::api::path::app_local_data_dir(context.config())
        .ok_or("Application data directory unavailable")?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let install = exe.parent().ok_or("Installation directory unavailable")?;
    let paths = quick_paths(&data)?;
    if paths.is_empty() {
        return Err("No quick scan locations are available".into());
    }
    tauri::async_runtime::block_on(async {
        let engine = load_engine(install, &data).await?;
        let record = session::run(
            &engine,
            uuid::Uuid::new_v4(),
            "scheduled".into(),
            paths,
            &data,
            &AtomicBool::new(false),
            |_| {},
            |_| {},
        )
        .await;
        session::save(&data.join("history"), &record).map_err(|e| e.to_string())?;
        if record.status != "completed" {
            return Err(record.last_error.unwrap_or(record.status));
        }
        Ok(())
    })
}
