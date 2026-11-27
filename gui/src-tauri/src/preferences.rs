use super::{load_engine, Desktop};
use crate::session;
use amaru::{
    quick_paths as locations,
    scheduler::{self, Schedule},
};
use std::{
    path::{Path, PathBuf},
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

#[command]
pub(super) async fn get_schedule() -> Result<Option<Schedule>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        scheduler::read(&std::env::current_exe().map_err(|e| e.to_string())?)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[command]
pub(super) async fn set_schedule(schedule: Option<Schedule>) -> Result<Option<Schedule>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        match schedule {
            Some(schedule) => scheduler::set(&exe, &schedule),
            None => scheduler::remove(&exe),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

pub(crate) fn run_scheduled() -> Result<(), String> {
    let context = tauri::generate_context!();
    let data = tauri::api::path::app_local_data_dir(context.config())
        .ok_or("Application data directory unavailable")?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let install = exe.parent().ok_or("Installation directory unavailable")?;
    let paths = match scheduler::scheduled_path(std::env::args().skip(2))? {
        Some(path) => vec![path],
        None => quick_paths(&data)?,
    };
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
