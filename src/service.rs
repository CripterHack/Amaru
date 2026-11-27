//! Windows Service Control Manager entry points and the local administrative pipe.
use crate::{
    ipc::{
        self, IpcCommand, IpcError, IpcResponse, MAX_COMMAND_BYTES, MAX_RESPONSE_BYTES, PIPE_NAME,
        STATUS_PIPE_NAME,
    },
    Amaru, Config,
};
use std::{
    cell::RefCell,
    ffi::OsString,
    io, mem,
    path::{Path, PathBuf},
    ptr,
    rc::Rc,
    sync::OnceLock,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    sync::{watch, RwLock},
    task::{JoinSet, LocalSet},
};
use winapi::{
    shared::sddl::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
    um::{minwinbase::SECURITY_ATTRIBUTES, winbase::LocalFree},
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher, Error, Result,
};

mod scan;
mod scm;
use scm::SERVICE_NAME;
pub use scm::{
    get_service_status, install_service, is_autostart_enabled, restart_service, set_autostart,
    start_service, stop_service, uninstall_service,
};

pub struct ServiceConfig {
    pub yara_rules_path: String,
    pub monitored_paths: Vec<String>,
    pub auto_quarantine: bool,
}

static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();
pub struct AmaruService;
impl AmaruService {
    pub fn run(config_path: &str) -> Result<()> {
        CONFIG_PATH
            .set(std::path::absolute(config_path).map_err(Error::Winapi)?)
            .map_err(|_| {
                Error::Winapi(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "Service already configured",
                ))
            })?;
        run_service()
    }
}

define_windows_service!(ffi_service_main, service_main);

pub fn run_service() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

pub fn run() -> Result<()> {
    run_service()
}

fn report(
    handle: &ServiceStatusHandle,
    state: ServiceState,
    checkpoint: u32,
    exit_code: ServiceExitCode,
) -> Result<()> {
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint,
        wait_hint: if checkpoint > 0 {
            Duration::from_secs(30)
        } else {
            Duration::ZERO
        },
        process_id: None,
    })
}

fn service_main(_: Vec<OsString>) {
    if let Err(err) = run_registered() {
        log::error!("Amaru service stopped with an error: {err}");
    }
}

fn run_registered() -> Result<()> {
    let (stop, stopping) = watch::channel(false);
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop.send_replace(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    report(
        &handle,
        ServiceState::StartPending,
        1,
        ServiceExitCode::Win32(0),
    )?;
    let outcome = (|| {
        let path = match CONFIG_PATH.get() {
            Some(path) => path.clone(),
            None => std::env::current_exe()?.with_file_name("config.toml"),
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        LocalSet::new().block_on(&runtime, serve(&path, stopping, &handle))
    })();
    let code = if outcome.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    report(&handle, ServiceState::Stopped, 0, code)?;
    outcome.map_err(Error::Winapi)
}

fn create_pipe(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    // Administrative commands can move files and change protection. Only elevated local
    // administrators and SYSTEM may open this pipe. The first instance reserves the name.
    let public_status = name == STATUS_PIPE_NAME;
    let acl = if public_status {
        // GR permits reading. It does not include FILE_CREATE_PIPE_INSTANCE.
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)"
    } else {
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
    };
    let sddl: Vec<u16> = acl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = ptr::null_mut();
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1.into(),
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let pipe = ServerOptions::new()
            .first_pipe_instance(first)
            .access_inbound(!public_status)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            );
        LocalFree(descriptor.cast());
        pipe
    }
}

fn take_connection(
    listener: &mut NamedPipeServer,
    name: &str,
    connection: io::Result<()>,
) -> io::Result<Option<NamedPipeServer>> {
    // A peer can close between opening its handle and completion of ConnectNamedPipe.
    let connected = match connection {
        Ok(()) => true,
        Err(err) if matches!(err.raw_os_error(), Some(109 | 232 | 233)) => false,
        Err(err) => return Err(err),
    };
    let previous = mem::replace(listener, create_pipe(name, false)?);
    Ok(connected.then_some(previous))
}

struct Context {
    amaru: RwLock<Amaru>,
    config: Config,
    started: Instant,
    scan: RefCell<scan::Session>,
    resources: RefCell<sysinfo::System>,
}

async fn serve(
    path: &Path,
    mut stopping: watch::Receiver<bool>,
    handle: &ServiceStatusHandle,
) -> io::Result<()> {
    use sysinfo::SystemExt;
    let mut config = Config::load(path)?;
    // SCM's current directory is usually System32. Resolve every relative service path
    // against the configuration file just as an installed launch from the app directory would.
    let base = path.parent().unwrap_or(Path::new("."));
    config.yara_rules_path = base.join(&config.yara_rules_path);
    config.quarantine_config.quarantine_path = base.join(&config.quarantine_config.quarantine_path);
    for path in config
        .monitored_paths
        .iter_mut()
        .chain(&mut config.scan_config.exclude_paths)
    {
        *path = base.join(&*path);
    }
    let mut server = create_pipe(PIPE_NAME, true)?;
    let mut public_status = create_pipe(STATUS_PIPE_NAME, true)?;
    report(
        handle,
        ServiceState::StartPending,
        2,
        ServiceExitCode::Win32(0),
    )
    .map_err(io::Error::other)?;
    let mut engine = Amaru::from_config_with_radare2(config.clone(), |analyzer| {
        let binary = analyzer.executable_path();
        let allowed = binary.parent().is_some_and(|dir| {
            scm::validate_install_directory(dir)
                .inspect_err(|err| {
                    log::warn!("Service skipped Radare2 at {}: {err}", binary.display())
                })
                .is_ok()
        });
        if allowed {
            analyzer.restrict_dependency_search();
        }
        allowed
    })
    .map_err(io::Error::other)?;
    engine
        .init_core_services()
        .await
        .map_err(io::Error::other)?;
    report(
        handle,
        ServiceState::StartPending,
        3,
        ServiceExitCode::Win32(0),
    )
    .map_err(io::Error::other)?;
    if config.realtime_protection {
        engine
            .enable_realtime_protection()
            .await
            .map_err(io::Error::other)?;
    }
    let state = Rc::new(Context {
        amaru: RwLock::new(engine),
        config,
        started: Instant::now(),
        scan: RefCell::new(scan::Session::default()),
        resources: RefCell::new(sysinfo::System::new()),
    });
    report(handle, ServiceState::Running, 0, ServiceExitCode::Win32(0))
        .map_err(io::Error::other)?;
    let mut clients = JoinSet::new();
    let mut readers = JoinSet::new();
    let (stop_clients, clients_stopping) = watch::channel(false);
    let mut result = Ok(());
    loop {
        tokio::select! {
            biased;
            _ = stopping.changed() => break,
            Some(outcome) = clients.join_next(), if !clients.is_empty() => {
                if let Err(err) = outcome { log::error!("IPC task: {err}"); }
            }
            connection = server.connect(), if clients.len() < 32 => {
                match take_connection(&mut server, PIPE_NAME, connection) {
                    Ok(Some(pipe)) => { clients.spawn_local(serve_client(pipe, state.clone(), clients_stopping.clone())); }
                    Ok(None) => {}
                    Err(err) => { result = Err(err); break; }
                }
            }
            Some(_) = readers.join_next(), if !readers.is_empty() => {}
            connection = public_status.connect(), if readers.len() < 8 => {
                match take_connection(&mut public_status, STATUS_PIPE_NAME, connection) {
                    Ok(Some(mut pipe)) => {
                        let state = state.clone();
                        readers.spawn_local(async move {
                            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                                let enabled = state.amaru.read().await.realtime_enabled();
                                pipe.write_u8(u8::from(enabled)).await
                            }).await;
                        });
                    }
                    Ok(None) => {}
                    Err(err) => { result = Err(err); break; }
                }
            }
        }
    }
    drop(server);
    drop(public_status);
    readers.abort_all();
    report(
        handle,
        ServiceState::StopPending,
        1,
        ServiceExitCode::Win32(0),
    )
    .map_err(io::Error::other)?;
    // Stop issuing new commands, finish any command already operating on files, then stop monitoring.
    stop_clients.send_replace(true);
    let finish = async {
        while clients.join_next().await.is_some() {}
        let scan_task = state.scan.borrow_mut().shutdown();
        if let Some(task) = scan_task {
            task.await.map_err(io::Error::other)?;
        }
        state
            .amaru
            .write()
            .await
            .disable_realtime_protection()
            .await
            .map_err(io::Error::other)
    };
    tokio::pin!(finish);
    let mut checkpoint = 1;
    loop {
        tokio::select! {
            stopped = &mut finish => { stopped?; return result; }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                checkpoint += 1;
                report(handle, ServiceState::StopPending, checkpoint, ServiceExitCode::Win32(0)).map_err(io::Error::other)?;
            }
        }
    }
}

async fn serve_client(
    mut pipe: NamedPipeServer,
    state: Rc<Context>,
    mut stopping: watch::Receiver<bool>,
) {
    while !*stopping.borrow() {
        let command = tokio::select! {
            biased;
            _ = stopping.changed() => return,
            result = ipc::read_json(&mut pipe, MAX_COMMAND_BYTES) => match result {
                Ok(command) => command,
                Err(IpcError::ConnectionClosed) => return,
                Err(err) => { log::debug!("Invalid IPC request: {err}"); return; }
            }
        };
        let response = handle_command(&state, command)
            .await
            .unwrap_or_else(|err| IpcResponse::Error(err.to_string()));
        let bytes = match serde_json::to_vec(&response) {
            Ok(bytes) if bytes.len() <= MAX_RESPONSE_BYTES => bytes,
            _ => serde_json::to_vec(&IpcResponse::Error(
                "Response exceeds the IPC size limit".into(),
            ))
            .unwrap(),
        };
        tokio::select! {
            _ = stopping.changed() => return,
            result = pipe.write_all(&bytes) => if result.is_err() { return; }
        }
    }
}

async fn realtime_status(state: &Context) -> IpcResponse {
    let enabled = state.amaru.read().await.realtime_enabled();
    IpcResponse::RealtimeStatus {
        enabled,
        monitored_paths: if enabled {
            state
                .config
                .monitored_paths
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect()
        } else {
            Vec::new()
        },
    }
}

fn absolute_request_path(value: &str) -> io::Result<&Path> {
    let path = Path::new(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "An absolute file path is required",
        ))
    }
}

async fn handle_command(
    state: &Rc<Context>,
    command: IpcCommand,
) -> std::result::Result<IpcResponse, Box<dyn std::error::Error>> {
    Ok(match command {
        IpcCommand::GetStatus => {
            let stats = state.amaru.read().await.monitor_stats();
            let monitor_threats = stats.as_ref().map_or(0, |s| s.threats_detected);
            IpcResponse::Status {
                is_running: true,
                uptime_secs: state.started.elapsed().as_secs(),
                files_monitored: stats.map_or(0, |s| s.files_monitored),
                threats_detected: monitor_threats + state.scan.borrow().threats_detected,
            }
        }
        IpcCommand::GetRealtimeStatus => realtime_status(state).await,
        IpcCommand::GetScanProgress => state.scan.borrow().response(),
        IpcCommand::StartScan { path } => {
            scan::start(state, PathBuf::from(path)).await?;
            IpcResponse::Ok
        }
        IpcCommand::StopScan => {
            state.scan.borrow_mut().request_cancel()?;
            IpcResponse::Ok
        }
        IpcCommand::GetServiceStats => {
            use sysinfo::{ProcessExt, SystemExt};
            let pid = sysinfo::get_current_pid().map_err(io::Error::other)?;
            let mut resources = state.resources.borrow_mut();
            resources.refresh_process(pid);
            let process = resources
                .process(pid)
                .ok_or_else(|| io::Error::other("Service metrics unavailable"))?;
            IpcResponse::ServiceStats {
                cpu_usage: process.cpu_usage(),
                memory_usage: process.memory(),
                scan_queue_size: state.scan.borrow().pending(),
            }
        }
        IpcCommand::IntegratedScan { path } => IpcResponse::IntegratedScanResult(
            state
                .amaru
                .read()
                .await
                .integrated_scan_file(absolute_request_path(&path)?)
                .await?,
        ),
        IpcCommand::UpdateRules => {
            state.amaru.read().await.update_yara_rules().await?;
            IpcResponse::Ok
        }
        IpcCommand::EnableIntegratedRealtime | IpcCommand::DisableIntegratedRealtime => {
            let mut engine = state.amaru.write().await;
            match command {
                IpcCommand::EnableIntegratedRealtime => engine.enable_realtime_protection().await?,
                _ => engine.disable_realtime_protection().await?,
            }
            drop(engine);
            realtime_status(state).await
        }
        IpcCommand::CheckUpdates => {
            let available = state.amaru.read().await.check_core_updates().await?;
            IpcResponse::UpdateStatus {
                available,
                component: available.then(|| "YARA Rules".into()),
                version: None,
                size: None,
            }
        }
        IpcCommand::QuarantineFile { path, reason } => {
            state
                .amaru
                .read()
                .await
                .integrated_quarantine_file(absolute_request_path(&path)?, &reason)
                .await?;
            IpcResponse::Ok
        }
        IpcCommand::RestoreFromQuarantine { entry_id } => {
            state
                .amaru
                .read()
                .await
                .integrated_restore_file(&entry_id)
                .await?;
            IpcResponse::Ok
        }
        IpcCommand::DeleteQuarantinedFile { entry_id } => {
            state
                .amaru
                .read()
                .await
                .quarantine()
                .delete_file_by_id(&entry_id)?;
            IpcResponse::Ok
        }
        IpcCommand::GetQuarantineList => {
            let entries = state.amaru.read().await.quarantine().list_entries()?;
            IpcResponse::QuarantineList(
                entries
                    .into_iter()
                    .map(|entry| ipc::QuarantineEntry {
                        id: entry.quarantine_name,
                        original_path: entry.original_path.to_string_lossy().into_owned(),
                        reason: entry.reason,
                        quarantine_date: entry.quarantine_date,
                        file_size: entry.file_size,
                        hash: entry.original_hash,
                    })
                    .collect(),
            )
        }
    })
}
