//! Administración local del servicio de protección mediante el SCM de Windows.
use std::{
    ffi::OsString,
    io,
    path::PathBuf,
    ptr, thread,
    time::{Duration, Instant},
};
use winapi::um::{
    winnt::{SERVICE_AUTO_START, SERVICE_DEMAND_START},
    winsvc,
};
use windows_service::{
    service::{
        Service, ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
    Error, Result,
};

pub(super) const SERVICE_NAME: &str = "AmaruAntivirus";
const WAIT_LIMIT: Duration = Duration::from_secs(30);

fn service_info(executable_path: PathBuf) -> ServiceInfo {
    ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: "Amaru Antivirus Real-time Protection".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path,
        launch_arguments: vec![OsString::from("service-run")],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    }
}

pub fn install_service() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let info = service_info(std::env::current_exe().map_err(Error::Winapi)?);
    let service =
        manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::DELETE)?;
    if let Err(err) = service
        .set_description("Provides real-time protection against malware and suspicious activity")
    {
        service.delete()?;
        return Err(err);
    }
    Ok(())
}

fn open(access: ServiceAccess) -> Result<Service> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    manager.open_service(SERVICE_NAME, access | ServiceAccess::QUERY_STATUS)
}

fn settled(service: &Service) -> Result<ServiceStatus> {
    let start = Instant::now();
    loop {
        let status = service.query_status()?;
        if !matches!(
            status.current_state,
            ServiceState::StartPending
                | ServiceState::StopPending
                | ServiceState::PausePending
                | ServiceState::ContinuePending
        ) {
            return Ok(status);
        }
        if start.elapsed() >= WAIT_LIMIT {
            return Err(Error::Winapi(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "Timed out waiting for {SERVICE_NAME} ({:?})",
                    status.current_state
                ),
            )));
        }
        thread::sleep(
            (status.wait_hint / 10).clamp(Duration::from_millis(100), Duration::from_secs(1)),
        );
    }
}

fn require_state(service: &Service, expected: ServiceState) -> Result<()> {
    let status = settled(service)?;
    if status.current_state == expected {
        Ok(())
    } else {
        Err(Error::Winapi(io::Error::other(format!(
            "{SERVICE_NAME}: expected {expected:?}, found {:?} (exit {:?})",
            status.current_state, status.exit_code
        ))))
    }
}

fn start(service: &Service) -> Result<()> {
    match settled(service)?.current_state {
        ServiceState::Running => return Ok(()),
        ServiceState::Stopped => match service.start::<&str>(&[]) {
            Ok(()) => {}
            Err(Error::Winapi(err)) if err.raw_os_error() == Some(1056) => {} // ERROR_SERVICE_ALREADY_RUNNING
            Err(err) => return Err(err),
        },
        state => {
            return Err(Error::Winapi(io::Error::other(format!(
                "Cannot start service in state {state:?}"
            ))))
        }
    }
    require_state(service, ServiceState::Running)
}

fn stop(service: &Service) -> Result<()> {
    if settled(service)?.current_state == ServiceState::Stopped {
        return Ok(());
    }
    match service.stop() {
        Ok(_) => {}
        Err(Error::Winapi(err)) if err.raw_os_error() == Some(1062) => {} // ERROR_SERVICE_NOT_ACTIVE
        Err(err) => return Err(err),
    }
    require_state(service, ServiceState::Stopped)
}

pub fn start_service() -> Result<()> {
    start(&open(ServiceAccess::START)?)
}
pub fn stop_service() -> Result<()> {
    stop(&open(ServiceAccess::STOP)?)
}
pub fn restart_service() -> Result<()> {
    let service = open(ServiceAccess::START | ServiceAccess::STOP)?;
    stop(&service)?;
    start(&service)
}
pub fn get_service_status() -> Result<ServiceStatus> {
    open(ServiceAccess::QUERY_STATUS)?.query_status()
}

pub fn uninstall_service() -> Result<()> {
    let service = match open(ServiceAccess::STOP | ServiceAccess::DELETE) {
        Ok(service) => service,
        Err(Error::Winapi(err)) if err.raw_os_error() == Some(1060) => return Ok(()), // ERROR_SERVICE_DOES_NOT_EXIST
        Err(err) => return Err(err),
    };
    stop(&service)?;
    service.delete()
}

struct ScHandle(winsvc::SC_HANDLE);
impl ScHandle {
    fn new(raw: winsvc::SC_HANDLE) -> Result<Self> {
        if raw.is_null() {
            Err(Error::Winapi(io::Error::last_os_error()))
        } else {
            Ok(Self(raw))
        }
    }
}
impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            winsvc::CloseServiceHandle(self.0);
        }
    }
}

pub fn set_autostart(enabled: bool) -> Result<()> {
    let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    // windows-service 0.5 change_config requires resubmitting account, ImagePath and dependencies.
    // Keep those fields under SCM control and change only the startup type.
    unsafe {
        let manager = ScHandle::new(winsvc::OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            winsvc::SC_MANAGER_CONNECT,
        ))?;
        let service = ScHandle::new(winsvc::OpenServiceW(
            manager.0,
            name.as_ptr(),
            winsvc::SERVICE_CHANGE_CONFIG,
        ))?;
        let succeeded = winsvc::ChangeServiceConfigW(
            service.0,
            winsvc::SERVICE_NO_CHANGE,
            if enabled {
                SERVICE_AUTO_START
            } else {
                SERVICE_DEMAND_START
            },
            winsvc::SERVICE_NO_CHANGE,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );
        if succeeded == 0 {
            return Err(Error::Winapi(io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scm_launches_the_installed_executable_in_service_mode() {
        let exe = PathBuf::from(r"C:\Program Files\Amaru\amaru.exe");
        let config = service_info(exe.clone());
        assert_eq!(config.executable_path, exe);
        assert_eq!(config.launch_arguments, [OsString::from("service-run")]);
        assert_eq!(config.name, SERVICE_NAME);
    }
}
