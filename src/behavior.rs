use dashmap::DashMap;
use object::{
    read::pe::{ImageNtHeaders, Import, PeFile, ResourceNameOrId},
    Object, ObjectSection,
};
use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use thiserror::Error;

/// Tipos de comportamientos maliciosos conocidos
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MaliciousBehaviorType {
    /// Inyección de código en otros procesos
    ProcessInjection,
    /// Persistencia en el sistema
    SystemPersistence,
    /// Evasión de detección
    DetectionEvasion,
    /// Ransomware
    Ransomware,
    /// Keylogger
    Keylogger,
    /// Robo de información
    DataExfiltration,
    /// Comunicación con C&C
    CommandAndControl,
    /// Escalación de privilegios
    PrivilegeEscalation,
    /// Anti-depuración
    AntiDebug,
    /// Anti-VM
    AntiVM,
    /// Rootkit
    Rootkit,
    /// CryptoMiner
    CryptoMiner,
    /// Advanced Persistent Threat
    AdvancedPersistentThreat,
    /// Empaquetado
    Packing,
    /// Test file
    TestFile,
}

/// Detalles de un comportamiento malicioso
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaliciousBehavior {
    /// Tipo de comportamiento
    pub behavior_type: MaliciousBehaviorType,
    /// Descripción del comportamiento
    pub description: String,
    /// Nivel de confianza (0-100)
    pub confidence: u8,
    /// Evidencia recopilada
    pub evidence: HashMap<String, String>,
}

type Result<T> = std::result::Result<T, BehaviorError>;

#[derive(Error, Debug)]
pub enum BehaviorError {
    #[error("Error de E/S: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Error de análisis: {0}")]
    AnalysisError(String),

    #[error("Análisis inconcluso: {0}")]
    InconclusiveAnalysis(String),

    #[error("Error de formato PE: {0}")]
    PeFormatError(String),

    #[error("Error de análisis estático: {0}")]
    StaticAnalysisError(String),

    #[error("Timeout en análisis: {0}")]
    TimeoutError(String),

    #[error("Error interno: {0}")]
    InternalError(String),
}

/// Analizador de comportamientos maliciosos
pub struct BehaviorAnalyzer {
    patterns: HashMap<MaliciousBehaviorType, Vec<String>>,
    cache: DashMap<String, (Instant, Vec<MaliciousBehavior>)>,
    confidence_thresholds: HashMap<MaliciousBehaviorType, f32>,
    stats: AnalyzerStats,
    thread_pool: RwLock<Option<Arc<rayon::ThreadPool>>>,
    timeout_ms: AtomicU64,
    memory_limit: AtomicUsize,
}

struct AnalyzerStats {
    cache_hits: AtomicUsize,
    cache_misses: AtomicUsize,
    total_analyses: AtomicUsize,
    pattern_matches: AtomicUsize,
}

impl BehaviorAnalyzer {
    /// Crea un nuevo analizador de comportamientos
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        let mut confidence_thresholds = HashMap::new();

        // Process Injection patterns
        patterns.insert(
            MaliciousBehaviorType::ProcessInjection,
            vec![
                "VirtualAllocEx".to_string(),
                "WriteProcessMemory".to_string(),
                "CreateRemoteThread".to_string(),
                "NtCreateThreadEx".to_string(),
                "QueueUserAPC".to_string(),
                "SetWindowsHookEx".to_string(),
                "NtMapViewOfSection".to_string(),
                "NtWriteVirtualMemory".to_string(),
                "RtlCreateUserThread".to_string(),
                "NtAllocateVirtualMemory".to_string(),
                "LoadLibraryA".to_string(),
                "GetProcAddress".to_string(),
                "VirtualProtectEx".to_string(),
                "CreateToolhelp32Snapshot".to_string(),
                "Process32First".to_string(),
                "Process32Next".to_string(),
            ],
        );
        confidence_thresholds.insert(MaliciousBehaviorType::ProcessInjection, 0.6);

        // Persistence patterns
        patterns.insert(MaliciousBehaviorType::SystemPersistence, vec![
            "RegSetValueEx".to_string(),
            "RegCreateKeyEx".to_string(),
            "RegOpenKeyEx".to_string(),
            "SHGetSpecialFolderPath".to_string(),
            "GetStartupInfo".to_string(),
            "WinExec".to_string(),
            "CreateService".to_string(),
            "StartService".to_string(),
            "Shell32.dll".to_string(),
            "CurrentVersion\\Run".to_string(),
            "Schedule\\TaskCache".to_string(),
            "StartupItems".to_string(),
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services".to_string(),
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell".to_string(),
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders".to_string(),
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad".to_string(),
            "schtasks.exe".to_string(),
            "at.exe".to_string(),
            "wmic.exe".to_string(),
            "STARTUP".to_string(),
        ]);
        confidence_thresholds.insert(MaliciousBehaviorType::SystemPersistence, 0.5);

        // Evasion patterns
        patterns.insert(
            MaliciousBehaviorType::DetectionEvasion,
            vec![
                "IsDebuggerPresent".to_string(),
                "CheckRemoteDebuggerPresent".to_string(),
                "OutputDebugString".to_string(),
                "GetTickCount".to_string(),
                "QueryPerformanceCounter".to_string(),
                "GetSystemTime".to_string(),
                "Sleep".to_string(),
                "SleepEx".to_string(),
                "WaitForSingleObject".to_string(),
                "timeGetTime".to_string(),
                "GetProcessHeap".to_string(),
                "HeapAlloc".to_string(),
                "VirtualAlloc".to_string(),
                "VirtualProtect".to_string(),
                "NtSetInformationProcess".to_string(),
                "ZwSetInformationThread".to_string(),
                "NtQueryInformationProcess".to_string(),
                "CreateToolhelp32Snapshot".to_string(),
                "Process32First".to_string(),
                "Process32Next".to_string(),
                "GetModuleHandle".to_string(),
                "GetProcAddress".to_string(),
                "LoadLibrary".to_string(),
                "TerminateProcess".to_string(),
            ],
        );
        confidence_thresholds.insert(MaliciousBehaviorType::DetectionEvasion, 0.5);

        // Ransomware patterns
        patterns.insert(
            MaliciousBehaviorType::Ransomware,
            vec![
                "CryptEncrypt".to_string(),
                "CryptAcquireContext".to_string(),
                "BCryptEncrypt".to_string(),
                "CreateFile".to_string(),
                "WriteFile".to_string(),
                "DeleteFile".to_string(),
                "RemoveDirectory".to_string(),
                "GetLogicalDrives".to_string(),
                "GetDriveType".to_string(),
                "FindFirstFile".to_string(),
                "wmic.exe shadowcopy delete".to_string(),
                "vssadmin.exe delete shadows".to_string(),
            ],
        );
        confidence_thresholds.insert(MaliciousBehaviorType::Ransomware, 0.5);

        // Keylogger patterns
        patterns.insert(
            MaliciousBehaviorType::Keylogger,
            vec![
                "SetWindowsHookEx".to_string(),
                "GetAsyncKeyState".to_string(),
                "GetKeyState".to_string(),
                "GetKeyboardState".to_string(),
                "RegisterRawInputDevices".to_string(),
                "GetRawInputData".to_string(),
                "AttachThreadInput".to_string(),
                "MapVirtualKey".to_string(),
                "GetForegroundWindow".to_string(),
            ],
        );
        confidence_thresholds.insert(MaliciousBehaviorType::Keylogger, 0.5);

        // Exfiltration patterns
        patterns.insert(
            MaliciousBehaviorType::DataExfiltration,
            vec![
                "InternetOpen".to_string(),
                "InternetConnect".to_string(),
                "HttpSendRequest".to_string(),
                "WinHttpOpen".to_string(),
                "WinHttpConnect".to_string(),
                "WinHttpSendRequest".to_string(),
                "socket".to_string(),
                "connect".to_string(),
                "send".to_string(),
                "WSASend".to_string(),
                "FtpPutFile".to_string(),
                "GetClipboardData".to_string(),
                "SHGetKnownFolderPath".to_string(),
            ],
        );
        confidence_thresholds.insert(MaliciousBehaviorType::DataExfiltration, 0.5);

        // Command and Control patterns
        patterns.insert(
            MaliciousBehaviorType::CommandAndControl,
            vec![
                "DnsQuery".to_string(),
                "WinHttpOpen".to_string(),
                "InternetOpenUrl".to_string(),
                "WSAConnect".to_string(),
                "connect".to_string(),
                "socket".to_string(),
                "SslEncryptPacket".to_string(),
                "HttpSendRequest".to_string(),
                "WinHttpSendRequest".to_string(),
                "WinHttpWebSocketCompleteUpgrade".to_string(),
                "CreateNamedPipe".to_string(),
                "ConnectNamedPipe".to_string(),
                "GetAdaptersInfo".to_string(),
                "GetAdaptersAddresses".to_string(),
                "HttpOpenRequest".to_string(),
                "InternetReadFile".to_string(),
                "InternetWriteFile".to_string(),
                "WSAStartup".to_string(),
                "gethostbyname".to_string(),
                "getaddrinfo".to_string(),
                "recv".to_string(),
                "SSL_read".to_string(),
                "SSL_write".to_string(),
                "PR_Read".to_string(),
                "PR_Write".to_string(),
                "URLDownloadToFile".to_string(),
                "ShellExecute".to_string(),
            ],
        );
        confidence_thresholds.insert(MaliciousBehaviorType::CommandAndControl, 0.5);

        // Privilege Escalation patterns
        patterns.insert(
            MaliciousBehaviorType::PrivilegeEscalation,
            vec![
                "AdjustTokenPrivileges".to_string(),
                "CreateProcessAsUser".to_string(),
                "OpenProcessToken".to_string(),
                "LookupPrivilegeValue".to_string(),
                "SeDebugPrivilege".to_string(),
                "SeTakeOwnershipPrivilege".to_string(),
                "SeBackupPrivilege".to_string(),
                "SeRestorePrivilege".to_string(),
                "SeImpersonatePrivilege".to_string(),
            ],
        );
        confidence_thresholds.insert(MaliciousBehaviorType::PrivilegeEscalation, 0.5);

        // Anti-Debug patterns
        patterns.insert(
            MaliciousBehaviorType::AntiDebug,
            vec![
                "IsDebuggerPresent".to_string(),
                "CheckRemoteDebuggerPresent".to_string(),
                "NtQueryInformationProcess".to_string(),
                "OutputDebugString".to_string(),
                "FindWindow".to_string(),
                "BlockInput".to_string(),
                "DebugActiveProcess".to_string(),
                "QueryPerformanceCounter".to_string(),
                "GetTickCount".to_string(),
                "timeGetTime".to_string(),
            ],
        );
        confidence_thresholds.insert(MaliciousBehaviorType::AntiDebug, 0.5);

        // Anti-VM patterns
        patterns.insert(
            MaliciousBehaviorType::AntiVM,
            vec![
                "vmware.exe".to_string(),
                "vbox.exe".to_string(),
                "vboxtray.exe".to_string(),
                "qemu".to_string(),
                "HKLM\\SOFTWARE\\VMware".to_string(),
                "HKLM\\SOFTWARE\\VirtualBox".to_string(),
                "SYSTEM\\ControlSet001\\Services\\Disk\\Enum".to_string(),
                "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port".to_string(),
            ],
        );
        confidence_thresholds.insert(MaliciousBehaviorType::AntiVM, 0.5);

        // Rootkit patterns
        patterns.insert(
            MaliciousBehaviorType::Rootkit,
            vec![
                "NtCreateFile".to_string(),
                "NtOpenFile".to_string(),
                "NtQueryDirectoryFile".to_string(),
                "NtQuerySystemInformation".to_string(),
                "NtQueryInformationProcess".to_string(),
                "ZwCreateFile".to_string(),
                "ZwOpenFile".to_string(),
                "ZwQueryDirectoryFile".to_string(),
                "DeviceIoControl".to_string(),
                "NtDeviceIoControlFile".to_string(),
            ],
        );
        confidence_thresholds.insert(MaliciousBehaviorType::Rootkit, 0.5);

        // CryptoMiner patterns
        patterns.insert(
            MaliciousBehaviorType::CryptoMiner,
            vec![
                "stratum+tcp://".to_string(),
                "xmrig".to_string(),
                "minerd".to_string(),
                "cpuminer".to_string(),
                "CreateThread".to_string(),
                "SetThreadPriority".to_string(),
                "SetProcessPriority".to_string(),
                "CRYPTONIGHT".to_string(),
                "RANDOMX".to_string(),
                "ETHASH".to_string(),
            ],
        );
        confidence_thresholds.insert(MaliciousBehaviorType::CryptoMiner, 0.5);

        BehaviorAnalyzer {
            patterns,
            cache: DashMap::new(),
            confidence_thresholds,
            stats: AnalyzerStats {
                cache_hits: AtomicUsize::new(0),
                cache_misses: AtomicUsize::new(0),
                total_analyses: AtomicUsize::new(0),
                pattern_matches: AtomicUsize::new(0),
            },
            thread_pool: RwLock::new(None),
            timeout_ms: AtomicU64::new(5000),
            memory_limit: AtomicUsize::new(512 * 1024 * 1024),
        }
    }

    /// Obtiene estadísticas del analizador
    pub fn get_stats(&self) -> (usize, usize, usize, usize) {
        (
            self.stats.cache_hits.load(Ordering::Relaxed),
            self.stats.cache_misses.load(Ordering::Relaxed),
            self.stats.total_analyses.load(Ordering::Relaxed),
            self.stats.pattern_matches.load(Ordering::Relaxed),
        )
    }

    fn cached<F>(&self, key: String, scan: F) -> Vec<MaliciousBehavior>
    where
        F: FnOnce() -> Vec<MaliciousBehavior>,
    {
        self.stats.total_analyses.fetch_add(1, Ordering::Relaxed);
        if let Some(entry) = self.cache.get(&key) {
            if entry.0.elapsed() < Duration::from_secs(3600) {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return entry.1.clone();
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        let result = scan();
        if self.cache.len() >= 4096 {
            self.trim_cache(2048);
        }
        self.cache.insert(key, (Instant::now(), result.clone()));
        result
    }

    fn import_behaviors(&self, imports: &HashSet<&str>) -> Vec<MaliciousBehavior> {
        let scan = || {
            self.patterns
                .par_iter()
                .filter_map(|(kind, patterns)| {
                    let matches: Vec<_> = patterns
                        .iter()
                        .filter(|s| imports.contains(s.as_str()))
                        .collect();
                    let mut confidence = matches.len() as f32 / patterns.len() as f32;
                    // This specific sequence combines allocation, cross-process writing and thread creation.
                    if *kind == MaliciousBehaviorType::ProcessInjection
                        && ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
                            .iter()
                            .all(|name| imports.contains(*name))
                    {
                        confidence = confidence.max(0.9);
                    }
                    if confidence < self.confidence_thresholds[kind] {
                        return None;
                    }
                    self.stats
                        .pattern_matches
                        .fetch_add(matches.len(), Ordering::Relaxed);
                    let names = matches
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    Some(MaliciousBehavior {
                        behavior_type: *kind,
                        confidence: (confidence * 100.0) as u8,
                        description: format!("Detected {kind:?} indicators: {names}"),
                        evidence: HashMap::from([("matched_imports".into(), names)]),
                    })
                })
                .collect::<Vec<_>>()
        };
        let pool = self.thread_pool.read().clone();
        let mut results = match pool {
            Some(pool) => pool.install(scan),
            None => scan(),
        };
        results.sort_by_key(|b| b.behavior_type);
        results
    }

    pub async fn analyze_imports_optimized(
        &self,
        imports: &[String],
        file_hash: &str,
    ) -> Vec<MaliciousBehavior> {
        self.cached(format!("imports:{file_hash}"), || {
            self.import_behaviors(&imports.iter().map(String::as_str).collect())
        })
    }

    pub async fn optimize_thread_pool(&self, max_threads: usize) {
        let count = num_cpus::get().min(max_threads).max(1);
        match rayon::ThreadPoolBuilder::new().num_threads(count).build() {
            Ok(pool) => *self.thread_pool.write() = Some(Arc::new(pool)),
            Err(error) => log::warn!("Unable to configure behavior analysis threads: {error}"),
        }
    }

    pub fn set_memory_limit(&self, bytes: usize) {
        self.memory_limit.store(bytes, Ordering::Relaxed);
    }

    pub fn set_timeout(&self, milliseconds: u64) {
        self.timeout_ms.store(milliseconds, Ordering::Relaxed);
    }

    fn trim_cache(&self, max_size: usize) {
        self.cache
            .retain(|_, (time, _)| time.elapsed() < Duration::from_secs(3600));
        let mut entries: Vec<_> = self.cache.iter().map(|e| (e.0, e.key().clone())).collect();
        entries.sort_unstable();
        let excess = entries.len().saturating_sub(max_size);
        for (_, key) in entries.into_iter().take(excess) {
            self.cache.remove(&key);
        }
    }

    pub async fn cleanup_cache(&self, max_size: usize) {
        self.trim_cache(max_size);
    }

    fn section_behaviors(sections: &[(String, f64)]) -> Vec<MaliciousBehavior> {
        // Radare2 and the in-memory PE reader both report Shannon entropy in bits per byte.
        let packed: Vec<_> = sections
            .iter()
            .filter(|(_, entropy)| *entropy > 7.2)
            .map(|(name, value)| format!("{name}:{value:.2}"))
            .collect();
        let named: Vec<_> = sections
            .iter()
            .filter(|(name, _)| {
                let name = name.to_ascii_lowercase();
                ["upx", "aspack", "vmp", "themida", "encrypt", "crypt"]
                    .iter()
                    .any(|s| name.contains(s))
            })
            .map(|s| s.0.clone())
            .collect();
        let mut result = Vec::new();
        if !packed.is_empty() {
            result.push(MaliciousBehavior {
                behavior_type: MaliciousBehaviorType::Packing,
                description: format!("Detected {} high-entropy sections", packed.len()),
                confidence: (packed.len() * 15).min(90) as u8,
                evidence: HashMap::from([("high_entropy_sections".into(), packed.join(", "))]),
            });
        }
        if !named.is_empty() {
            result.push(MaliciousBehavior {
                behavior_type: MaliciousBehaviorType::Packing,
                description: format!("Suspicious section names: {}", named.join(", ")),
                confidence: 85,
                evidence: HashMap::from([("suspicious_sections".into(), named.join(", "))]),
            });
        }
        result
    }

    pub async fn analyze_sections_optimized(
        &self,
        sections: &[(String, f64)],
        file_hash: &str,
    ) -> Vec<MaliciousBehavior> {
        self.cached(format!("sections:{file_hash}"), || {
            Self::section_behaviors(sections)
        })
    }

    fn resource_behaviors(resources: &[String]) -> Vec<MaliciousBehavior> {
        let names: Vec<_> = resources
            .iter()
            .filter(|name| {
                let name = name.to_ascii_lowercase();
                [
                    ".exe", ".dll", ".sys", ".bin", ".dat", ".scr", ".vbs", ".ps1", ".bat",
                ]
                .iter()
                .any(|ext| name.ends_with(ext))
            })
            .map(String::as_str)
            .collect();
        if names.is_empty() {
            return Vec::new();
        }
        vec![MaliciousBehavior {
            behavior_type: MaliciousBehaviorType::DetectionEvasion,
            description: format!("Suspicious embedded resources: {}", names.join(", ")),
            confidence: (names.len() * 10).min(90) as u8,
            evidence: HashMap::from([("suspicious_resources".into(), names.join(", "))]),
        }]
    }

    pub async fn analyze_resources(
        &self,
        resources: &[String],
        file_hash: &str,
    ) -> Vec<MaliciousBehavior> {
        self.cached(format!("resources:{file_hash}"), || {
            Self::resource_behaviors(resources)
        })
    }

    /// Analiza las correlaciones entre comportamientos para mejorar la detección
    fn analyze_correlations(&self, behaviors: &[MaliciousBehavior]) -> Vec<MaliciousBehavior> {
        let mut correlated_behaviors = Vec::new();

        // Detectar patrones de ransomware avanzado
        if behaviors
            .iter()
            .any(|b| matches!(b.behavior_type, MaliciousBehaviorType::Ransomware))
            && behaviors
                .iter()
                .any(|b| matches!(b.behavior_type, MaliciousBehaviorType::SystemPersistence))
        {
            let mut evidence = HashMap::new();
            evidence.insert(
                "correlation".to_string(),
                "Ransomware behavior combined with persistence mechanisms".to_string(),
            );

            correlated_behaviors.push(MaliciousBehavior {
                behavior_type: MaliciousBehaviorType::Ransomware,
                description: "Advanced ransomware behavior detected with persistence capabilities"
                    .to_string(),
                confidence: 95,
                evidence,
            });
        }

        // Detectar APT (Advanced Persistent Threat)
        if behaviors
            .iter()
            .any(|b| matches!(b.behavior_type, MaliciousBehaviorType::ProcessInjection))
            && behaviors
                .iter()
                .any(|b| matches!(b.behavior_type, MaliciousBehaviorType::CommandAndControl))
            && behaviors
                .iter()
                .any(|b| matches!(b.behavior_type, MaliciousBehaviorType::DetectionEvasion))
        {
            let mut evidence = HashMap::new();
            evidence.insert(
                "correlation".to_string(),
                "Multiple sophisticated attack techniques detected".to_string(),
            );

            correlated_behaviors.push(MaliciousBehavior {
                behavior_type: MaliciousBehaviorType::DetectionEvasion,
                description: "Possible APT behavior detected".to_string(),
                confidence: 90,
                evidence,
            });
        }

        // Detectar robo de información avanzado
        if behaviors
            .iter()
            .any(|b| matches!(b.behavior_type, MaliciousBehaviorType::DataExfiltration))
            && behaviors
                .iter()
                .any(|b| matches!(b.behavior_type, MaliciousBehaviorType::Keylogger))
        {
            let mut evidence = HashMap::new();
            evidence.insert(
                "correlation".to_string(),
                "Data theft combined with keylogging capabilities".to_string(),
            );

            correlated_behaviors.push(MaliciousBehavior {
                behavior_type: MaliciousBehaviorType::DataExfiltration,
                description: "Advanced data theft behavior detected".to_string(),
                confidence: 85,
                evidence,
            });
        }

        correlated_behaviors
    }

    /// Analiza las importaciones con correlaciones
    pub async fn analyze_imports_with_correlations(
        &self,
        imports: &[String],
        file_hash: &str,
    ) -> Vec<MaliciousBehavior> {
        let mut behaviors = self.analyze_imports_optimized(imports, file_hash).await;
        let correlated = self.analyze_correlations(&behaviors);
        behaviors.extend(correlated);
        behaviors
    }

    pub fn analyze_optimized(
        &self,
        bytes: &[u8],
        _file_hash: &str,
    ) -> Result<Vec<MaliciousBehavior>> {
        if bytes.len() > self.memory_limit.load(Ordering::Relaxed) {
            return Err(BehaviorError::InconclusiveAnalysis(
                "File exceeds analysis limit".into(),
            ));
        }
        if let Some(marker) = self.detect_test_files(bytes) {
            return Ok(vec![marker]);
        }
        self.stats.total_analyses.fetch_add(1, Ordering::Relaxed);
        let key = format!("pe:{:x}", Sha256::digest(bytes));
        if let Some(cached) = self.cache.get(&key) {
            if cached.0.elapsed() < Duration::from_secs(3600) {
                self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(cached.1.clone());
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();
        let deadline = Duration::from_millis(self.timeout_ms.load(Ordering::Relaxed));
        let format_error = |error: object::Error| BehaviorError::PeFormatError(error.to_string());
        let result = match object::FileKind::parse(bytes).map_err(format_error)? {
            object::FileKind::Pe32 => self.analyze_pe(
                object::read::pe::PeFile32::parse(bytes).map_err(format_error)?,
                start,
                deadline,
            ),
            object::FileKind::Pe64 => self.analyze_pe(
                object::read::pe::PeFile64::parse(bytes).map_err(format_error)?,
                start,
                deadline,
            ),
            _ => return Err(BehaviorError::PeFormatError("Expected a PE image".into())),
        }?;
        if self.cache.len() >= 4096 {
            self.trim_cache(2048);
        }
        self.cache.insert(key, (Instant::now(), result.clone()));
        Ok(result)
    }

    fn analyze_pe<Pe: ImageNtHeaders>(
        &self,
        file: PeFile<'_, Pe>,
        start: Instant,
        deadline: Duration,
    ) -> Result<Vec<MaliciousBehavior>> {
        let format_error = |e: object::Error| BehaviorError::PeFormatError(e.to_string());
        let check_time = || {
            if start.elapsed() > deadline {
                Err(BehaviorError::TimeoutError(
                    "PE analysis deadline exceeded".into(),
                ))
            } else {
                Ok(())
            }
        };
        // Import descriptors can share thunk tables. Stream them so aliased offsets
        // cannot expand into a Vec of duplicate imports proportional to descriptors × thunks.
        let mut imports = HashSet::new();
        let mut memory_budget = self.memory_limit.load(Ordering::Relaxed);
        let mut charge = |bytes| -> Result<()> {
            memory_budget = memory_budget.checked_sub(bytes).ok_or_else(|| {
                BehaviorError::InconclusiveAnalysis(
                    "PE metadata exceeds analysis memory limit".into(),
                )
            })?;
            Ok(())
        };
        if let Some(table) = file.import_table().map_err(format_error)? {
            let mut descriptors = table.descriptors().map_err(format_error)?;
            let mut seen_thunks = HashSet::new();
            while let Some(descriptor) = descriptors.next().map_err(format_error)? {
                check_time()?;
                let address = descriptor.original_first_thunk.get(object::LittleEndian);
                let address = if address == 0 {
                    descriptor.first_thunk.get(object::LittleEndian)
                } else {
                    address
                };
                if !seen_thunks.insert(address) {
                    continue;
                }
                charge(2 * std::mem::size_of::<u32>())?;
                let mut thunks = table.thunks(address).map_err(format_error)?;
                while let Some(thunk) = thunks.next::<Pe>().map_err(format_error)? {
                    check_time()?;
                    if let Import::Name(_, name) =
                        table.import::<Pe>(thunk).map_err(format_error)?
                    {
                        if let Ok(name) = std::str::from_utf8(name) {
                            if imports.insert(name) {
                                charge(2 * std::mem::size_of::<&str>())?;
                            }
                        }
                    }
                }
            }
        }
        let mut behaviors = self.import_behaviors(&imports);
        let mut sections = Vec::new();
        for section in file.sections() {
            let data = section.data().map_err(format_error)?;
            let mut counts = [0usize; 256];
            for chunk in data.chunks(65536) {
                check_time()?;
                for b in chunk {
                    counts[*b as usize] += 1;
                }
            }
            let entropy: f64 = counts
                .iter()
                .filter(|&&n| n > 0)
                .map(|n| {
                    let p = *n as f64 / data.len() as f64;
                    -p * p.log2()
                })
                .sum();
            sections.push((section.name().map_err(format_error)?.to_owned(), entropy));
        }
        behaviors.extend(Self::section_behaviors(&sections));
        if let Some(directory) = file
            .data_directories()
            .resource_directory(file.data(), &file.section_table())
            .map_err(format_error)?
        {
            let mut stack = vec![directory.root().map_err(format_error)?];
            let mut visited = HashSet::from([0]);
            let mut names = Vec::new();
            while let Some(table) = stack.pop() {
                check_time()?;
                for entry in table.entries {
                    check_time()?;
                    if let ResourceNameOrId::Name(name) = entry.name_or_id() {
                        let units = name.data(directory).map_err(format_error)?;
                        charge(units.len() * 3 + std::mem::size_of::<String>())?;
                        names.push(name.to_string_lossy(directory).map_err(format_error)?);
                    }
                    if entry.is_table() && visited.insert(entry.data_offset()) {
                        charge(2 * std::mem::size_of::<u32>())?;
                        if let Some(child) = entry.data(directory).map_err(format_error)?.table() {
                            stack.push(child);
                        }
                    }
                }
            }
            behaviors.extend(Self::resource_behaviors(&names));
        }
        check_time()?;
        behaviors.extend(self.analyze_correlations(&behaviors));
        Ok(behaviors)
    }

    /// Detects common test viruses like EICAR
    pub fn detect_test_files(&self, content: &[u8]) -> Option<MaliciousBehavior> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        // Decode once so the scanner executable does not contain the raw diagnostic signature.
        static MARKER: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        let marker = MARKER.get_or_init(|| {
            STANDARD.decode("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=")
                .expect("valid diagnostic signature")
        });
        if content.windows(marker.len()).any(|window| window == marker) {
            return Some(MaliciousBehavior {
                behavior_type: MaliciousBehaviorType::TestFile,
                description: "EICAR antivirus test file detected".to_string(),
                confidence: 0, // It's not actually malicious, just a test
                evidence: HashMap::new(),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_behavior_detection() {
        let analyzer = BehaviorAnalyzer::new();
        let imports = vec![
            "VirtualAllocEx".to_string(),
            "WriteProcessMemory".to_string(),
            "CreateRemoteThread".to_string(),
        ];

        let behaviors = analyzer
            .analyze_imports_optimized(&imports, "test_hash")
            .await;
        assert!(!behaviors.is_empty());
        assert!(behaviors
            .iter()
            .any(|b| matches!(b.behavior_type, MaliciousBehaviorType::ProcessInjection)));
    }

    #[test]
    fn parses_real_pe_and_rejects_truncated_headers() {
        let analyzer = BehaviorAnalyzer::new();
        let fixture = include_bytes!("../build/CMakeFiles/3.29.5-msvc4/CompilerIdC/a.exe");
        analyzer.analyze_optimized(fixture, "compiler").unwrap();
        assert!(matches!(
            analyzer.analyze_optimized(&fixture[..64], "compiler"),
            Err(BehaviorError::PeFormatError(_))
        ));
    }

    #[tokio::test]
    async fn test_eicar_detection() {
        let analyzer = BehaviorAnalyzer::new();
        // EICAR test string
        let eicar_content =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        // Test detection
        let result = analyzer.detect_test_files(eicar_content);

        // Verify result
        assert!(result.is_some(), "EICAR test file should be detected");
        if let Some(behavior) = result {
            assert!(matches!(
                behavior.behavior_type,
                MaliciousBehaviorType::TestFile
            ));
            assert_eq!(behavior.description, "EICAR antivirus test file detected");
        }
    }

    #[tokio::test]
    async fn test_caching() {
        let analyzer = BehaviorAnalyzer::new();
        let imports = vec!["VirtualAllocEx".to_string()];
        let file_hash = "test_hash_2";

        // First analysis
        let first_result = analyzer
            .analyze_imports_optimized(&imports, file_hash)
            .await;

        // Second analysis (should use cache)
        let second_result = analyzer
            .analyze_imports_optimized(&imports, file_hash)
            .await;

        assert_eq!(first_result, second_result);
        assert_eq!(analyzer.get_stats().0, 1);
    }

    #[tokio::test]
    async fn test_confidence_thresholds() {
        let analyzer = BehaviorAnalyzer::new();
        let imports = vec!["DnsQuery".to_string()]; // Single C&C indicator

        let behaviors = analyzer
            .analyze_imports_optimized(&imports, "test_hash_3")
            .await;
        assert!(behaviors.is_empty()); // Should not trigger with just one match
    }
}
