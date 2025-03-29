use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Memory::*;
use windows::Win32::Foundation::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use parking_lot::RwLock as PLRwLock;
use dashmap::DashMap;
use crossbeam_channel::{bounded, Sender};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use log::{debug, info, warn};
use thiserror::Error;
use serde_json;

/// Tipos de comportamientos maliciosos conocidos
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    cache: Arc<RwLock<HashMap<String, Vec<MaliciousBehavior>>>>,
    confidence_thresholds: HashMap<MaliciousBehaviorType, f32>,
    pattern_cache: Arc<DashMap<String, HashSet<MaliciousBehaviorType>>>,
    stats: Arc<AnalyzerStats>,
    /// Pool de hilos personalizado para análisis
    thread_pool: Option<Arc<rayon::ThreadPool>>,
    /// Caché con acceso concurrente para resultados rápidos
    fast_cache: Arc<DashMap<String, (Vec<MaliciousBehavior>, Instant)>>,
    /// Timeout para análisis (ms)
    timeout_ms: u64,
    /// Límite de memoria por análisis (bytes)
    memory_limit: usize,
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
        patterns.insert(MaliciousBehaviorType::ProcessInjection, vec![
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
        ]);
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
        patterns.insert(MaliciousBehaviorType::DetectionEvasion, vec![
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
        ]);
        confidence_thresholds.insert(MaliciousBehaviorType::DetectionEvasion, 0.5);

        // Ransomware patterns
        patterns.insert(MaliciousBehaviorType::Ransomware, vec![
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
        ]);
        confidence_thresholds.insert(MaliciousBehaviorType::Ransomware, 0.5);

        // Keylogger patterns
        patterns.insert(MaliciousBehaviorType::Keylogger, vec![
            "SetWindowsHookEx".to_string(),
            "GetAsyncKeyState".to_string(),
            "GetKeyState".to_string(),
            "GetKeyboardState".to_string(),
            "RegisterRawInputDevices".to_string(),
            "GetRawInputData".to_string(),
            "AttachThreadInput".to_string(),
            "MapVirtualKey".to_string(),
            "GetForegroundWindow".to_string(),
        ]);
        confidence_thresholds.insert(MaliciousBehaviorType::Keylogger, 0.5);

        // Exfiltration patterns
        patterns.insert(MaliciousBehaviorType::DataExfiltration, vec![
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
        ]);
        confidence_thresholds.insert(MaliciousBehaviorType::DataExfiltration, 0.5);

        // Command and Control patterns
        patterns.insert(MaliciousBehaviorType::CommandAndControl, vec![
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
        ]);
        confidence_thresholds.insert(MaliciousBehaviorType::CommandAndControl, 0.5);

        // Privilege Escalation patterns
        patterns.insert(MaliciousBehaviorType::PrivilegeEscalation, vec![
            "AdjustTokenPrivileges".to_string(),
            "CreateProcessAsUser".to_string(),
            "OpenProcessToken".to_string(),
            "LookupPrivilegeValue".to_string(),
            "SeDebugPrivilege".to_string(),
            "SeTakeOwnershipPrivilege".to_string(),
            "SeBackupPrivilege".to_string(),
            "SeRestorePrivilege".to_string(),
            "SeImpersonatePrivilege".to_string(),
        ]);
        confidence_thresholds.insert(MaliciousBehaviorType::PrivilegeEscalation, 0.5);

        // Anti-Debug patterns
        patterns.insert(MaliciousBehaviorType::AntiDebug, vec![
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
        ]);
        confidence_thresholds.insert(MaliciousBehaviorType::AntiDebug, 0.5);

        // Anti-VM patterns
        patterns.insert(MaliciousBehaviorType::AntiVM, vec![
            "vmware.exe".to_string(),
            "vbox.exe".to_string(),
            "vboxtray.exe".to_string(),
            "qemu".to_string(),
            "HKLM\\SOFTWARE\\VMware".to_string(),
            "HKLM\\SOFTWARE\\VirtualBox".to_string(),
            "SYSTEM\\ControlSet001\\Services\\Disk\\Enum".to_string(),
            "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port".to_string(),
        ]);
        confidence_thresholds.insert(MaliciousBehaviorType::AntiVM, 0.5);

        // Rootkit patterns
        patterns.insert(MaliciousBehaviorType::Rootkit, vec![
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
        ]);
        confidence_thresholds.insert(MaliciousBehaviorType::Rootkit, 0.5);

        // CryptoMiner patterns
        patterns.insert(MaliciousBehaviorType::CryptoMiner, vec![
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
        ]);
        confidence_thresholds.insert(MaliciousBehaviorType::CryptoMiner, 0.5);

        let analyzer = BehaviorAnalyzer {
            patterns,
            cache: Arc::new(RwLock::new(HashMap::new())),
            confidence_thresholds,
            pattern_cache: Arc::new(DashMap::new()),
            stats: Arc::new(AnalyzerStats {
                cache_hits: AtomicUsize::new(0),
                cache_misses: AtomicUsize::new(0),
                total_analyses: AtomicUsize::new(0),
                pattern_matches: AtomicUsize::new(0),
            }),
            thread_pool: None,
            fast_cache: Arc::new(DashMap::with_capacity(1000)),
            timeout_ms: 5000,
            memory_limit: 512 * 1024 * 1024, // 512 MB por defecto
        };

        // Precalcular patrones comunes
        analyzer.precalculate_patterns();
        analyzer
    }
    
    /// Precalcula patrones comunes para mejorar el rendimiento
    fn precalculate_patterns(&self) {
        for (behavior_type, patterns) in &self.patterns {
            for pattern in patterns {
                let mut behavior_set = self.pattern_cache
                    .entry(pattern.clone())
                    .or_insert_with(HashSet::new);
                behavior_set.insert(behavior_type.clone());
            }
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

    /// Analiza las importaciones con optimizaciones
    pub async fn analyze_imports_optimized(&self, imports: &[String], file_hash: &str) -> Vec<MaliciousBehavior> {
        self.stats.total_analyses.fetch_add(1, Ordering::Relaxed);

        // Verificar caché
        if let Some(cached_result) = self.cache.read().await.get(file_hash) {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return cached_result.clone();
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        let mut behaviors = Vec::new();
        let mut behavior_matches: HashMap<MaliciousBehaviorType, Vec<String>> = HashMap::new();

        // Usar el caché de patrones precalculado
        for import in imports {
            if let Some(behavior_types) = self.pattern_cache.get(import) {
                self.stats.pattern_matches.fetch_add(1, Ordering::Relaxed);
                for behavior_type in behavior_types.value() {
                    behavior_matches
                        .entry(behavior_type.clone())
                        .or_insert_with(Vec::new)
                        .push(import.clone());
                }
            }
        }

        // Procesar coincidencias en paralelo
        let behavior_results: Vec<_> = behavior_matches
            .par_iter()
            .filter_map(|(behavior_type, matches)| {
                let pattern_list = &self.patterns[behavior_type];
                let confidence = matches.len() as f32 / pattern_list.len() as f32;
                let threshold = self.confidence_thresholds.get(behavior_type)
                    .unwrap_or(&0.5);

                if confidence >= *threshold {
                    Some(MaliciousBehavior {
                        behavior_type: behavior_type.clone(),
                        confidence: (confidence * 100.0) as u8,
                        description: format!(
                            "Detected {} behavior with confidence {:.2}. Matched imports: {}",
                            behavior_type,
                            confidence,
                            matches.join(", ")
                        ),
                        evidence: {
                            let mut evidence = HashMap::new();
                            evidence.insert("matched_imports".to_string(), matches.join(", "));
                            evidence
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        behaviors.extend(behavior_results);

        // Agregar al caché
        self.cache.write().await.insert(file_hash.to_string(), behaviors.clone());

        behaviors
    }

    /// Optimiza el pool de hilos según la configuración del sistema
    pub async fn optimize_thread_pool(&self, max_threads: usize) {
        let num_cpus = num_cpus::get();
        let optimal_threads = num_cpus.min(max_threads).max(2);
        
        let new_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(optimal_threads)
            .thread_name(|i| format!("behavior-analyzer-{}", i))
            .build()
            .ok()
            .map(Arc::new);
            
        if let Some(pool) = new_pool {
            debug!("Pool de hilos optimizado: {} hilos", optimal_threads);
            // Ya que thread_pool es Option<Arc<>>>, podemos reemplazarlo directamente sin mutabilidad
            // Es seguro porque estamos reemplazando el Arc entero, no modificando su contenido
            unsafe {
                let ptr = &self.thread_pool as *const _ as *mut Option<Arc<rayon::ThreadPool>>;
                *ptr = Some(pool);
            }
        }
    }
    
    /// Establece el límite de memoria para análisis
    pub fn set_memory_limit(&self, limit_bytes: usize) {
        // Similar al método anterior, usamos la misma técnica para actualizar el límite
        unsafe {
            let ptr = &self.memory_limit as *const _ as *mut usize;
            *ptr = limit_bytes;
        }
        debug!("Límite de memoria establecido: {} MB", limit_bytes / (1024 * 1024));
    }
    
    /// Establece el timeout para análisis
    pub fn set_timeout(&self, timeout_ms: u64) {
        unsafe {
            let ptr = &self.timeout_ms as *const _ as *mut u64;
            *ptr = timeout_ms;
        }
        debug!("Timeout de análisis establecido: {} ms", timeout_ms);
    }
    
    /// Versión optimizada de limpieza de caché
    pub async fn cleanup_cache(&self, max_size: usize) {
        // Limpiar caché rápida primero (más eficiente)
        self.fast_cache.retain(|_, (_, timestamp)| {
            timestamp.elapsed() < Duration::from_secs(3600) // 1 hora de tiempo de vida
        });
        
        // Limpiar caché principal si es necesario
        let mut cache = self.cache.write().await;
        if cache.len() > max_size {
            // Mantener solo las entradas más recientes
            let mut entries: Vec<_> = cache.keys().cloned().collect();
            entries.sort_by(|a, b| a.cmp(b));
            
            let to_remove = entries.len() - max_size;
            for key in entries.iter().take(to_remove) {
                cache.remove(key);
            }
            
            debug!("Cache limpiada: {} entradas eliminadas", to_remove);
        }
    }
    
    /// Analiza las secciones de un ejecutable PE con manejo optimizado de recursos
    pub async fn analyze_sections_optimized(&self, sections: &[(String, f64)], file_hash: &str) -> Vec<MaliciousBehavior> {
        // Verificar caché rápida primero
        let cache_key = format!("sections_{}", file_hash);
        if let Some(entry) = self.fast_cache.get(&cache_key) {
            let (behaviors, timestamp) = entry.value();
            if timestamp.elapsed() < Duration::from_secs(3600) {
                return behaviors.clone();
            }
        }
        
        // Verificar caché principal
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&cache_key) {
                return cached.clone();
            }
        }
        
        // Si no está en caché, realizar análisis con límite de tiempo
        let timeout = self.timeout_ms;
        let sections_vec = sections.to_vec();
        
        let behaviors = tokio::time::timeout(
            Duration::from_millis(timeout),
            tokio::task::spawn_blocking(move || {
                let mut results = Vec::new();
                
                // Análisis de entropia
                let high_entropy_sections: Vec<_> = sections_vec.iter()
                    .filter(|(_, entropy)| *entropy > 0.9)
                    .collect();
                    
                if !high_entropy_sections.is_empty() {
                    let mut evidence = HashMap::new();
                    evidence.insert(
                        "high_entropy_sections".to_string(), 
                        high_entropy_sections.iter()
                            .map(|(name, entropy)| format!("{}:{:.2}", name, entropy))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    
                    let behavior = MaliciousBehavior {
                        behavior_type: MaliciousBehaviorType::Packing,
                        description: format!(
                            "Detected {} high-entropy sections, possible packing",
                            high_entropy_sections.len()
                        ),
                        confidence: (high_entropy_sections.len() * 15).min(90) as u8,
                        evidence,
                    };
                    
                    results.push(behavior);
                }
                
                // Análisis de nombres sospechosos
                let suspicious_names = ["UPX", "aspack", "vmp", "themida", "encrypt", "crypt"];
                let suspicious_sections: Vec<_> = sections_vec.iter()
                    .filter(|(name, _)| {
                        suspicious_names.iter().any(|&sus| 
                            name.to_lowercase().contains(sus.to_lowercase().as_str())
                        )
                    })
                    .collect();
                    
                if !suspicious_sections.is_empty() {
                    let mut evidence = HashMap::new();
                    evidence.insert(
                        "suspicious_sections".to_string(),
                        suspicious_sections.iter()
                            .map(|(name, _)| name.clone())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    
                    let behavior = MaliciousBehavior {
                        behavior_type: MaliciousBehaviorType::Packing,
                        description: format!(
                            "Detected sections with suspicious names: {}",
                            suspicious_sections.iter()
                                .map(|(name, _)| name.clone())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        confidence: 85,
                        evidence,
                    };
                    
                    results.push(behavior);
                }
                
                results
            })
        ).await;
        
        // Manejar resultado o timeout
        let behaviors = match behaviors {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                warn!("Error en análisis de secciones para {}", file_hash);
                Vec::new()
            },
            Err(_) => {
                warn!("Timeout en análisis de secciones para {}", file_hash);
                Vec::new()
            }
        };
        
        // Guardar en ambas cachés
        self.fast_cache.insert(cache_key.clone(), (behaviors.clone(), Instant::now()));
        
        let mut cache = self.cache.write().await;
        cache.insert(cache_key, behaviors.clone());
        
        behaviors
    }

    /// Analiza los recursos de un ejecutable PE
    pub async fn analyze_resources(&self, resources: &[String], file_hash: &str) -> Vec<MaliciousBehavior> {
        // Check cache first
        if let Some(cached_result) = self.cache.read().await.get(&format!("resources_{}", file_hash)) {
            return cached_result.clone();
        }

        let mut behaviors = Vec::new();
        
        // Buscar recursos sospechosos usando procesamiento paralelo
        let suspicious_resources: Vec<_> = resources.par_iter()
            .filter(|r| {
                // Recursos con extensiones sospechosas
                let suspicious_exts = [".exe", ".dll", ".sys", ".bin", ".dat", ".scr", ".vbs", ".ps1", ".bat"];
                suspicious_exts.iter().any(|&ext| r.ends_with(ext))
            })
            .collect();
            
        if !suspicious_resources.is_empty() {
            let mut evidence = HashMap::new();
            evidence.insert(
                "suspicious_resources".to_string(),
                suspicious_resources.iter().map(|&s| s.to_string()).collect::<Vec<_>>().join(", "),
            );
            
            let behavior = MaliciousBehavior {
                behavior_type: MaliciousBehaviorType::DetectionEvasion,
                description: format!(
                    "Detected {} suspicious embedded resources: {}",
                    suspicious_resources.len(),
                    suspicious_resources.iter().map(|&s| s.to_string()).collect::<Vec<_>>().join(", ")
                ),
                confidence: (suspicious_resources.len() * 10).min(90) as u8,
                evidence,
            };

            behaviors.push(behavior);
        }
        
        // Cache the results
        self.cache.write().await.insert(format!("resources_{}", file_hash), behaviors.clone());
        
        behaviors
    }

    /// Analiza las correlaciones entre comportamientos para mejorar la detección
    async fn analyze_correlations(&self, behaviors: &[MaliciousBehavior]) -> Vec<MaliciousBehavior> {
        let mut correlated_behaviors = Vec::new();
        
        // Detectar patrones de ransomware avanzado
        if behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::Ransomware)) &&
           behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::SystemPersistence)) {
            let mut evidence = HashMap::new();
            evidence.insert(
                "correlation".to_string(),
                "Ransomware behavior combined with persistence mechanisms".to_string(),
            );
            
            correlated_behaviors.push(MaliciousBehavior {
                behavior_type: MaliciousBehaviorType::Ransomware,
                description: "Advanced ransomware behavior detected with persistence capabilities".to_string(),
                confidence: 95,
                evidence,
            });
        }
        
        // Detectar APT (Advanced Persistent Threat)
        if behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::ProcessInjection)) &&
           behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::CommandAndControl)) &&
           behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::DetectionEvasion)) {
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
        if behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::DataExfiltration)) &&
           behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::Keylogger)) {
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
    pub async fn analyze_imports_with_correlations(&self, imports: &[String], file_hash: &str) -> Vec<MaliciousBehavior> {
        let mut behaviors = self.analyze_imports_optimized(imports, file_hash).await;
        let correlated = self.analyze_correlations(&behaviors).await;
        behaviors.extend(correlated);
        behaviors
    }

    pub fn analyze_optimized(&self, pe_data: &[u8], file_hash: &str) -> Result<Vec<MaliciousBehavior>> {
        // Verificar caché
        if let Some(cached) = self.cache.get(file_hash) {
            return Ok(cached);
        }

        // Canales para resultados parciales
        let (tx, rx) = bounded(4);
        
        // Análisis paralelo
        self.parallel_analysis(pe_data, tx)?;

        // Recolectar resultados
        let mut behaviors = Vec::new();
        drop(tx);
        for result in rx {
            behaviors.extend(result?);
        }

        // Analizar correlaciones
        let correlated = self.analyze_correlations(&behaviors).await;
        behaviors.extend(correlated);

        // Guardar en caché
        self.cache.insert(file_hash.to_string(), behaviors.clone());
        
        Ok(behaviors)
    }

    fn parallel_analysis(&self, pe_data: &[u8], tx: Sender<Result<Vec<MaliciousBehavior>>>) -> Result<()> {
        // Análisis de secciones PE
        let tx_clone = tx.clone();
        let pe_data = pe_data.to_vec();
        rayon::spawn(move || {
            let result = analyze_sections(&pe_data);
            tx_clone.send(result).ok();
        });

        // Análisis de recursos
        let tx_clone = tx.clone();
        let pe_data = pe_data.to_vec();
        rayon::spawn(move || {
            let result = analyze_resources(&pe_data);
            tx_clone.send(result).ok();
        });

        // Análisis de imports
        let tx_clone = tx.clone();
        let pe_data = pe_data.to_vec();
        rayon::spawn(move || {
            let result = analyze_imports(&pe_data);
            tx_clone.send(result).ok();
        });

        Ok(())
    }

    /// Detects common test viruses like EICAR
    pub fn detect_test_files(&self, content: &[u8]) -> Option<MaliciousBehavior> {
        // EICAR test string pattern
        const EICAR_PATTERN: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        
        // Check if content contains the EICAR test string
        if content.windows(EICAR_PATTERN.len()).any(|window| window == EICAR_PATTERN) {
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

        let behaviors = analyzer.analyze_imports_optimized(&imports, "test_hash").await;
        assert!(!behaviors.is_empty());
        assert!(behaviors.iter().any(|b| matches!(b.behavior_type, MaliciousBehaviorType::ProcessInjection)));
    }
    
    #[tokio::test]
    async fn test_eicar_detection() {
        let analyzer = BehaviorAnalyzer::new();
        // EICAR test string 
        let eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        
        // Test detection
        let result = analyzer.detect_test_files(eicar_content);
        
        // Verify result
        assert!(result.is_some(), "EICAR test file should be detected");
        if let Some(behavior) = result {
            assert!(matches!(behavior.behavior_type, MaliciousBehaviorType::TestFile));
            assert_eq!(behavior.description, "EICAR antivirus test file detected");
        }
    }
    
    #[tokio::test]
    async fn test_caching() {
        let analyzer = BehaviorAnalyzer::new();
        let imports = vec!["VirtualAllocEx".to_string()];
        let file_hash = "test_hash_2";

        // First analysis
        let first_result = analyzer.analyze_imports_optimized(&imports, file_hash).await;
        
        // Second analysis (should use cache)
        let second_result = analyzer.analyze_imports_optimized(&imports, file_hash).await;
        
        assert_eq!(first_result, second_result);
        assert_eq!(analyzer.get_stats().0, 1);
    }
    
    #[tokio::test]
    async fn test_confidence_thresholds() {
        let analyzer = BehaviorAnalyzer::new();
        let imports = vec!["DnsQuery".to_string()]; // Single C&C indicator

        let behaviors = analyzer.analyze_imports_optimized(&imports, "test_hash_3").await;
        assert!(behaviors.is_empty()); // Should not trigger with just one match
    }
} 