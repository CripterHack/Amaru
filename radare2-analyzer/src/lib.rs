use log::{debug, error, info, warn};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use thiserror::Error;
use serde::{Deserialize, Serialize};
use subprocess::{Exec, Redirection};
use std::str;
use tokio::task;
use md5;
use sha2::{Sha256, Digest};
use regex;
use std::sync::mpsc::Sender;
use std::time::Duration;
use tokio::process::Command as AsyncCommand;
use chrono;

pub mod events;
use events::{EventHandler, AnalyzerEvent};

/// Errors that can occur during Radare2 analysis
#[derive(Error, Debug)]
pub enum Radare2Error {
    #[error("Failed to initialize Radare2: {0}")]
    InitError(String),
    
    #[error("Failed to run Radare2 command: {0}")]
    CommandError(String),
    
    #[error("Failed to parse Radare2 output: {0}")]
    ParseError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Invalid file path: {0}")]
    InvalidPath(String),
    
    #[error("Radare2 not found in PATH")]
    NotFound,
    
    #[error("Radare2 no está instalado o no se encuentra en el PATH")]
    NotInstalled,
    
    #[error("Error al ejecutar Radare2: {0}")]
    ExecutionError(String),
    
    #[error("Error al analizar el archivo: {0}")]
    AnalysisError(String),
    
    #[error("Error al parsear JSON: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Result of a Radare2 analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub path: PathBuf,
    pub md5: Option<String>,
    pub sha256: Option<String>,
    pub file_type: Option<String>,
    pub size: Option<usize>,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub suspicious_strings: Vec<String>,
    pub risk_score: u8,
    pub analysis_time_ms: u64,
    pub behaviors: Vec<DetectedBehavior>,
    pub threat_category: Option<ThreatCategory>,
}

/// PE Section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub size: usize,
    pub vsize: usize,
    pub perm: String,
    pub md5: Option<String>,
    pub entropy: f64,
}

/// Import information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub name: String,
    pub type_: String,
    pub library: Option<String>,
}

/// Detected malicious behaviors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedBehavior {
    pub name: String,
    pub description: String,
    pub severity: BehaviorSeverity,
    pub evidence: Vec<String>,
}

/// Severity of a detected behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BehaviorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Detected threat category
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatCategory {
    Ransomware,
    Trojan,
    Backdoor,
    Rootkit,
    Spyware,
    Adware,
    Worm,
    Dropper,
    Miner,
    Hacktool,
    PUP,
    Unknown,
}

/// Radare2 analyzer configuration
#[derive(Debug, Clone)]
pub struct Radare2Config {
    pub radare2_path: Option<PathBuf>,
    pub timeout_seconds: u64,
    pub max_strings: usize,
    pub event_sender: Option<Sender<AnalyzerEvent>>,
}

impl Default for Radare2Config {
    fn default() -> Self {
        Self {
            radare2_path: None,
            timeout_seconds: 30,
            max_strings: 1000,
            event_sender: None,
        }
    }
}

/// Radare2 analyzer for static file analysis
pub struct Radare2Analyzer {
    config: Radare2Config,
}

impl Radare2Analyzer {
    /// Create a new Radare2 analyzer with the given configuration
    pub fn new(config: Radare2Config) -> Result<Self, Radare2Error> {
        // Check if r2 is available
        let r2_path = match &config.radare2_path {
            Some(path) => path.clone(),
            None => {
                // Try to find r2 in PATH
                match Self::find_radare2() {
                    Some(path) => path,
                    None => return Err(Radare2Error::NotFound),
                }
            }
        };
        
        // Verify r2 binary is executable
        if !r2_path.exists() {
            return Err(Radare2Error::NotFound);
        }
        
        Ok(Self { config })
    }
    
    /// Find radare2 binary in PATH
    fn find_radare2() -> Option<PathBuf> {
        // First check environment variable
        if let Ok(path) = env::var("AMARU_RADARE2_PATH") {
            let p = PathBuf::from(path).join("r2.exe");
            if p.exists() {
                return Some(p);
            }
        }
        
        // Check PATH
        if let Ok(output) = Command::new("where").arg("r2").output() {
            if output.status.success() {
                if let Ok(path) = String::from_utf8(output.stdout) {
                    let path = path.trim().to_string();
                    return Some(PathBuf::from(path));
                }
            }
        }
        
        // Fallback to common locations
        let common_locations = [
            r"C:\Program Files\radare2\bin\r2.exe",
            r"C:\radare2\bin\r2.exe",
        ];
        
        for location in common_locations.iter() {
            let path = PathBuf::from(location);
            if path.exists() {
                return Some(path);
            }
        }
        
        None
    }
    
    /// Analyze a file with Radare2
    pub async fn analyze_file<P: AsRef<Path>>(&self, file_path: P) -> Result<AnalysisResult, Radare2Error> {
        let path = file_path.as_ref();
        let start_time = std::time::Instant::now();
        
        // Notify analysis started
        if let Some(sender) = &self.config.event_sender {
            let _ = sender.send(AnalyzerEvent::AnalysisStarted {
                file_path: path.to_string_lossy().to_string(),
            });
        }
        
        // Create basic result
        let mut result = AnalysisResult {
            path: path.to_path_buf(),
            md5: None,
            sha256: None,
            file_type: None,
            size: None,
            sections: Vec::new(),
            imports: Vec::new(),
            suspicious_strings: Vec::new(),
            risk_score: 0,
            analysis_time_ms: 0,
            behaviors: Vec::new(),
            threat_category: None,
        };
        
        // Analyze file
        match self.analyze_file_internal(path, &mut result).await {
            Ok(_) => {
                // Notify analysis completed
                if let Some(sender) = &self.config.event_sender {
                    let _ = sender.send(AnalyzerEvent::AnalysisCompleted {
                        file_path: path.to_string_lossy().to_string(),
                        result: result.clone(),
                    });
                }
                Ok(result)
            }
            Err(e) => {
                // Notify error
                if let Some(sender) = &self.config.event_sender {
                    let _ = sender.send(AnalyzerEvent::AnalysisError {
                        file_path: path.to_string_lossy().to_string(),
                        error: e.to_string(),
                    });
                }
                Err(e)
            }
        }
    }
    
    /// Internal analysis function
    async fn analyze_file_internal<P: AsRef<Path>>(&self, path: P, result: &mut AnalysisResult) -> Result<(), Radare2Error> {
        let path = path.as_ref();
        let start_time = std::time::Instant::now();
        
        // Get file info
        self.get_file_info(path, result)?;
        
        // Get sections
        self.get_sections(path, result)?;
        
        // Get imports
        self.get_imports(path, result)?;
        
        // Get strings
        self.get_strings(path, result)?;
        
        // Analyze behaviors
        let behaviors = self.analyze_behaviors(path).await?;
        
        // Notify each detected behavior
        if let Some(sender) = &self.config.event_sender {
            for behavior in &behaviors {
                let _ = sender.send(AnalyzerEvent::BehaviorDetected {
                    file_path: path.to_string_lossy().to_string(),
                    behavior: behavior.clone(),
                });
            }
        }
        
        result.behaviors = behaviors;
        
        // Calculate risk score
        result.risk_score = self.calculate_risk_score(&result.behaviors);
        
        // Determine threat category
        result.threat_category = Some(self.determine_threat_category(&result.behaviors));
        
        // Notify if threat detected
        if let Some(sender) = &self.config.event_sender {
            if result.risk_score > 50 {
                let _ = sender.send(AnalyzerEvent::ThreatDetected {
                    file_path: path.to_string_lossy().to_string(),
                    category: result.threat_category.clone().unwrap_or(ThreatCategory::Unknown),
                    risk_score: result.risk_score,
                });
            }
        }
        
        // Set analysis time
        result.analysis_time_ms = start_time.elapsed().as_millis() as u64;
        
        Ok(())
    }
    
    /// Get basic file information
    fn get_file_info(&self, file_path: &Path, result: &mut AnalysisResult) -> Result<(), Radare2Error> {
        // Use r2 to get file info
        let output = self.run_r2_command(file_path, "-qj")?;
        
        // Parse JSON
        let info: serde_json::Value = serde_json::from_str(&output)
            .map_err(|e| Radare2Error::ParseError(format!("Failed to parse file info: {}", e)))?;
        
        // Extract information
        if let Some(core) = info.get("core") {
            if let Some(file) = core.get("file") {
                if let Some(size) = file.get("size") {
                    result.size = size.as_u64().map(|s| s as usize);
                }
                
                if let Some(md5) = file.get("md5") {
                    result.md5 = md5.as_str().map(String::from);
                }
                
                if let Some(sha256) = file.get("sha256") {
                    result.sha256 = sha256.as_str().map(String::from);
                }
            }
            
            if let Some(bin) = core.get("bin") {
                if let Some(type_) = bin.get("type") {
                    result.file_type = type_.as_str().map(String::from);
                }
            }
        }
        
        Ok(())
    }
    
    /// Get PE sections
    fn get_sections(&self, file_path: &Path, result: &mut AnalysisResult) -> Result<(), Radare2Error> {
        // Use r2 to get sections
        let output = self.run_r2_command(file_path, "-qj iSj")?;
        
        // Parse JSON
        let sections: Vec<serde_json::Value> = serde_json::from_str(&output)
            .map_err(|e| Radare2Error::ParseError(format!("Failed to parse sections: {}", e)))?;
        
        // Process sections
        for section in sections {
            let name = section.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let size = section.get("size").and_then(|s| s.as_u64()).unwrap_or(0) as usize;
            let vsize = section.get("vsize").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let perm = section.get("perm").and_then(|p| p.as_str()).unwrap_or("").to_string();
            let md5 = section.get("md5").and_then(|h| h.as_str()).map(String::from);
            let entropy = section.get("entropy").and_then(|e| e.as_f64()).unwrap_or(0.0);
            
            result.sections.push(Section {
                name,
                size,
                vsize,
                perm,
                md5,
                entropy,
            });
        }
        
        Ok(())
    }
    
    /// Get imports
    fn get_imports(&self, file_path: &Path, result: &mut AnalysisResult) -> Result<(), Radare2Error> {
        // Use r2 to get imports
        let output = self.run_r2_command(file_path, "-qj iij")?;
        
        // Parse JSON
        let imports: Vec<serde_json::Value> = serde_json::from_str(&output)
            .map_err(|e| Radare2Error::ParseError(format!("Failed to parse imports: {}", e)))?;
        
        // Process imports
        for import in imports {
            let name = import.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let type_ = import.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let library = import.get("libname").and_then(|l| l.as_str()).map(String::from);
            
            result.imports.push(Import {
                name,
                type_,
                library,
            });
        }
        
        Ok(())
    }
    
    /// Get strings and filter suspicious ones
    fn get_strings(&self, file_path: &Path, result: &mut AnalysisResult) -> Result<(), Radare2Error> {
        // Use r2 to get strings
        let output = self.run_r2_command(file_path, "-qj izj")?;
        
        // Parse JSON
        let strings: Vec<serde_json::Value> = serde_json::from_str(&output)
            .map_err(|e| Radare2Error::ParseError(format!("Failed to parse strings: {}", e)))?;
        
        // Suspicious patterns
        let suspicious_patterns = [
            "cmd.exe", "powershell", "http://", "https://",
            "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory",
            "HKEY_", "RegCreateKey", "RegSetValue",
            "WScript", "ShellExecute", "WinExec",
            "URLDownload", "socket", "connect",
            "crypt", "encrypt", "decrypt", "base64",
        ];
        
        // Process strings
        for string_obj in strings.iter().take(self.config.max_strings) {
            if let Some(string) = string_obj.get("string").and_then(|s| s.as_str()) {
                // Check if string matches any suspicious pattern
                for pattern in &suspicious_patterns {
                    if string.to_lowercase().contains(&pattern.to_lowercase()) {
                        result.suspicious_strings.push(string.to_string());
                        break;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Calculate risk score based on various indicators
    fn calculate_risk_score(&self, behaviors: &[DetectedBehavior]) -> u8 {
        let mut score = 0u8;
        
        for behavior in behaviors {
            score = score.saturating_add(match behavior.severity {
                BehaviorSeverity::Critical => 25,
                BehaviorSeverity::High => 15,
                BehaviorSeverity::Medium => 10,
                BehaviorSeverity::Low => 5,
            });
        }
        
        score.min(100)
    }
    
    /// Determine threat category based on detected behaviors
    fn determine_threat_category(&self, behaviors: &[DetectedBehavior]) -> ThreatCategory {
        let mut network_count = 0;
        let mut file_count = 0;
        let mut process_count = 0;
        let mut registry_count = 0;
        let mut anti_analysis_count = 0;
        let mut crypto_count = 0;
        
        for behavior in behaviors {
            match behavior.name.as_str() {
                "Network Communication" => network_count += 1,
                "File System Operations" => file_count += 1,
                "Process Manipulation" => process_count += 1,
                "Registry Manipulation" => registry_count += 1,
                "Anti-Analysis Techniques" => anti_analysis_count += 1,
                _ if behavior.name.contains("Crypt") => crypto_count += 1,
                _ => {}
            }
        }
        
        // Determine category based on most frequent behaviors
        if crypto_count > 0 && file_count > 0 {
            ThreatCategory::Ransomware
        } else if process_count > 0 && anti_analysis_count > 0 {
            ThreatCategory::Rootkit
        } else if network_count > 0 && process_count > 0 {
            ThreatCategory::Backdoor
        } else if network_count > 0 && file_count > 0 {
            ThreatCategory::Trojan
        } else if anti_analysis_count > 0 {
            ThreatCategory::Hacktool
        } else if network_count > 0 {
            ThreatCategory::Spyware
        } else {
            ThreatCategory::Unknown
        }
    }
    
    /// Run a Radare2 command and get the output
    fn run_r2_command(&self, file_path: &Path, args: &str) -> Result<String, Radare2Error> {
        let r2_path = match &self.config.radare2_path {
            Some(path) => path.clone(),
            None => {
                match Self::find_radare2() {
                    Some(path) => path,
                    None => return Err(Radare2Error::NotFound),
                }
            }
        };
        
        let file_path_str = file_path.to_string_lossy();
        let full_args = format!("{} {}", args, file_path_str);
        
        debug!("Running r2 command: {} {}", r2_path.display(), full_args);
        
        let result = Exec::cmd(r2_path)
            .args(full_args.split_whitespace().collect::<Vec<_>>().as_slice())
            .stdout(Redirection::Pipe)
            .stderr(Redirection::Pipe)
            .capture()
            .map_err(|e| Radare2Error::CommandError(format!("Failed to execute r2: {}", e)))?;
        
        if !result.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            return Err(Radare2Error::CommandError(format!("r2 command failed: {}", stderr)));
        }
        
        let stdout = String::from_utf8_lossy(&result.stdout).to_string();
        Ok(stdout)
    }

    /// Analizar comportamientos sospechosos
    async fn analyze_behaviors<P: AsRef<Path>>(&self, path: P) -> Result<Vec<DetectedBehavior>, Radare2Error> {
        let path = path.as_ref();
        let mut behaviors = Vec::new();
        
        // Obtener imports
        let imports = self.analyze_imports(path).await?;
        
        // Obtener strings
        let strings = self.analyze_strings(path).await?;
        
        // Analizar comportamientos de red
        self.analyze_network_behaviors(&imports, &strings, &mut behaviors);
        
        // Analizar comportamientos de sistema de archivos
        self.analyze_filesystem_behaviors(&imports, &strings, &mut behaviors);
        
        // Analizar comportamientos de proceso
        self.analyze_process_behaviors(&imports, &strings, &mut behaviors);
        
        // Analizar comportamientos de registro
        self.analyze_registry_behaviors(&imports, &strings, &mut behaviors);
        
        // Analizar comportamientos anti-análisis
        self.analyze_anti_analysis_behaviors(&imports, &strings, &mut behaviors);
        
        Ok(behaviors)
    }
    
    /// Analizar comportamientos de red
    fn analyze_network_behaviors(&self, imports: &[Import], strings: &StringsAnalysis, behaviors: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();
        
        // Buscar imports relacionados con red
        let network_imports = imports.iter()
            .filter(|i| {
                let name = i.name.to_lowercase();
                name.contains("socket") || name.contains("connect") || 
                name.contains("send") || name.contains("recv") ||
                name.contains("internet") || name.contains("url") ||
                name.contains("http") || name.contains("ftp")
            })
            .map(|i| format!("Import: {} from {}", i.name, i.library.as_ref().map(|l| format!("{}", l)).unwrap_or_default()))
            .collect::<Vec<_>>();
            
        evidence.extend(network_imports);
        
        // Buscar URLs y IPs en strings
        evidence.extend(strings.urls.iter().map(|s| format!("URL: {}", s)));
        evidence.extend(strings.ips.iter().map(|s| format!("IP: {}", s)));
        
        if !evidence.is_empty() {
            behaviors.push(DetectedBehavior {
                name: "Network Communication".to_string(),
                description: "El ejecutable realiza comunicaciones de red".to_string(),
                severity: if evidence.len() > 5 { BehaviorSeverity::High } else { BehaviorSeverity::Medium },
                evidence,
            });
        }
    }
    
    /// Analizar comportamientos de sistema de archivos
    fn analyze_filesystem_behaviors(&self, imports: &[Import], strings: &StringsAnalysis, behaviors: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();
        
        // Buscar imports relacionados con archivos
        let file_imports = imports.iter()
            .filter(|i| {
                let name = i.name.to_lowercase();
                name.contains("file") || name.contains("directory") ||
                name.contains("create") || name.contains("write") ||
                name.contains("delete") || name.contains("move")
            })
            .map(|i| format!("Import: {} from {}", i.name, i.library.as_ref().map(|l| format!("{}", l)).unwrap_or_default()))
            .collect::<Vec<_>>();
            
        evidence.extend(file_imports);
        
        // Buscar paths sospechosos
        evidence.extend(strings.file_paths.iter()
            .filter(|s| {
                let s = s.to_lowercase();
                s.contains("system32") || s.contains("windows") ||
                s.contains("temp") || s.contains("appdata")
            })
            .map(|s| format!("Path: {}", s)));
        
        if !evidence.is_empty() {
            behaviors.push(DetectedBehavior {
                name: "File System Operations".to_string(),
                description: "El ejecutable realiza operaciones sospechosas con archivos".to_string(),
                severity: if evidence.len() > 5 { BehaviorSeverity::High } else { BehaviorSeverity::Medium },
                evidence,
            });
        }
    }
    
    /// Analizar comportamientos de proceso
    fn analyze_process_behaviors(&self, imports: &[Import], strings: &StringsAnalysis, behaviors: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();
        
        // Buscar imports relacionados con procesos
        let process_imports = imports.iter()
            .filter(|i| {
                let name = i.name.to_lowercase();
                name.contains("process") || name.contains("thread") ||
                name.contains("virtual") || name.contains("memory") ||
                name.contains("inject") || name.contains("remote")
            })
            .map(|i| format!("Import: {} from {}", i.name, i.library.as_ref().map(|l| format!("{}", l)).unwrap_or_default()))
            .collect::<Vec<_>>();
            
        evidence.extend(process_imports);
        
        // Buscar strings relacionados con procesos
        evidence.extend(strings.suspicious_strings.iter()
            .filter(|s| {
                let s = s.to_lowercase();
                s.contains("cmd.exe") || s.contains("powershell") ||
                s.contains("wscript") || s.contains("rundll32")
            })
            .map(|s| format!("Process: {}", s)));
        
        if !evidence.is_empty() {
            let severity = if evidence.iter().any(|e| 
                e.to_lowercase().contains("inject") || 
                e.to_lowercase().contains("remote")) {
                BehaviorSeverity::Critical
            } else {
                BehaviorSeverity::High
            };
            
            behaviors.push(DetectedBehavior {
                name: "Process Manipulation".to_string(),
                description: "El ejecutable manipula otros procesos".to_string(),
                severity,
                evidence,
            });
        }
    }
    
    /// Analizar comportamientos de registro
    fn analyze_registry_behaviors(&self, imports: &[Import], strings: &StringsAnalysis, behaviors: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();
        
        // Buscar imports relacionados con registro
        let registry_imports = imports.iter()
            .filter(|i| {
                let name = i.name.to_lowercase();
                name.contains("reg") || name.contains("registry") ||
                name.contains("hkey") || name.contains("key")
            })
            .map(|i| format!("Import: {} from {}", i.name, i.library.as_ref().map(|l| format!("{}", l)).unwrap_or_default()))
            .collect::<Vec<_>>();
            
        evidence.extend(registry_imports);
        
        // Buscar claves de registro sospechosas
        evidence.extend(strings.registry_keys.iter()
            .filter(|s| {
                let s = s.to_lowercase();
                s.contains("run") || s.contains("startup") ||
                s.contains("system") || s.contains("policies")
            })
            .map(|s| format!("Registry: {}", s)));
        
        if !evidence.is_empty() {
            behaviors.push(DetectedBehavior {
                name: "Registry Manipulation".to_string(),
                description: "El ejecutable modifica el registro de Windows".to_string(),
                severity: BehaviorSeverity::High,
                evidence,
            });
        }
    }
    
    /// Analizar comportamientos anti-análisis
    fn analyze_anti_analysis_behaviors(&self, imports: &[Import], strings: &StringsAnalysis, behaviors: &mut Vec<DetectedBehavior>) {
        let mut evidence = Vec::new();
        
        // Buscar imports anti-análisis
        let anti_imports = imports.iter()
            .filter(|i| {
                let name = i.name.to_lowercase();
                name.contains("debug") || name.contains("checkremote") ||
                name.contains("isdebuggerpresent") || name.contains("outputdebug") ||
                name.contains("virtualprotect") || name.contains("sleep")
            })
            .map(|i| format!("Import: {} from {}", i.name, i.library.as_ref().map(|l| format!("{}", l)).unwrap_or_default()))
            .collect::<Vec<_>>();
            
        evidence.extend(anti_imports);
        
        // Buscar strings anti-análisis
        evidence.extend(strings.suspicious_strings.iter()
            .filter(|s| {
                let s = s.to_lowercase();
                s.contains("debug") || s.contains("sandbox") ||
                s.contains("virtual") || s.contains("vmware") ||
                s.contains("virtualbox") || s.contains("analysis")
            })
            .map(|s| format!("Anti-Analysis: {}", s)));
        
        if !evidence.is_empty() {
            behaviors.push(DetectedBehavior {
                name: "Anti-Analysis Techniques".to_string(),
                description: "El ejecutable intenta evadir el análisis".to_string(),
                severity: BehaviorSeverity::Critical,
                evidence,
            });
        }
    }

    /// Verificar la instalación de Radare2
    pub fn check_installation() -> bool {
        match Command::new("r2").arg("-v").output() {
            Ok(output) => {
                if !output.status.success() {
                    return false;
                }
                
                let version = String::from_utf8_lossy(&output.stdout);
                version.contains("radare2")
            }
            Err(_) => false
        }
    }
    
    /// Get installation instructions
    pub fn get_installation_instructions() -> String {
        let os = std::env::consts::OS;
        match os {
            "windows" => format!(
                "Para instalar Radare2 en Windows:\n\
                1. Descarga el instalador desde https://github.com/radareorg/radare2/releases\n\
                2. Ejecuta el instalador como administrador\n\
                3. Agrega C:\\radare2\\bin al PATH del sistema\n\
                4. Reinicia tu terminal"
            ),
            "linux" => format!(
                "Para instalar Radare2 en Linux:\n\
                1. sudo apt update\n\
                2. sudo apt install radare2\n\
                O compila desde fuente:\n\
                1. git clone https://github.com/radareorg/radare2\n\
                2. cd radare2\n\
                3. sys/install.sh"
            ),
            "macos" => format!(
                "Para instalar Radare2 en macOS:\n\
                1. brew install radare2\n\
                O compila desde fuente:\n\
                1. git clone https://github.com/radareorg/radare2\n\
                2. cd radare2\n\
                3. sys/install.sh"
            ),
            _ => "Por favor visita https://github.com/radareorg/radare2 para instrucciones de instalación".to_string(),
        }
    }
    
    /// Create a new Radare2 analyzer with installation verification
    pub async fn new_with_verification(config: Radare2Config) -> Result<Self, Radare2Error> {
        // Verify installation first
        if !Self::verify_installation() {
            let instructions = Self::get_installation_instructions();
            return Err(Radare2Error::NotInstalled);
        }
        
        Self::new(config)
    }
}

/// Helper function to check if any of the specified imports exist
fn has_imports(imports: &[Import], names: &[&str]) -> bool {
    for import in imports {
        for &name in names {
            if import.name.contains(name) {
                return true;
            }
        }
    }
    false
}

/// Helper function to check if any of the specified strings exist
fn has_strings(strings: &[String], patterns: &[&str]) -> bool {
    for string in strings {
        let lowercase = string.to_lowercase();
        for &pattern in patterns {
            if lowercase.contains(pattern) {
                return true;
            }
        }
    }
    false
}

/// Helper function to extract imports as evidence
fn imports_as_evidence(imports: &[Import], names: &[&str]) -> Vec<String> {
    let mut evidence = Vec::new();
    
    for import in imports {
        for &name in names {
            if import.name.contains(name) {
                let library = import.library.as_ref().map(|l| format!(" from {}", l)).unwrap_or_default();
                evidence.push(format!("Import: {}{}", import.name, library));
                break;
            }
        }
    }
    
    evidence
}

/// Helper function to extract strings as evidence
fn strings_as_evidence(strings: &[String], patterns: &[&str]) -> Vec<String> {
    let mut evidence = Vec::new();
    
    for string in strings {
        let lowercase = string.to_lowercase();
        for &pattern in patterns {
            if lowercase.contains(pattern) {
                evidence.push(format!("String: {}", string));
                break;
            }
        }
    }
    
    evidence
}

/// Información del encabezado PE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PEInfo {
    pub machine: String,
    pub subsystem: String,
    pub entry_point: u64,
    pub image_base: u64,
    pub characteristics: Vec<String>,
    pub dll_characteristics: Vec<String>,
}

impl PEInfo {
    /// Parse PE characteristics from a u16 value
    pub fn parse_characteristics(chars: u16) -> Vec<String> {
        let mut result = Vec::new();
        
        if chars & 0x0002 != 0 { result.push("EXECUTABLE".to_string()); }
        if chars & 0x0020 != 0 { result.push("LARGE_ADDRESS_AWARE".to_string()); }
        if chars & 0x0100 != 0 { result.push("32BIT".to_string()); }
        if chars & 0x2000 != 0 { result.push("DLL".to_string()); }
        
        result
    }
    
    /// Parse DLL characteristics from a u16 value
    pub fn parse_dll_characteristics(chars: u16) -> Vec<String> {
        let mut result = Vec::new();
        
        if chars & 0x0020 != 0 { result.push("HIGH_ENTROPY_VA".to_string()); }
        if chars & 0x0040 != 0 { result.push("DYNAMIC_BASE".to_string()); }
        if chars & 0x0080 != 0 { result.push("FORCE_INTEGRITY".to_string()); }
        if chars & 0x0100 != 0 { result.push("NX_COMPAT".to_string()); }
        if chars & 0x0200 != 0 { result.push("NO_ISOLATION".to_string()); }
        if chars & 0x0400 != 0 { result.push("NO_SEH".to_string()); }
        if chars & 0x0800 != 0 { result.push("NO_BIND".to_string()); }
        if chars & 0x2000 != 0 { result.push("WDM_DRIVER".to_string()); }
        if chars & 0x8000 != 0 { result.push("TERMINAL_SERVER_AWARE".to_string()); }
        
        result
    }
}

/// Análisis de strings encontrados
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringsAnalysis {
    pub suspicious_strings: Vec<SuspiciousString>,
    pub urls: Vec<String>,
    pub ips: Vec<String>,
    pub file_paths: Vec<String>,
    pub registry_keys: Vec<String>,
}

/// String sospechoso encontrado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousString {
    pub string: String,
    pub offset: u64,
    pub category: StringCategory,
    pub risk_level: RiskLevel,
}

/// Categorías de strings sospechosos
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringCategory {
    Command,
    API,
    Network,
    FileSystem,
    Registry,
    Crypto,
    AntiDebug,
    Other,
}

/// Niveles de riesgo
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Funciones auxiliares para análisis de strings
fn is_suspicious_string(s: &str) -> bool {
    let suspicious_patterns = [
        "cmd.exe", "powershell", "rundll32", "shell", "exec",
        "http://", "https://", "ftp://", 
        "HKEY_", "RegCreateKey", "RegSetValue",
        "CreateProcess", "CreateThread", "VirtualAlloc",
        "crypt", "encrypt", "decrypt",
        "password", "pwd", "login",
        "dump", "inject", "hook",
    ];
    
    suspicious_patterns.iter().any(|&pattern| s.to_lowercase().contains(pattern))
}

fn categorize_string(s: &str) -> StringCategory {
    let s = s.to_lowercase();
    
    if s.contains("cmd.exe") || s.contains("powershell") || s.contains("shell") {
        StringCategory::Command
    } else if s.contains("createprocess") || s.contains("virtualalloc") || s.contains("getprocaddress") {
        StringCategory::API
    } else if s.contains("http://") || s.contains("https://") || s.contains("ftp://") {
        StringCategory::Network
    } else if s.contains("\\") || s.contains(".exe") || s.contains(".dll") {
        StringCategory::FileSystem
    } else if s.contains("hkey_") || s.contains("registry") {
        StringCategory::Registry
    } else if s.contains("crypt") || s.contains("encrypt") || s.contains("decrypt") {
        StringCategory::Crypto
    } else if s.contains("debug") || s.contains("inject") || s.contains("hook") {
        StringCategory::AntiDebug
    } else {
        StringCategory::Other
    }
}

fn assess_string_risk(s: &str) -> RiskLevel {
    let s = s.to_lowercase();
    
    if s.contains("inject") || s.contains("hook") || s.contains("debug") {
        RiskLevel::Critical
    } else if s.contains("createprocess") || s.contains("virtualalloc") || s.contains("crypt") {
        RiskLevel::High
    } else if s.contains("http://") || s.contains("https://") || s.contains("hkey_") {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn parse_section_characteristics(perm: &str) -> Vec<String> {
    let mut chars = Vec::new();
    
    if perm.contains('r') {
        chars.push("read".to_string());
    }
    if perm.contains('w') {
        chars.push("write".to_string());
    }
    if perm.contains('x') {
        chars.push("execute".to_string());
    }
    if perm.contains("rw") {
        chars.push("rw".to_string());
    }
    if perm.contains("rx") {
        chars.push("rx".to_string());
    }
    if perm.contains("rwx") {
        chars.push("rwx".to_string());
    }
    
    chars
}

// Tests module
#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tempfile::tempdir;

    #[test]
    fn test_find_radare2() {
        let r2_path = Radare2Analyzer::find_radare2();
        println!("Radare2 path: {:?}", r2_path);
    }

    #[test]
    fn test_radare2_installation() {
        assert!(Radare2Analyzer::check_installation(), "Radare2 no está instalado");
    }

    #[tokio::test]
    async fn test_analyze_pe_info() {
        let config = Radare2Config::default();
        let analyzer = Radare2Analyzer::new(config);
        
        // Crear un archivo PE de prueba
        let mut temp_file = NamedTempFile::new().unwrap();
        let pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00";
        temp_file.write_all(pe_header).unwrap();
        
        let result = analyzer.analyze_pe_info(temp_file.path()).await;
        assert!(result.is_ok(), "El análisis PE falló");
    }

    #[tokio::test]
    async fn test_analyze_strings() {
        let config = Radare2Config::default();
        let analyzer = Radare2Analyzer::new(config);
        
        // Crear un archivo con strings de prueba
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_content = b"MZ\x90\x00http://malicious.com\x00HKEY_LOCAL_MACHINE\\Software\x00cmd.exe\x00";
        temp_file.write_all(test_content).unwrap();
        
        let result = analyzer.analyze_strings(temp_file.path()).await;
        assert!(result.is_ok(), "El análisis de strings falló");
        
        let strings = result.unwrap();
        assert!(!strings.urls.is_empty(), "No se detectaron URLs");
        assert!(!strings.registry_keys.is_empty(), "No se detectaron claves de registro");
    }

    #[tokio::test]
    async fn test_analyze_imports() {
        let config = Radare2Config::default();
        let analyzer = Radare2Analyzer::new(config);
        
        // Crear un archivo PE de prueba con imports
        let mut temp_file = NamedTempFile::new().unwrap();
        let pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00";
        temp_file.write_all(pe_header).unwrap();
        
        let result = analyzer.analyze_imports(temp_file.path()).await;
        assert!(result.is_ok(), "El análisis de imports falló");
    }

    #[tokio::test]
    async fn test_analyze_sections() {
        let config = Radare2Config::default();
        let analyzer = Radare2Analyzer::new(config);
        
        // Crear un archivo PE de prueba con secciones
        let mut temp_file = NamedTempFile::new().unwrap();
        let pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00";
        temp_file.write_all(pe_header).unwrap();
        
        let result = analyzer.analyze_sections(temp_file.path()).await;
        assert!(result.is_ok(), "El análisis de secciones falló");
    }

    #[test]
    fn test_is_suspicious_string() {
        assert!(is_suspicious_string("cmd.exe /c"), "cmd.exe debería ser sospechoso");
        assert!(is_suspicious_string("http://malicious.com"), "URL debería ser sospechosa");
        assert!(is_suspicious_string("HKEY_LOCAL_MACHINE"), "Clave de registro debería ser sospechosa");
        assert!(!is_suspicious_string("hello world"), "String normal no debería ser sospechoso");
    }

    #[test]
    fn test_categorize_string() {
        assert!(matches!(categorize_string("cmd.exe"), StringCategory::Command));
        assert!(matches!(categorize_string("http://example.com"), StringCategory::Network));
        assert!(matches!(categorize_string("C:\\Windows\\System32"), StringCategory::FileSystem));
        assert!(matches!(categorize_string("HKEY_LOCAL_MACHINE"), StringCategory::Registry));
    }

    #[test]
    fn test_assess_string_risk() {
        assert!(matches!(assess_string_risk("inject"), RiskLevel::Critical));
        assert!(matches!(assess_string_risk("CreateProcess"), RiskLevel::High));
        assert!(matches!(assess_string_risk("http://"), RiskLevel::Medium));
        assert!(matches!(assess_string_risk("readme.txt"), RiskLevel::Low));
    }

    #[test]
    fn test_parse_section_characteristics() {
        let rwx = parse_section_characteristics("rwx");
        assert!(rwx.contains(&"read".to_string()));
        assert!(rwx.contains(&"write".to_string()));
        assert!(rwx.contains(&"execute".to_string()));
        assert!(rwx.contains(&"rwx".to_string()));
        
        let rx = parse_section_characteristics("rx");
        assert!(rx.contains(&"read".to_string()));
        assert!(!rx.contains(&"write".to_string()));
        assert!(rx.contains(&"execute".to_string()));
        assert!(rx.contains(&"rx".to_string()));
    }

    #[tokio::test]
    async fn test_installation_verification() {
        let result = Radare2Analyzer::verify_installation().await;
        assert!(result.is_ok(), "La verificación de instalación debería funcionar");
        
        if let Ok(installed) = result {
            if !installed {
                println!("Radare2 no está instalado. Instrucciones de instalación:");
                println!("{}", Radare2Analyzer::get_installation_instructions());
            }
        }
    }
    
    #[tokio::test]
    async fn test_new_with_verification() {
        let config = Radare2Config::default();
        let result = Radare2Analyzer::new_with_verification(config).await;
        
        match result {
            Ok(_) => println!("Radare2 está instalado y configurado correctamente"),
            Err(e) => {
                if let Radare2Error::NotInstalled = e {
                    println!("Radare2 no está instalado. Instrucciones:");
                    println!("{}", Radare2Analyzer::get_installation_instructions());
                } else {
                    panic!("Error inesperado: {}", e);
                }
            }
        }
    }
} 