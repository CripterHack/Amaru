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
}

impl Default for Radare2Config {
    fn default() -> Self {
        Self {
            radare2_path: None,
            timeout_seconds: 30,
            max_strings: 1000,
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
    pub fn analyze_file(&self, file_path: &Path) -> Result<AnalysisResult, Radare2Error> {
        let start_time = std::time::Instant::now();
        
        if !file_path.exists() {
            return Err(Radare2Error::InvalidPath(format!("File not found: {:?}", file_path)));
        }
        
        // Create a basic result first
        let mut result = AnalysisResult {
            path: file_path.to_path_buf(),
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
        
        // Get file info
        self.get_file_info(file_path, &mut result)?;
        
        // Get sections
        self.get_sections(file_path, &mut result)?;
        
        // Get imports
        self.get_imports(file_path, &mut result)?;
        
        // Get strings
        self.get_strings(file_path, &mut result)?;
        
        // Calculate risk score
        self.calculate_risk_score(&mut result);
        
        // Set analysis time
        result.analysis_time_ms = start_time.elapsed().as_millis() as u64;
        
        Ok(result)
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
    fn calculate_risk_score(&self, result: &mut AnalysisResult) {
        let mut score = 0u8;
        
        // Analyze sections
        for section in &result.sections {
            // High entropy sections are suspicious (potential packed/encrypted code)
            if section.entropy > 7.0 {
                score += 15;
            } else if section.entropy > 6.5 {
                score += 5;
            }
            
            // Executable sections with unusual names
            if section.perm.contains("x") && !["text", "code", "data"].contains(&section.name.as_str()) {
                score += 10;
            }
        }
        
        // Analyze imports
        let suspicious_imports = [
            ("VirtualAlloc", 5), ("VirtualProtect", 5), ("WriteProcessMemory", 10),
            ("CreateRemoteThread", 15), ("LoadLibraryA", 5), ("GetProcAddress", 5),
            ("CreateProcess", 3), ("ShellExecute", 5), ("WinExec", 5),
            ("ReadProcessMemory", 5), ("TerminateProcess", 3), ("OpenProcess", 3),
            ("RegCreateKey", 3), ("RegSetValue", 3), ("InternetOpen", 2),
            ("InternetConnect", 2), ("HttpSendRequest", 2), ("URLDownloadToFile", 8),
            ("CreateService", 10), ("StartService", 5), ("CryptEncrypt", 5),
            ("CryptDecrypt", 5), ("CreateToolhelp32Snapshot", 5), ("Process32First", 5),
            ("Process32Next", 5), ("Thread32First", 5), ("Thread32Next", 5),
            ("FindResource", 3), ("LoadResource", 3), ("SetWindowsHookEx", 10),
            ("MapVirtualKey", 5), ("GetAsyncKeyState", 10), ("GetKeyState", 5),
            ("BitBlt", 3), ("GetDC", 3), ("CreateDC", 3),
        ];
        
        for import in &result.imports {
            for (name, value) in suspicious_imports.iter() {
                if import.name.contains(name) {
                    score = score.saturating_add(*value);
                    break;
                }
            }
        }
        
        // Analyze suspicious strings
        let suspicious_string_patterns = [
            ("cmd.exe", 5), ("powershell", 5), ("/c ", 5), ("-e ", 5),
            ("http://", 2), ("https://", 2), (".onion", 10), ("bitcoin", 8),
            ("ransom", 15), ("encrypt", 10), ("decrypt", 8), ("pastebin", 5),
            ("Your files", 5), ("payment", 5), ("malware", 5), ("virus", 5),
            ("hack", 5), ("crack", 5), ("keygen", 5), ("patch", 3),
            ("admin", 3), ("root", 3), ("system32", 3), ("\\\\admin$", 8),
            ("password", 3), ("username", 3), ("login", 3), ("logon", 3),
            ("backdoor", 10), ("trojan", 10), ("rootkit", 10), ("spyware", 8),
            ("worm", 8), ("botnet", 8), ("miner", 8), ("crypto", 5),
            ("\\x", 3), ("%x", 3), ("base64", 3), ("0x90", 10), // encoded content or NOP sled
        ];
        
        for string in &result.suspicious_strings {
            for (pattern, value) in suspicious_string_patterns.iter() {
                if string.to_lowercase().contains(pattern) {
                    score = score.saturating_add(*value);
                    break;
                }
            }
        }
        
        // Detect behaviors and categorize threat
        self.detect_behaviors(result);
        self.categorize_threat(result);
        
        // Additional score from behaviors
        for behavior in &result.behaviors {
            match behavior.severity {
                BehaviorSeverity::Low => score = score.saturating_add(5),
                BehaviorSeverity::Medium => score = score.saturating_add(10),
                BehaviorSeverity::High => score = score.saturating_add(15),
                BehaviorSeverity::Critical => score = score.saturating_add(25),
            }
        }
        
        // Cap the score at 100
        result.risk_score = std::cmp::min(score, 100);
    }
    
    /// Detect malicious behaviors in the analyzed file
    fn detect_behaviors(&self, result: &mut AnalysisResult) {
        let mut behaviors: Vec<DetectedBehavior> = Vec::new();
        
        // Detect process injection
        if has_imports(&result.imports, &["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]) {
            behaviors.push(DetectedBehavior {
                name: "Process Injection".to_string(),
                description: "The executable can inject code into other processes".to_string(),
                severity: BehaviorSeverity::High,
                evidence: imports_as_evidence(&result.imports, &["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]),
            });
        }
        
        // Detect keylogging
        if has_imports(&result.imports, &["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState"]) {
            behaviors.push(DetectedBehavior {
                name: "Keylogging".to_string(),
                description: "The executable can monitor keyboard input".to_string(),
                severity: BehaviorSeverity::High,
                evidence: imports_as_evidence(&result.imports, &["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState"]),
            });
        }
        
        // Detect persistence
        if has_imports(&result.imports, &["RegCreateKey", "RegSetValue"]) 
            && has_strings(&result.suspicious_strings, &["HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]) {
            behaviors.push(DetectedBehavior {
                name: "Registry Persistence".to_string(),
                description: "The executable can establish persistence through registry".to_string(),
                severity: BehaviorSeverity::Medium,
                evidence: strings_as_evidence(&result.suspicious_strings, &["HKEY_LOCAL_MACHINE", "Run"]),
            });
        }
        
        // Detect service installation
        if has_imports(&result.imports, &["CreateService", "StartService"]) {
            behaviors.push(DetectedBehavior {
                name: "Service Installation".to_string(),
                description: "The executable can install itself as a service".to_string(),
                severity: BehaviorSeverity::Medium,
                evidence: imports_as_evidence(&result.imports, &["CreateService", "StartService"]),
            });
        }
        
        // Detect network communication
        if has_imports(&result.imports, &["InternetOpen", "InternetConnect", "HttpSendRequest", "socket", "connect"]) {
            behaviors.push(DetectedBehavior {
                name: "Network Communication".to_string(),
                description: "The executable can communicate over the network".to_string(),
                severity: BehaviorSeverity::Medium,
                evidence: imports_as_evidence(&result.imports, &["InternetOpen", "InternetConnect", "HttpSendRequest", "socket", "connect"]),
            });
        }
        
        // Detect file encryption (potential ransomware)
        if has_imports(&result.imports, &["CryptEncrypt", "CryptAcquireContext"]) 
            && has_strings(&result.suspicious_strings, &["ransom", "encrypt", "decrypt", "bitcoin", "payment"]) {
            behaviors.push(DetectedBehavior {
                name: "File Encryption".to_string(),
                description: "The executable can encrypt files (potential ransomware)".to_string(),
                severity: BehaviorSeverity::Critical,
                evidence: strings_as_evidence(&result.suspicious_strings, &["ransom", "encrypt", "decrypt", "bitcoin", "payment"]),
            });
        }
        
        // Detect process enumeration (used for targeting)
        if has_imports(&result.imports, &["CreateToolhelp32Snapshot", "Process32First", "Process32Next"]) {
            behaviors.push(DetectedBehavior {
                name: "Process Enumeration".to_string(),
                description: "The executable can enumerate running processes".to_string(),
                severity: BehaviorSeverity::Medium,
                evidence: imports_as_evidence(&result.imports, &["CreateToolhelp32Snapshot", "Process32First", "Process32Next"]),
            });
        }
        
        // Detect anti-debugging
        if has_imports(&result.imports, &["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString"]) {
            behaviors.push(DetectedBehavior {
                name: "Anti-Debugging".to_string(),
                description: "The executable attempts to detect debuggers".to_string(),
                severity: BehaviorSeverity::Medium,
                evidence: imports_as_evidence(&result.imports, &["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString"]),
            });
        }
        
        // Detect screenshot capability
        if has_imports(&result.imports, &["BitBlt", "GetDC", "CreateDC"]) {
            behaviors.push(DetectedBehavior {
                name: "Screen Capture".to_string(),
                description: "The executable can capture screen content".to_string(),
                severity: BehaviorSeverity::Medium,
                evidence: imports_as_evidence(&result.imports, &["BitBlt", "GetDC", "CreateDC"]),
            });
        }
        
        // Detect potential shellcode
        for section in &result.sections {
            if section.perm.contains("x") && section.entropy > 7.0 {
                behaviors.push(DetectedBehavior {
                    name: "Potential Shellcode".to_string(),
                    description: format!("Section {} has high entropy ({:.2}) and is executable", section.name, section.entropy),
                    severity: BehaviorSeverity::High,
                    evidence: vec![format!("Section: {}, Entropy: {:.2}, Permissions: {}", section.name, section.entropy, section.perm)],
                });
                break;
            }
        }
        
        result.behaviors = behaviors;
    }
    
    /// Categorize the threat based on detected behaviors
    fn categorize_threat(&self, result: &mut AnalysisResult) {
        // Default to Unknown
        let mut category = ThreatCategory::Unknown;
        
        // Check for ransomware indicators
        if has_strings(&result.suspicious_strings, &["ransom", "encrypt", "decrypt", "bitcoin", "payment", "your files"]) 
            && has_imports(&result.imports, &["CryptEncrypt", "FindFirstFile", "FindNextFile"]) {
            category = ThreatCategory::Ransomware;
        }
        // Check for trojan indicators
        else if result.behaviors.iter().any(|b| b.name == "Process Injection") || 
                 result.behaviors.iter().any(|b| b.name == "Keylogging") {
            category = ThreatCategory::Trojan;
        }
        // Check for backdoor indicators
        else if has_imports(&result.imports, &["socket", "bind", "listen", "accept"]) &&
                 result.behaviors.iter().any(|b| b.name == "Registry Persistence") {
            category = ThreatCategory::Backdoor;
        }
        // Check for rootkit indicators
        else if has_strings(&result.suspicious_strings, &["ntoskrnl", "driver", ".sys"]) &&
                 has_imports(&result.imports, &["DeviceIoControl"]) {
            category = ThreatCategory::Rootkit;
        }
        // Check for spyware indicators
        else if result.behaviors.iter().any(|b| b.name == "Screen Capture") ||
                 result.behaviors.iter().any(|b| b.name == "Keylogging") {
            category = ThreatCategory::Spyware;
        }
        // Check for cryptominer indicators
        else if has_strings(&result.suspicious_strings, &["miner", "crypto", "monero", "stratum", "xmr"]) {
            category = ThreatCategory::Miner;
        }
        // Check for worm indicators
        else if has_imports(&result.imports, &["socket", "connect"]) &&
                 has_strings(&result.suspicious_strings, &["\\\\", "share", "admin$", "c$"]) {
            category = ThreatCategory::Worm;
        }
        
        result.threat_category = Some(category);
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

// Tests module
#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    
    #[test]
    fn test_find_radare2() {
        let r2_path = Radare2Analyzer::find_radare2();
        println!("Radare2 path: {:?}", r2_path);
    }
} 