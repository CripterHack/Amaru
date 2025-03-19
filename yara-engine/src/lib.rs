use log::{debug, error, info, warn};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use thiserror::Error;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Errors that can occur during YARA operations
#[derive(Error, Debug)]
pub enum YaraError {
    #[error("Failed to initialize YARA: {0}")]
    InitError(String),
    
    #[error("Failed to compile rules: {0}")]
    CompileError(String),
    
    #[error("Failed to scan target: {0}")]
    ScanError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Invalid file path: {0}")]
    InvalidPath(String),
}

/// Result of a YARA scan
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub path: PathBuf,
    pub matched_rules: Vec<MatchedRule>,
    pub scan_time_ms: u64,
    pub error: Option<String>,
}

/// A rule that matched during scanning
#[derive(Debug, Clone)]
pub struct MatchedRule {
    pub name: String,
    pub meta: HashMap<String, String>,
    pub tags: Vec<String>,
    pub strings: Vec<MatchedString>,
}

/// A string that matched during scanning
#[derive(Debug, Clone)]
pub struct MatchedString {
    pub id: String,
    pub offset: usize,
    pub data: Vec<u8>,
}

/// YARA engine configuration
#[derive(Debug, Clone)]
pub struct YaraConfig {
    pub rules_path: PathBuf,
    pub custom_rules_path: Option<PathBuf>,
    pub max_strings_per_rule: usize,
    pub timeout_seconds: u64,
    pub compile_externals: HashMap<String, String>,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            rules_path: PathBuf::from("./signatures"),
            custom_rules_path: Some(PathBuf::from("./signatures/custom")),
            max_strings_per_rule: 10000,
            timeout_seconds: 60,
            compile_externals: HashMap::new(),
        }
    }
}

/// YARA engine for malware scanning
pub struct YaraEngine {
    config: YaraConfig,
    rules: Arc<Mutex<Option<yara::Rules>>>,
    rule_count: Arc<Mutex<usize>>,
}

impl YaraEngine {
    /// Create a new YARA engine with the given configuration
    pub fn new(config: YaraConfig) -> Result<Self, YaraError> {
        // Initialize YARA library
        yara::initialize().map_err(|e| YaraError::InitError(e.to_string()))?;
        
        let engine = Self {
            config,
            rules: Arc::new(Mutex::new(None)),
            rule_count: Arc::new(Mutex::new(0)),
        };
        
        // Load rules
        engine.load_rules()?;
        
        Ok(engine)
    }
    
    /// Load YARA rules from the configured paths
    pub fn load_rules(&self) -> Result<(), YaraError> {
        info!("Loading YARA rules from: {:?}", self.config.rules_path);
        
        let mut compiler = yara::Compiler::new().map_err(|e| YaraError::InitError(e.to_string()))?;
        
        // Add externals
        for (name, value) in &self.config.compile_externals {
            compiler.define_variable(name, value).map_err(|e| YaraError::CompileError(e.to_string()))?;
        }
        
        // Load rules from main rules path
        self.add_rules_from_path(&mut compiler, &self.config.rules_path)?;
        
        // Load custom rules if configured
        if let Some(custom_path) = &self.config.custom_rules_path {
            self.add_rules_from_path(&mut compiler, custom_path)?;
        }
        
        // Compile rules
        let rules = compiler.compile_rules().map_err(|e| YaraError::CompileError(e.to_string()))?;
        
        // Store compiled rules
        let mut rules_lock = self.rules.lock().unwrap();
        *rules_lock = Some(rules);
        
        let rule_count = compiler.get_rules_count().unwrap_or(0);
        let mut count_lock = self.rule_count.lock().unwrap();
        *count_lock = rule_count;
        
        info!("Loaded {} YARA rules", rule_count);
        
        Ok(())
    }
    
    /// Add rules from a directory path
    fn add_rules_from_path(&self, compiler: &mut yara::Compiler, dir_path: &Path) -> Result<(), YaraError> {
        if !dir_path.exists() {
            return Err(YaraError::InvalidPath(format!("Path does not exist: {:?}", dir_path)));
        }
        
        if dir_path.is_file() && dir_path.extension().map_or(false, |ext| ext == "yar" || ext == "yara") {
            self.add_rule_file(compiler, dir_path)?;
            return Ok(());
        }
        
        // Walk directory for rule files
        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() && path.extension().map_or(false, |ext| ext == "yar" || ext == "yara") {
                self.add_rule_file(compiler, &path)?;
            } else if path.is_dir() {
                self.add_rules_from_path(compiler, &path)?;
            }
        }
        
        Ok(())
    }
    
    /// Add a single rule file to the compiler
    fn add_rule_file(&self, compiler: &mut yara::Compiler, file_path: &Path) -> Result<(), YaraError> {
        debug!("Loading YARA rule file: {:?}", file_path);
        
        let mut file = File::open(file_path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        
        let namespace = file_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("default");
        
        compiler
            .add_rules_str(&content, namespace)
            .map_err(|e| YaraError::CompileError(format!("In file {:?}: {}", file_path, e)))?;
        
        Ok(())
    }
    
    /// Scan a file with the loaded YARA rules
    pub fn scan_file(&self, file_path: &Path) -> Result<ScanResult, YaraError> {
        let start_time = Instant::now();
        let path_buf = file_path.to_path_buf();
        
        // Check if rules are loaded
        let rules_lock = self.rules.lock().unwrap();
        let rules = rules_lock.as_ref().ok_or_else(|| YaraError::InitError("YARA rules not loaded".to_string()))?;
        
        // Scan the file
        match rules.scan_file(file_path) {
            Ok(scan_results) => {
                let matched_rules = scan_results
                    .iter()
                    .map(|rule| {
                        MatchedRule {
                            name: rule.identifier.to_string(),
                            meta: rule.metadatas.iter().map(|m| (m.identifier.to_string(), m.value.to_string())).collect(),
                            tags: rule.tags.iter().map(|t| t.to_string()).collect(),
                            strings: rule.strings.iter().map(|s| {
                                MatchedString {
                                    id: s.identifier.to_string(),
                                    offset: s.offset as usize,
                                    data: s.data.to_vec(),
                                }
                            }).collect(),
                        }
                    })
                    .collect();
                
                let scan_time = start_time.elapsed().as_millis() as u64;
                
                Ok(ScanResult {
                    path: path_buf,
                    matched_rules,
                    scan_time_ms: scan_time,
                    error: None,
                })
            },
            Err(e) => {
                let scan_time = start_time.elapsed().as_millis() as u64;
                
                Ok(ScanResult {
                    path: path_buf,
                    matched_rules: Vec::new(),
                    scan_time_ms: scan_time,
                    error: Some(e.to_string()),
                })
            }
        }
    }
    
    /// Scan memory with the loaded YARA rules
    pub fn scan_memory(&self, buffer: &[u8]) -> Result<Vec<MatchedRule>, YaraError> {
        // Check if rules are loaded
        let rules_lock = self.rules.lock().unwrap();
        let rules = rules_lock.as_ref().ok_or_else(|| YaraError::InitError("YARA rules not loaded".to_string()))?;
        
        // Scan the memory buffer
        match rules.scan_mem(buffer) {
            Ok(scan_results) => {
                let matched_rules = scan_results
                    .iter()
                    .map(|rule| {
                        MatchedRule {
                            name: rule.identifier.to_string(),
                            meta: rule.metadatas.iter().map(|m| (m.identifier.to_string(), m.value.to_string())).collect(),
                            tags: rule.tags.iter().map(|t| t.to_string()).collect(),
                            strings: rule.strings.iter().map(|s| {
                                MatchedString {
                                    id: s.identifier.to_string(),
                                    offset: s.offset as usize,
                                    data: s.data.to_vec(),
                                }
                            }).collect(),
                        }
                    })
                    .collect();
                
                Ok(matched_rules)
            },
            Err(e) => Err(YaraError::ScanError(e.to_string())),
        }
    }
    
    /// Scan a directory recursively with the loaded YARA rules
    pub fn scan_directory(&self, dir_path: &Path, recursive: bool) -> Result<Vec<ScanResult>, YaraError> {
        if !dir_path.exists() || !dir_path.is_dir() {
            return Err(YaraError::InvalidPath(format!("Invalid directory path: {:?}", dir_path)));
        }
        
        let mut results = Vec::new();
        
        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                match self.scan_file(&path) {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        warn!("Failed to scan file {:?}: {}", path, e);
                        // Continue scanning other files
                    }
                }
            } else if path.is_dir() && recursive {
                match self.scan_directory(&path, recursive) {
                    Ok(mut dir_results) => results.append(&mut dir_results),
                    Err(e) => {
                        warn!("Failed to scan directory {:?}: {}", path, e);
                        // Continue scanning other directories
                    }
                }
            }
        }
        
        Ok(results)
    }
    
    /// Scan a process by PID with the loaded YARA rules
    #[cfg(target_os = "windows")]
    pub fn scan_process(&self, pid: u32) -> Result<ScanResult, YaraError> {
        use std::ffi::CString;
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::winnt::{PROCESS_VM_READ, PROCESS_QUERY_INFORMATION};
        use std::ptr;
        
        let start_time = std::time::Instant::now();
        
        // Check if rules are loaded
        let rules_lock = self.rules.lock().unwrap();
        let rules = rules_lock.as_ref().ok_or_else(|| YaraError::InitError("YARA rules not loaded".to_string()))?;
        
        // Open the process
        let handle = unsafe {
            OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                0,
                pid,
            )
        };
        
        if handle == ptr::null_mut() {
            return Err(YaraError::ScanError(format!("Failed to open process with PID {}", pid)));
        }
        
        // Create a process identifier for yara
        let id = format!("pid:{}", pid);
        let c_id = CString::new(id).unwrap();
        
        // Scan the process
        let scan_result = match rules.scan_proc(pid) {
            Ok(scan_results) => {
                let matched_rules = scan_results
                    .iter()
                    .map(|rule| {
                        MatchedRule {
                            name: rule.identifier.to_string(),
                            meta: rule.metadatas.iter().map(|m| (m.identifier.to_string(), m.value.to_string())).collect(),
                            tags: rule.tags.iter().map(|t| t.to_string()).collect(),
                            strings: rule.strings.iter().map(|s| {
                                MatchedString {
                                    id: s.identifier.to_string(),
                                    offset: s.offset as usize,
                                    data: s.data.to_vec(),
                                }
                            }).collect(),
                        }
                    })
                    .collect();
                
                ScanResult {
                    path: PathBuf::from(format!("process:{}", pid)),
                    matched_rules,
                    scan_time_ms: start_time.elapsed().as_millis() as u64,
                    error: None,
                }
            },
            Err(e) => {
                ScanResult {
                    path: PathBuf::from(format!("process:{}", pid)),
                    matched_rules: Vec::new(),
                    scan_time_ms: start_time.elapsed().as_millis() as u64,
                    error: Some(e.to_string()),
                }
            }
        };
        
        // Close the process handle
        unsafe {
            CloseHandle(handle);
        }
        
        Ok(scan_result)
    }
    
    /// Get the number of loaded rules
    pub fn get_rule_count(&self) -> usize {
        *self.rule_count.lock().unwrap()
    }
    
    /// Get a copy of the current configuration
    pub fn get_config(&self) -> YaraConfig {
        self.config.clone()
    }
    
    /// Reload rules from disk
    pub fn reload_rules(&self) -> Result<(), YaraError> {
        self.load_rules()
    }
}

impl Drop for YaraEngine {
    fn drop(&mut self) {
        // Finalize YARA when the engine is dropped
        if let Err(e) = yara::finalize() {
            error!("Failed to finalize YARA: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    
    #[test]
    fn test_load_rules() {
        let temp_dir = tempdir().unwrap();
        let rule_path = temp_dir.path().join("test.yar");
        
        // Create a test rule
        let rule_content = r#"
        rule TestRule {
            meta:
                description = "Test rule"
                severity = "low"
            strings:
                $test = "test string"
            condition:
                $test
        }
        "#;
        
        let mut file = File::create(&rule_path).unwrap();
        file.write_all(rule_content.as_bytes()).unwrap();
        
        // Create config pointing to our test rule
        let config = YaraConfig {
            rules_path: temp_dir.path().to_path_buf(),
            custom_rules_path: None,
            max_strings_per_rule: 1000,
            timeout_seconds: 10,
            compile_externals: HashMap::new(),
        };
        
        // Initialize engine
        let engine = YaraEngine::new(config).unwrap();
        
        // Check rule count
        assert_eq!(engine.get_rule_count(), 1);
    }
} 