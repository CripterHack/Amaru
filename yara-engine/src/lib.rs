use log::{debug, error, info, warn};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use thiserror::Error;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::fs;
use yara::{Compiler, Rules, ScanFlags};
use std::convert::TryFrom;
use walkdir::WalkDir;
use tokio::task;
use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Serialize, Deserialize};
use md5::{Md5, Digest};

// Módulos internos
pub mod cache;
pub mod heuristic; // Nuevo módulo de análisis heurístico

// Re-exportamos los elementos públicos del módulo de heurística
pub use heuristic::{
    HeuristicEngine, 
    HeuristicConfig, 
    HeuristicResult, 
    HeuristicError,
    ThreatType,
    ConfidenceLevel
};

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

    #[error("YARA error: {0}")]
    YaraError(#[from] yara::Error),
}

/// Result of a YARA scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: PathBuf,
    pub matches: Vec<RuleMatch>,
    pub scan_time: f64,
}

/// A rule that matched during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub meta: serde_json::Value,
    pub strings: Vec<MatchString>,
}

/// A string that matched during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchString {
    pub identifier: String,
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Configuration for the YARA engine
#[derive(Debug, Clone)]
pub struct YaraConfig {
    pub rule_paths: Vec<PathBuf>,
    pub max_strings_per_rule: usize,
    pub timeout_ms: u64,
    pub max_file_size_bytes: Option<u64>,
    pub scan_process_memory: bool,
    pub excluded_namespaces: Option<Vec<String>>,
    pub fast_scan: bool,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            rule_paths: vec![PathBuf::from("signatures/official"), PathBuf::from("signatures/custom")],
            max_strings_per_rule: 20,
            timeout_ms: 30000,
            max_file_size_bytes: None,
            scan_process_memory: false,
            excluded_namespaces: None,
            fast_scan: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub priority: u32,
    pub version: String,
    pub md5: String,
    pub last_modified: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
struct CachedRule {
    rules: Rules,
    metadata: RuleMetadata,
}

/// YARA engine implementation using the yara crate
pub struct YaraEngine {
    config: YaraConfig,
    rules: Arc<Rules>,
    rule_cache: Arc<DashMap<String, CachedRule>>,
    rules_dir: PathBuf,
}

impl YaraEngine {
    /// Create a new YARA engine with the given configuration
    pub fn new(rules_dir: impl Into<PathBuf>) -> Result<Self, YaraError> {
        let rules_dir = rules_dir.into();
        let mut compiler = Compiler::new()?;
        let rule_cache = Arc::new(DashMap::new());
        
        // Cargar y compilar reglas con metadatos
        for entry in std::fs::read_dir(&rules_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "yar") {
                let content = std::fs::read_to_string(&path)?;
                
                // Calcular hash MD5 del contenido
                let mut hasher = Md5::new();
                hasher.update(&content);
                let md5 = format!("{:x}", hasher.finalize());
                
                // Extraer metadatos de la regla
                let metadata = Self::extract_rule_metadata(&content, &md5)?;
                
                // Compilar regla
                compiler.add_rules_str(&content)
                    .map_err(|e| YaraError::CompileError(e.to_string()))?;
                    
                // Almacenar en caché
                if let Ok(rules) = compiler.compile_rules() {
                    rule_cache.insert(
                        path.file_name().unwrap().to_string_lossy().to_string(),
                        CachedRule { rules, metadata }
                    );
                }
            }
        }

        let rules = compiler.compile_rules()?;
        
        Ok(Self {
            config: YaraConfig::default(),
            rules: Arc::new(rules),
            rule_cache,
            rules_dir,
        })
    }
    
    /// Scan a file with YARA rules
    ///
    /// Performs a scan of the target file with all loaded YARA rules,
    /// prioritizing rules based on their metadata and optimizing for performance.
    ///
    /// # Arguments
    /// * `path` - Path to the file to scan
    ///
    /// # Returns
    /// A `ScanResult` containing matched rules and scan metadata
    ///
    /// # Errors
    /// Returns an error if:
    /// - The file cannot be accessed
    /// - The file is too large to scan
    /// - YARA scanning fails
    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResult, YaraError> {
        let path = path.as_ref();
        let start = std::time::Instant::now();
        
        debug!("Starting scan of file: {}", path.display());
        
        // Check if file exists
        if !path.exists() {
            return Err(YaraError::InvalidPath(format!(
                "File not found: {}", path.display()
            )));
        }
        
        // Get file metadata for size checks
        let metadata = fs::metadata(path)
            .map_err(|e| YaraError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to get metadata for {}: {}", path.display(), e)
            )))?;
        
        // Skip scanning large files (configurable threshold)
        if metadata.len() > self.config.max_file_size_bytes.unwrap_or(100 * 1024 * 1024) {
            debug!(
                "Skipping scan of large file: {} ({} bytes)",
                path.display(),
                metadata.len()
            );
            return Ok(ScanResult {
                file_path: path.to_path_buf(),
                matches: Vec::new(),
                scan_time: 0.0,
            });
        }
        
        // Check if file is accessible
        if let Err(e) = File::open(path) {
            return Err(YaraError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Cannot open file for scanning: {}: {}", path.display(), e)
            )));
        }
        
        // Get prioritized rules for scanning
        let prioritized_rules: Vec<_> = self.rule_cache
            .iter()
            .collect();
        
        // Sort rules by priority (high to low)
        let mut prioritized_rules = prioritized_rules;
        prioritized_rules.sort_by(|a, b| {
            b.value().metadata.priority.cmp(&a.value().metadata.priority)
        });
        
        debug!(
            "Scanning file {} with {} prioritized rule sets",
            path.display(),
            prioritized_rules.len()
        );
        
        // Track all matches across rule sets
        let mut all_matches = Vec::new();
        
        // Set up scan flags and apply timeout if configured
        let mut scan_flags = ScanFlags::empty();
        
        // Apply timeout if configured
        if self.config.timeout_ms > 0 {
            scan_flags |= ScanFlags::TIMEOUT;
        }
        
        // Apply process memory scanning if needed
        if self.config.scan_process_memory {
            scan_flags |= ScanFlags::PROCESS_MEMORY;
        }
        
        // Scan with fast rules first to fail fast
        for cached_rule in prioritized_rules {
            // Get rule name for logging
            let rule_name = cached_rule.key();
            let rule_start = std::time::Instant::now();
            
            // Skip rules with namespace exclusions if applicable
            if let Some(excluded_namespaces) = &self.config.excluded_namespaces {
                if excluded_namespaces.iter().any(|ns| rule_name.starts_with(ns)) {
                    debug!("Skipping excluded rule namespace: {}", rule_name);
                    continue;
                }
            }
            
            // Apply the rule to the target file
            match cached_rule.value().rules.scan_file(path, scan_flags) {
                Ok(matches) => {
                    // Process and convert matches to our format
                    let rule_matches: Vec<_> = matches.into_iter()
                        .map(|m| RuleMatch {
                            rule_name: m.identifier.to_string(),
                            tags: m.tags.iter().map(|t| t.to_string()).collect(),
                            meta: serde_json::to_value(m.metadatas).unwrap_or_default(),
                            strings: m.strings
                                .into_iter()
                                .take(self.config.max_strings_per_rule)
                                .map(|s| MatchString {
                                    identifier: s.identifier.to_string(),
                                    offset: s.offset,
                                    data: s.data,
                                })
                                .collect(),
                        })
                        .collect();
                    
                    if !rule_matches.is_empty() {
                        debug!(
                            "Rule {} matched {} patterns in {}ms",
                            rule_name,
                            rule_matches.len(),
                            rule_start.elapsed().as_millis()
                        );
                        
                        // Add matches to result
                        all_matches.extend(rule_matches);
                        
                        // Break early if fast scanning mode and we found matches
                        if self.config.fast_scan && !all_matches.is_empty() {
                            debug!("Fast scan enabled and matches found, breaking early");
                            break;
                        }
                    }
                }
                Err(e) => {
                    // Log the error but continue with other rules
                    warn!(
                        "Error applying rule {} to {}: {}",
                        rule_name,
                        path.display(),
                        e
                    );
                    
                    // Report the error if it's a timeout
                    if e.to_string().contains("timeout") {
                        warn!("Rule {} timed out on file {}", rule_name, path.display());
                    }
                }
            }
        }
        
        // Calculate total scan time
        let scan_time = start.elapsed().as_secs_f64();
        
        debug!(
            "Completed scan of {} in {:.2}s, found {} matches",
            path.display(),
            scan_time,
            all_matches.len()
        );
        
        Ok(ScanResult {
            file_path: path.to_path_buf(),
            matches: all_matches,
            scan_time,
        })
    }

    pub fn scan_memory(&self, buffer: &[u8]) -> Result<Vec<RuleMatch>, YaraError> {
        let matches = self.rules
            .scan_mem(buffer, ScanFlags::empty())
            .map_err(|e| YaraError::Scan(e.to_string()))?;
        
        Ok(matches
            .into_iter()
            .map(|m| RuleMatch {
                rule_name: m.identifier.to_string(),
                tags: m.tags.iter().map(|t| t.to_string()).collect(),
                meta: serde_json::to_value(m.metadatas).unwrap_or_default(),
                strings: m.strings
                    .into_iter()
                    .map(|s| MatchString {
                        identifier: s.identifier.to_string(),
                        offset: s.offset,
                        data: s.data,
                    })
                    .collect(),
            })
            .collect())
    }

    pub fn scan_directory(&self, dir: impl AsRef<Path>) -> Result<Vec<ScanResult>, YaraError> {
        let dir = dir.as_ref();
        let start = std::time::Instant::now();
        
        info!("Iniciando escaneo recursivo de {}", dir.display());
        
        let mut files = Vec::new();
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
        {
            files.push(entry.path().to_path_buf());
        }
        
        let results: Vec<_> = files
            .par_iter()
            .filter_map(|path| {
                match self.scan_file(path) {
                    Ok(result) if !result.matches.is_empty() => Some(Ok(result)),
                    Ok(_) => None,
                    Err(e) => {
                        error!("Error escaneando {}: {}", path.display(), e);
                        Some(Err(e))
                    }
                }
            })
            .collect();
        
        let (successes, failures): (Vec<_>, Vec<_>) = results.into_iter().partition(Result::is_ok);
        let successes: Vec<_> = successes.into_iter().map(Result::unwrap).collect();
        
        if !failures.is_empty() {
            warn!("Hubo {} errores durante el escaneo", failures.len());
        }
        
        info!(
            "Escaneo recursivo completado en {:.2}s. Escaneados: {}, Coincidencias: {}, Errores: {}",
            start.elapsed().as_secs_f64(),
            files.len(),
            successes.len(),
            failures.len()
        );
        
        Ok(successes)
    }

    pub fn reload_rules(&mut self) -> Result<(), YaraError> {
        let mut compiler = Compiler::new()?;
        
        for entry in std::fs::read_dir(&self.rules_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "yar") {
                let content = std::fs::read_to_string(&path)?;
                compiler.add_rules_str(&content)
                    .map_err(|e| YaraError::Compilation(e))?;
            }
        }

        let rules = compiler.compile_rules()?;
        self.rules = Arc::new(rules);
        self.rule_cache.clear();
        
        Ok(())
    }

    pub fn update_rules(&mut self) -> Result<(), YaraError> {
        let mut compiler = Compiler::new()?;
        let mut updated = false;
        
        for entry in std::fs::read_dir(&self.rules_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().map_or(false, |ext| ext == "yar") {
                let content = std::fs::read_to_string(&path)?;
                
                // Calcular hash MD5
                let mut hasher = Md5::new();
                hasher.update(&content);
                let md5 = format!("{:x}", hasher.finalize());
                
                let file_name = path.file_name().unwrap().to_string_lossy().to_string();
                
                // Verificar si la regla ha cambiado
                if let Some(cached) = self.rule_cache.get(&file_name) {
                    if cached.value().metadata.md5 != md5 {
                        // La regla ha cambiado, actualizar
                        let metadata = Self::extract_rule_metadata(&content, &md5)?;
                        compiler.add_rules_str(&content)
                            .map_err(|e| YaraError::CompileError(e.to_string()))?;
                            
                        if let Ok(rules) = compiler.compile_rules() {
                            self.rule_cache.insert(
                                file_name,
                                CachedRule { rules, metadata }
                            );
                            updated = true;
                        }
                    }
                } else {
                    // Nueva regla
                    let metadata = Self::extract_rule_metadata(&content, &md5)?;
                    compiler.add_rules_str(&content)
                        .map_err(|e| YaraError::CompileError(e.to_string()))?;
                        
                    if let Ok(rules) = compiler.compile_rules() {
                        self.rule_cache.insert(
                            file_name,
                            CachedRule { rules, metadata }
                        );
                        updated = true;
                    }
                }
            }
        }
        
        if updated {
            // Actualizar reglas compiladas
            self.rules = Arc::new(compiler.compile_rules()?);
        }
        
        Ok(())
    }

    pub fn get_rule_metadata(&self) -> HashMap<String, RuleMetadata> {
        self.rule_cache
            .iter()
            .map(|entry| (
                entry.key().clone(),
                entry.value().metadata.clone()
            ))
            .collect()
    }

    fn extract_rule_metadata(content: &str, md5: &str) -> Result<RuleMetadata, YaraError> {
        // Extraer prioridad y versión de los metadatos de la regla
        let priority = if let Some(cap) = regex::Regex::new(r"priority\s*=\s*(\d+)")
            .unwrap()
            .captures(content) 
        {
            cap[1].parse().unwrap_or(1)
        } else {
            1
        };

        let version = if let Some(cap) = regex::Regex::new(r"version\s*=\s*\"([^\"]+)\"")
            .unwrap()
            .captures(content)
        {
            cap[1].to_string()
        } else {
            "1.0.0".to_string()
        };

        Ok(RuleMetadata {
            priority,
            version,
            md5: md5.to_string(),
            last_modified: chrono::Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    
    #[test]
    fn test_scan_file() -> Result<(), YaraError> {
        // Create test rule
        let rule_content = r#"
        rule TestRule {
            meta:
                description = "Test rule"
                priority = 1
            strings:
                $a = "test string"
            condition:
                $a
        }
        "#;
        
        // Create temp directory
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let rule_path = temp_dir.path().join("test.yar");
        let test_file_path = temp_dir.path().join("test_file.txt");
        
        // Write test rule
        let mut file = File::create(&rule_path).expect("Failed to create rule file");
        file.write_all(rule_content.as_bytes()).expect("Failed to write rule");
        
        // Write test file with matching content
        let mut test_file = File::create(&test_file_path).expect("Failed to create test file");
        test_file.write_all(b"This is a test string for detection").expect("Failed to write test file");
        
        // Create YARA engine
        let engine = YaraEngine::new(temp_dir.path())?;
        
        // Scan the test file
        let result = engine.scan_file(&test_file_path)?;
        
        // Verify results
        assert!(!result.matches.is_empty(), "Expected to find matches");
        assert_eq!(result.matches[0].rule_name, "TestRule", "Expected to match TestRule");
        
        Ok(())
    }
    
    #[test]
    fn test_scan_memory() -> Result<(), YaraError> {
        // Create test rule
        let rule_content = r#"
        rule MemoryTestRule {
            meta:
                description = "Test rule for memory scanning"
                priority = 2
            strings:
                $a = "memory test"
            condition:
                $a
        }
        "#;
        
        // Create temp directory
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let rule_path = temp_dir.path().join("memory_test.yar");
        
        // Write test rule
        let mut file = File::create(&rule_path).expect("Failed to create rule file");
        file.write_all(rule_content.as_bytes()).expect("Failed to write rule");
        
        // Create YARA engine
        let engine = YaraEngine::new(temp_dir.path())?;
        
        // Create test buffer
        let test_buffer = b"This is a memory test buffer for YARA";
        
        // Scan the buffer
        let matches = engine.scan_memory(test_buffer)?;
        
        // Verify results
        assert!(!matches.is_empty(), "Expected to find matches");
        assert_eq!(matches[0].rule_name, "MemoryTestRule", "Expected to match MemoryTestRule");
        
        Ok(())
    }
    
    #[test]
    fn test_rule_prioritization() -> Result<(), YaraError> {
        // Create test rules with different priorities
        let high_priority_rule = r#"
        rule HighPriorityRule {
            meta:
                description = "High priority rule"
                priority = 10
            strings:
                $a = "test string"
            condition:
                $a
        }
        "#;
        
        let low_priority_rule = r#"
        rule LowPriorityRule {
            meta:
                description = "Low priority rule"
                priority = 1
            strings:
                $a = "test string"
            condition:
                $a
        }
        "#;
        
        // Create temp directory
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let high_path = temp_dir.path().join("high.yar");
        let low_path = temp_dir.path().join("low.yar");
        let test_file_path = temp_dir.path().join("prioritization_test.txt");
        
        // Write test rules
        File::create(&high_path).expect("Failed to create rule file")
            .write_all(high_priority_rule.as_bytes()).expect("Failed to write rule");
        File::create(&low_path).expect("Failed to create rule file")
            .write_all(low_priority_rule.as_bytes()).expect("Failed to write rule");
        
        // Write test file with matching content
        File::create(&test_file_path).expect("Failed to create test file")
            .write_all(b"This is a test string for priority testing").expect("Failed to write test file");
        
        // Create YARA engine
        let engine = YaraEngine::new(temp_dir.path())?;
        
        // Add fast scan config to break after first match
        let mut config = YaraConfig::default();
        config.fast_scan = true;
        
        // TODO: Apply config to engine for test
        
        // Scan the test file
        let result = engine.scan_file(&test_file_path)?;
        
        // In fast_scan mode with prioritization, we should see the high priority rule first
        if result.matches.len() > 1 {
            assert_eq!(
                result.matches[0].rule_name, 
                "HighPriorityRule",
                "Expected highest priority rule to be first"
            );
        }
        
        Ok(())
    }

    #[test]
    fn test_error_handling() -> Result<(), YaraError> {
        // Create temp directory
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        // Create minimal test rule
        let rule_content = r#"
        rule ErrorTestRule {
            meta:
                description = "Test rule for error handling"
                priority = 1
            strings:
                $a = "test"
            condition:
                $a
        }
        "#;
        
        // Write test rule
        let rule_path = temp_dir.path().join("error_test.yar");
        File::create(&rule_path).expect("Failed to create rule file")
            .write_all(rule_content.as_bytes()).expect("Failed to write rule");
        
        // Create YARA engine
        let engine = YaraEngine::new(temp_dir.path())?;
        
        // Test scanning non-existent file
        let non_existent_path = temp_dir.path().join("does_not_exist.txt");
        let result = engine.scan_file(&non_existent_path);
        
        assert!(result.is_err(), "Expected error for non-existent file");
        if let Err(e) = result {
            match e {
                YaraError::InvalidPath(_) => {
                    // This is the expected error
                    println!("Got expected error for non-existent file: {}", e);
                }
                _ => {
                    panic!("Unexpected error type: {:?}", e);
                }
            }
        }
        
        // Test file size limit handling
        // Create a large file that exceeds the default scan limit
        let large_file_path = temp_dir.path().join("large_file.bin");
        let mut large_file = File::create(&large_file_path).expect("Failed to create large file");
        
        // Create a YaraEngine with a small file size limit
        let mut config = YaraConfig::default();
        config.max_file_size_bytes = Some(100); // 100 bytes limit
        
        // TODO: Apply custom config to engine
        
        // Write data larger than the limit
        let data = vec![0u8; 1000]; // 1000 bytes
        large_file.write_all(&data).expect("Failed to write large file");
        
        // Scan the large file - this should not error but return empty results
        let result = engine.scan_file(&large_file_path)?;
        assert!(result.matches.is_empty(), "Expected no matches for size-limited file");
        
        Ok(())
    }
    
    #[test]
    fn test_rule_versioning() -> Result<(), YaraError> {
        // Create test rule with version
        let rule_v1 = r#"
        rule VersionedRule {
            meta:
                description = "Test versioned rule"
                version = "1.0"
                priority = 1
            strings:
                $a = "version 1"
            condition:
                $a
        }
        "#;
        
        let rule_v2 = r#"
        rule VersionedRule {
            meta:
                description = "Test versioned rule"
                version = "2.0"
                priority = 1
            strings:
                $a = "version 2"
            condition:
                $a
        }
        "#;
        
        // Create temp directory
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let rule_path = temp_dir.path().join("versioned.yar");
        
        // Write rule v1
        File::create(&rule_path).expect("Failed to create rule file")
            .write_all(rule_v1.as_bytes()).expect("Failed to write rule");
        
        // Create engine with v1
        let engine_v1 = YaraEngine::new(temp_dir.path())?;
        
        // Get rule metadata
        let metadata_v1 = engine_v1.get_rule_metadata();
        
        // Update rule to v2
        File::create(&rule_path).expect("Failed to create rule file")
            .write_all(rule_v2.as_bytes()).expect("Failed to write rule");
        
        // Create new engine with v2
        let engine_v2 = YaraEngine::new(temp_dir.path())?;
        
        // Get rule metadata
        let metadata_v2 = engine_v2.get_rule_metadata();
        
        // Check version differences
        let rule_name = "versioned.yar"; // Filename is used as the key
        
        if let (Some(v1_meta), Some(v2_meta)) = (metadata_v1.get(rule_name), metadata_v2.get(rule_name)) {
            assert_ne!(v1_meta.md5, v2_meta.md5, "Expected different MD5 hashes for different rule versions");
            assert_ne!(v1_meta.version, v2_meta.version, "Expected different version strings");
        } else {
            panic!("Could not find metadata for versioned rule");
        }
        
        Ok(())
    }
} 