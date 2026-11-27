use log::{debug, error, info, warn};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use thiserror::Error;
use std::sync::Arc;
use std::fs;
use yara::{Compiler, MetadataValue, Rules};
use walkdir::WalkDir;
use rayon::prelude::*;
use serde::{Serialize, Deserialize};

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

/// Loaded rules and metadata are replaced together after a successful reload.
#[derive(Clone)]
pub struct YaraEngine {
    config: YaraConfig,
    rules: Arc<Rules>,
    metadata: HashMap<String, RuleMetadata>,
    rules_dir: PathBuf,
}

impl YaraEngine {
    pub fn new(rules_dir: impl Into<PathBuf>) -> Result<Self, YaraError> {
        let rules_dir = rules_dir.into();
        let mut compiler = Compiler::new().map_err(|e| YaraError::InitError(e.to_string()))?;
        let mut metadata = HashMap::new();
        for entry in WalkDir::new(&rules_dir).sort_by_file_name() {
            let entry = entry.map_err(std::io::Error::from)?;
            let path = entry.path();
            if !entry.file_type().is_file()
                || !matches!(path.extension().and_then(|s| s.to_str()), Some("yar" | "yara"))
            {
                continue;
            }
            let name = path.strip_prefix(&rules_dir).expect("entry under rules directory")
                .to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
            let content = fs::read_to_string(path)?;
            if content.as_bytes().contains(&0) {
                return Err(YaraError::CompileError(format!("{}: rule contains a NUL byte", path.display())));
            }
            let digest = format!("{:x}", md5::compute(&content));
            compiler = compiler.add_rules_str_with_namespace(&content, &name)
                .map_err(|e| YaraError::CompileError(format!("{}: {}", path.display(), e)))?;
            metadata.insert(name, Self::extract_rule_metadata(&content, &digest)?);
        }
        let rules = compiler.compile_rules().map_err(|e| YaraError::CompileError(e.to_string()))?;
        Ok(Self { config: YaraConfig::default(), rules: Arc::new(rules), metadata, rules_dir })
    }

    /// Sets the scan deadline used by both file and memory scans.
    pub fn set_scan_timeout(&mut self, timeout: std::time::Duration) {
        self.config.timeout_ms = timeout.as_millis().clamp(1, u64::MAX as u128) as u64;
    }

    fn timeout_seconds(&self) -> i32 {
        self.config.timeout_ms.div_ceil(1000).min(i32::MAX as u64) as i32
    }

    fn collect_matches(&self, mut matches: Vec<yara::Rule<'_>>) -> Vec<RuleMatch> {
        if let Some(excluded) = &self.config.excluded_namespaces {
            matches.retain(|rule| !excluded.iter().any(|prefix| rule.namespace.starts_with(prefix)));
        }
        matches.sort_by_key(|rule| std::cmp::Reverse(self.metadata[rule.namespace].priority));
        if self.config.fast_scan {
            if let Some(first_namespace) = matches.first().map(|rule| rule.namespace) {
                matches.retain(|rule| rule.namespace == first_namespace);
            }
        }
        matches.into_iter().map(|rule| {
            let strings = rule.strings.into_iter().flat_map(|string| {
                let identifier = string.identifier;
                string.matches.into_iter().map(move |occurrence| MatchString {
                    identifier: identifier.to_owned(),
                    offset: occurrence.base as u64 + occurrence.offset as u64,
                    data: occurrence.data,
                })
            }).take(self.config.max_strings_per_rule).collect();
            let meta = rule.metadatas.into_iter().map(|entry| {
                let value = match entry.value {
                    MetadataValue::Integer(n) => n.into(),
                    MetadataValue::String(s) => s.into(),
                    MetadataValue::Boolean(b) => b.into(),
                };
                (entry.identifier.to_owned(), value)
            }).collect::<serde_json::Map<_, _>>();
            RuleMatch {
                rule_name: rule.identifier.to_owned(),
                tags: rule.tags.into_iter().map(str::to_owned).collect(),
                meta: meta.into(),
                strings,
            }
        }).collect()
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
        
        let matches = self.rules.scan_file(path, self.timeout_seconds())?;
        let all_matches = self.collect_matches(matches);

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
        let matches = self.rules.scan_mem(buffer, self.timeout_seconds())
            .map_err(|e| YaraError::ScanError(e.to_string()))?;
        Ok(self.collect_matches(matches))
    }

    /// Check the installed EICAR signature against a canonical sample and a clean control.
    pub fn verify_eicar(&self) -> Result<(), YaraError> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        // Store the diagnostic fixture in a form that does not embed its raw signature in the binary.
        let sample = STANDARD.decode("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=")
            .map_err(|error| YaraError::ScanError(error.to_string()))?;
        for (bytes, expected) in [(sample.as_slice(), true), (&b"Amaru control"[..], false)] {
            let detected = self.scan_memory(bytes)?.iter().any(|rule| rule.rule_name == "EICAR_Test_File");
            if detected != expected {
                return Err(YaraError::ScanError(format!(
                    "EICAR_Test_File returned {detected}, expected {expected} with rules at {}",
                    self.rules_dir.display()
                )));
            }
        }
        Ok(())
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
        let loaded = Self::new(self.rules_dir.clone())?;
        self.rules = loaded.rules;
        self.metadata = loaded.metadata;
        Ok(())
    }

    pub fn update_rules(&mut self) -> Result<(), YaraError> {
        self.reload_rules()
    }

    pub fn get_rule_metadata(&self) -> HashMap<String, RuleMetadata> {
        self.metadata.clone()
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

        let version = if let Some(cap) = regex::Regex::new(r#"version\s*=\s*"([^"]+)""#)
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
        
        let mut engine = YaraEngine::new(temp_dir.path())?;
        let result = engine.scan_file(&test_file_path)?;
        assert_eq!(result.matches.len(), 2);
        assert_eq!(result.matches[0].rule_name, "HighPriorityRule");

        engine.config.fast_scan = true;
        let result = engine.scan_file(&test_file_path)?;
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].rule_name, "HighPriorityRule");

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
        let mut engine = YaraEngine::new(temp_dir.path())?;
        
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
        
        engine.config.max_file_size_bytes = Some(100);
        large_file.write_all(&b"test".repeat(250))?;

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