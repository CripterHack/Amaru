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

/// Configuration for the YARA engine
#[derive(Debug, Clone)]
pub struct YaraConfig {
    pub rule_paths: Vec<PathBuf>,
    pub max_strings_per_rule: usize,
    pub timeout_ms: u64,
}

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            rule_paths: vec![PathBuf::from("signatures/official"), PathBuf::from("signatures/custom")],
            max_strings_per_rule: 20,
            timeout_ms: 30000,
        }
    }
}

/// YARA engine implementation using the yara crate
pub struct YaraEngine {
    config: YaraConfig,
    rules: Option<Rules>,
    rule_count: usize,
}

impl YaraEngine {
    /// Create a new YARA engine with the given configuration
    pub fn new(config: YaraConfig) -> Result<Self, YaraError> {
        info!("Initializing YARA engine");
        let mut engine = YaraEngine {
            config,
            rules: None,
            rule_count: 0,
        };
        
        // Cargar reglas desde los directorios configurados
        engine.load_rules()?;
        
        info!("Loaded {} rule(s)", engine.rule_count);
        Ok(engine)
    }
    
    /// Load rules from the configured rule paths
    fn load_rules(&mut self) -> Result<(), YaraError> {
        let mut compiler = Compiler::new()?;
        let mut total_rules = 0;
        
        for rule_path in &self.config.rule_paths {
            if rule_path.is_dir() {
                let rules_loaded = self.load_rules_from_directory(&rule_path, &mut compiler)?;
                total_rules += rules_loaded;
            } else if rule_path.is_file() && rule_path.extension().map_or(false, |ext| ext == "yar" || ext == "yara") {
                self.add_rule_file(&rule_path, &mut compiler)?;
                total_rules += 1;
            }
        }
        
        if total_rules > 0 {
            self.rules = Some(compiler.compile_rules()?);
            self.rule_count = total_rules;
            Ok(())
        } else {
            warn!("No YARA rules found in specified paths");
            Err(YaraError::CompileError("No rules found".to_string()))
        }
    }

    /// Load all YARA rules from a directory
    fn load_rules_from_directory(&self, dir: &Path, compiler: &mut Compiler) -> Result<usize, YaraError> {
        let mut rules_count = 0;
        
        if !dir.exists() || !dir.is_dir() {
            warn!("Directory does not exist or is not a directory: {:?}", dir);
            return Ok(0);
        }
        
        for entry in WalkDir::new(dir).follow_links(true).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            
            // Solo procesar archivos .yar o .yara
            if path.is_file() && path.extension().map_or(false, |ext| ext == "yar" || ext == "yara") {
                match self.add_rule_file(path, compiler) {
                    Ok(_) => {
                        debug!("Loaded rule file: {:?}", path);
                        rules_count += 1;
                    },
                    Err(e) => {
                        warn!("Failed to load rule file {:?}: {}", path, e);
                    }
                }
            }
        }
        
        info!("Loaded {} rule files from directory {:?}", rules_count, dir);
        Ok(rules_count)
    }
    
    /// Add a single rule file to the compiler
    fn add_rule_file(&self, path: &Path, compiler: &mut Compiler) -> Result<(), YaraError> {
        debug!("Adding rule file: {:?}", path);
        compiler.add_rules_file(path.to_str().ok_or_else(|| YaraError::InvalidPath(format!("Invalid path: {:?}", path)))?)?;
        Ok(())
    }
    
    /// Scan a file with YARA rules
    pub fn scan_file(&self, path: &Path) -> Result<Option<ScanResult>, YaraError> {
        if !path.exists() {
            return Err(YaraError::InvalidPath(format!("File does not exist: {:?}", path)));
        }
        
        let rules = match &self.rules {
            Some(rules) => rules,
            None => return Err(YaraError::InitError("YARA rules not loaded".to_string())),
        };
        
        let start_time = Instant::now();
        
        // Usar el scanner para establecer un timeout
        let scanner = rules.scanner();
        let rules_matches = scanner
            .set_timeout(self.config.timeout_ms)
            .scan_file(path)?;
        
        let elapsed = start_time.elapsed();
        let scan_time_ms = elapsed.as_millis() as u64;
        
        if rules_matches.is_empty() {
            return Ok(None);
        }
        
        // Convertir los resultados al formato de ScanResult
        let mut matched_rules = Vec::new();
        for rule_match in rules_matches {
            let mut meta = HashMap::new();
            for (key, value) in rule_match.metas {
                meta.insert(key.to_string(), format!("{:?}", value));
            }
            
            let mut strings = Vec::new();
            for matched_string in rule_match.strings {
                strings.push(MatchedString {
                    id: matched_string.identifier.to_string(),
                    offset: matched_string.offset as usize,
                    data: matched_string.data.to_vec(),
                });
            }
            
            matched_rules.push(MatchedRule {
                name: rule_match.identifier.to_string(),
                meta,
                tags: rule_match.tags.iter().map(|t| t.to_string()).collect(),
                strings,
            });
        }
        
        let result = ScanResult {
            path: path.to_path_buf(),
            matched_rules,
            scan_time_ms,
            error: None,
        };
        
        Ok(Some(result))
    }
    
    /// Get the number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }
    
    /// Scan multiple files concurrently
    pub async fn scan_files_async<P: AsRef<Path> + Send + 'static>(&self, paths: Vec<P>) -> Vec<Result<Option<ScanResult>, YaraError>> {
        let rules_clone = match &self.rules {
            Some(rules) => rules.clone(),
            None => return vec![Err(YaraError::InitError("YARA rules not loaded".to_string()))],
        };
        
        let timeout_ms = self.config.timeout_ms;
        
        let mut handles = Vec::new();
        
        for path in paths {
            let rules = rules_clone.clone();
            
            let handle = task::spawn_blocking(move || {
                let path = path.as_ref();
                
                if !path.exists() {
                    return Err(YaraError::InvalidPath(format!("File does not exist: {:?}", path)));
                }
                
                let start_time = Instant::now();
                
                let scanner = rules.scanner();
                let rules_matches = match scanner.set_timeout(timeout_ms).scan_file(path) {
                    Ok(matches) => matches,
                    Err(e) => return Err(YaraError::ScanError(format!("Failed to scan file: {}", e))),
                };
                
                let elapsed = start_time.elapsed();
                let scan_time_ms = elapsed.as_millis() as u64;
                
                if rules_matches.is_empty() {
                    return Ok(None);
                }
                
                // Convertir los resultados al formato de ScanResult
                let mut matched_rules = Vec::new();
                for rule_match in rules_matches {
                    let mut meta = HashMap::new();
                    for (key, value) in rule_match.metas {
                        meta.insert(key.to_string(), format!("{:?}", value));
                    }
                    
                    let mut strings = Vec::new();
                    for matched_string in rule_match.strings {
                        strings.push(MatchedString {
                            id: matched_string.identifier.to_string(),
                            offset: matched_string.offset as usize,
                            data: matched_string.data.to_vec(),
                        });
                    }
                    
                    matched_rules.push(MatchedRule {
                        name: rule_match.identifier.to_string(),
                        meta,
                        tags: rule_match.tags.iter().map(|t| t.to_string()).collect(),
                        strings,
                    });
                }
                
                let result = ScanResult {
                    path: path.to_path_buf(),
                    matched_rules,
                    scan_time_ms,
                    error: None,
                };
                
                Ok(Some(result))
            });
            
            handles.push(handle);
        }
        
        let mut results = Vec::new();
        
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(YaraError::ScanError(format!("Failed to join task: {}", e)))),
            }
        }
        
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_yara_engine_creation() {
        let config = YaraConfig::default();
        let result = YaraEngine::new(config);
        
        // Este test podría fallar si no hay reglas, pero eso es comportamiento esperado
        match result {
            Ok(_) => (),
            Err(e) => {
                if let YaraError::CompileError(msg) = e {
                    if msg == "No rules found" {
                        // Esto es esperado si no hay reglas
                    } else {
                        panic!("Error inesperado: {}", e);
                    }
                } else {
                    panic!("Error inesperado: {}", e);
                }
            }
        }
    }

    #[test]
    fn test_add_rule_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        
        // Escribir una regla simple
        writeln!(temp_file, r#"rule test_rule {{
            strings:
                $a = "test string"
            condition:
                $a
        }}"#).unwrap();
        
        // Crear el motor y el compilador
        let config = YaraConfig::default();
        let engine = YaraEngine {
            config,
            rules: None,
            rule_count: 0,
        };
        
        let mut compiler = Compiler::new().unwrap();
        
        // Intentar agregar la regla
        let result = engine.add_rule_file(&temp_file.path(), &mut compiler);
        assert!(result.is_ok());
    }
} 