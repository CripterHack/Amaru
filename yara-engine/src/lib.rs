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
    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResult, YaraError> {
        let path = path.as_ref();
        let start = std::time::Instant::now();
        
        debug!("Iniciando escaneo de {}", path.display());
        
        // Obtener reglas ordenadas por prioridad
        let mut prioritized_rules: Vec<_> = self.rule_cache
            .iter()
            .collect();
            
        prioritized_rules.sort_by(|a, b| {
            b.value().metadata.priority.cmp(&a.value().metadata.priority)
        });
        
        let mut all_matches = Vec::new();
        
        // Aplicar reglas en orden de prioridad
        for cached_rule in prioritized_rules {
            let matches = cached_rule.value().rules
                .scan_file(path, ScanFlags::empty())
                .map_err(|e| YaraError::ScanError(e.to_string()))?;
                
            all_matches.extend(matches.into_iter().map(|m| RuleMatch {
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
            }));
        }

        let scan_time = start.elapsed().as_secs_f64();
        
        info!("Escaneo completado en {:.2}s", scan_time);
        
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
    use tempfile::tempdir;
    use std::fs;

    #[test]
    fn test_scan_file() -> Result<(), YaraError> {
        let dir = tempdir()?;
        let rule_path = dir.path().join("test.yar");
        let test_file = dir.path().join("test.txt");

        fs::write(&rule_path, r#"
            rule TestRule {
                strings:
                    $test = "malicious"
                condition:
                    $test
            }
        "#)?;

        fs::write(&test_file, "This is a malicious test file")?;

        let engine = YaraEngine::new(dir.path())?;
        let result = engine.scan_file(&test_file)?;

        assert!(!result.matches.is_empty());
        assert_eq!(result.matches[0].rule_name, "TestRule");

        Ok(())
    }

    #[test]
    fn test_scan_memory() -> Result<(), YaraError> {
        let dir = tempdir()?;
        let rule_path = dir.path().join("test.yar");

        fs::write(&rule_path, r#"
            rule TestMemory {
                strings:
                    $test = "memory"
                condition:
                    $test
            }
        "#)?;

        let engine = YaraEngine::new(dir.path())?;
        let buffer = b"testing memory scan";
        let matches = engine.scan_memory(buffer)?;

        assert!(!matches.is_empty());
        assert_eq!(matches[0].rule_name, "TestMemory");

        Ok(())
    }

    #[test]
    fn test_rule_prioritization() -> Result<(), YaraError> {
        let dir = tempdir()?;
        
        // Crear reglas con diferentes prioridades
        fs::write(dir.path().join("high.yar"), r#"
            rule HighPriority {
                meta:
                    priority = 3
                    version = "1.0.0"
                strings:
                    $test = "high"
                condition:
                    $test
            }
        "#)?;
        
        fs::write(dir.path().join("low.yar"), r#"
            rule LowPriority {
                meta:
                    priority = 1
                    version = "1.0.0"
                strings:
                    $test = "low"
                condition:
                    $test
            }
        "#)?;

        let engine = YaraEngine::new(dir.path())?;
        let metadata = engine.get_rule_metadata();
        
        assert_eq!(metadata.get("high.yar").unwrap().priority, 3);
        assert_eq!(metadata.get("low.yar").unwrap().priority, 1);

        Ok(())
    }

    #[test]
    fn test_rule_versioning() -> Result<(), YaraError> {
        let dir = tempdir()?;
        
        // Crear regla con versión
        fs::write(dir.path().join("test.yar"), r#"
            rule VersionedRule {
                meta:
                    version = "2.1.0"
                strings:
                    $test = "test"
                condition:
                    $test
            }
        "#)?;

        let engine = YaraEngine::new(dir.path())?;
        let metadata = engine.get_rule_metadata();
        
        assert_eq!(metadata.get("test.yar").unwrap().version, "2.1.0");

        Ok(())
    }
} 