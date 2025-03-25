use std::path::{Path, PathBuf};
use std::collections::HashSet;
use regex::Regex;
use serde::{Serialize, Deserialize};
use log::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    pub exclude_paths: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub include_extensions: Vec<String>,
    pub min_file_size: u64,
    pub max_file_size: u64,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            exclude_paths: vec![
                r"C:\Windows".to_string(),
                r"C:\Program Files\Windows Defender".to_string(),
            ],
            exclude_patterns: vec![
                r"\.git".to_string(),
                r"node_modules".to_string(),
                r"\.tmp$".to_string(),
            ],
            include_extensions: vec![
                "exe".to_string(), "dll".to_string(), "sys".to_string(),
                "scr".to_string(), "bat".to_string(), "cmd".to_string(),
                "ps1".to_string(), "vbs".to_string(), "js".to_string(),
            ],
            min_file_size: 64,      // 64 bytes mínimo
            max_file_size: 104857600, // 100 MB máximo
        }
    }
}

#[derive(Debug)]
pub struct FileFilter {
    config: FilterConfig,
    exclude_paths: HashSet<PathBuf>,
    exclude_patterns: Vec<Regex>,
    include_extensions: HashSet<String>,
}

impl FileFilter {
    pub fn new(config: FilterConfig) -> Result<Self, regex::Error> {
        let exclude_paths: HashSet<PathBuf> = config.exclude_paths
            .iter()
            .map(PathBuf::from)
            .collect();
            
        let exclude_patterns = config.exclude_patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<Result<Vec<_>, _>>()?;
            
        let include_extensions: HashSet<String> = config.include_extensions
            .iter()
            .map(|s| s.to_lowercase())
            .collect();
            
        Ok(Self {
            config,
            exclude_paths,
            exclude_patterns,
            include_extensions,
        })
    }
    
    pub fn should_monitor<P: AsRef<Path>>(&self, path: P) -> bool {
        let path = path.as_ref();
        
        // Verificar si el path está en la lista de exclusiones
        if self.is_excluded_path(path) {
            debug!("Path excluido: {:?}", path);
            return false;
        }
        
        // Verificar si el path coincide con algún patrón de exclusión
        if self.matches_exclude_pattern(path) {
            debug!("Path coincide con patrón de exclusión: {:?}", path);
            return false;
        }
        
        // Verificar extensión
        if !self.has_valid_extension(path) {
            debug!("Extensión no válida: {:?}", path);
            return false;
        }
        
        // Verificar tamaño si el archivo existe
        if let Ok(metadata) = path.metadata() {
            let size = metadata.len();
            if size < self.config.min_file_size || size > self.config.max_file_size {
                debug!("Tamaño de archivo fuera de rango: {:?} ({} bytes)", path, size);
                return false;
            }
        }
        
        true
    }
    
    fn is_excluded_path(&self, path: &Path) -> bool {
        self.exclude_paths.iter().any(|excluded| {
            path.starts_with(excluded) || 
            path.components().any(|c| c.as_os_str() == ".git")
        })
    }
    
    fn matches_exclude_pattern(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.exclude_patterns.iter().any(|pattern| pattern.is_match(&path_str))
    }
    
    fn has_valid_extension(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| self.include_extensions.contains(&ext.to_lowercase()))
            .unwrap_or(false)
    }
    
    pub fn add_exclude_path<P: AsRef<Path>>(&mut self, path: P) {
        self.exclude_paths.insert(path.as_ref().to_path_buf());
    }
    
    pub fn add_exclude_pattern(&mut self, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.exclude_patterns.push(regex);
        Ok(())
    }
    
    pub fn add_extension(&mut self, ext: &str) {
        self.include_extensions.insert(ext.to_lowercase());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs::File;
    
    #[test]
    fn test_file_filter() {
        let config = FilterConfig::default();
        let filter = FileFilter::new(config).unwrap();
        
        // Crear directorio temporal para pruebas
        let temp_dir = tempdir().unwrap();
        
        // Probar archivo ejecutable
        let exe_path = temp_dir.path().join("test.exe");
        File::create(&exe_path).unwrap();
        assert!(filter.should_monitor(&exe_path));
        
        // Probar archivo excluido
        let git_path = temp_dir.path().join(".git").join("config");
        assert!(!filter.should_monitor(&git_path));
        
        // Probar extensión no incluida
        let txt_path = temp_dir.path().join("test.txt");
        assert!(!filter.should_monitor(&txt_path));
    }
    
    #[test]
    fn test_custom_patterns() {
        let mut config = FilterConfig::default();
        config.exclude_patterns.push(r"test\.bak$".to_string());
        let mut filter = FileFilter::new(config).unwrap();
        
        // Agregar nuevo patrón
        filter.add_exclude_pattern(r"\.temp$").unwrap();
        
        let temp_dir = tempdir().unwrap();
        let bak_path = temp_dir.path().join("test.bak");
        let temp_path = temp_dir.path().join("test.temp");
        
        assert!(!filter.should_monitor(&bak_path));
        assert!(!filter.should_monitor(&temp_path));
    }
    
    #[test]
    fn test_file_size_limits() {
        let mut config = FilterConfig::default();
        config.min_file_size = 100;
        config.max_file_size = 1000;
        let filter = FileFilter::new(config).unwrap();
        
        let temp_dir = tempdir().unwrap();
        let test_path = temp_dir.path().join("test.exe");
        
        // Crear archivo pequeño
        let mut file = File::create(&test_path).unwrap();
        file.set_len(50).unwrap();
        assert!(!filter.should_monitor(&test_path));
        
        // Crear archivo grande
        file.set_len(1500).unwrap();
        assert!(!filter.should_monitor(&test_path));
        
        // Crear archivo de tamaño válido
        file.set_len(500).unwrap();
        assert!(filter.should_monitor(&test_path));
    }
} 