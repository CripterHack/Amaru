use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, Duration};
use serde::{Serialize, Deserialize};
use std::fs;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub path: PathBuf,
    pub last_modified: SystemTime,
    pub hash: String,
    pub enabled: bool,
    pub priority: u8,
}

#[derive(Debug)]
pub struct RuleCache {
    metadata: Arc<RwLock<HashMap<String, RuleMetadata>>>,
    cache_file: PathBuf,
    max_age: Duration,
}

impl RuleCache {
    pub fn new(cache_file: PathBuf, max_age_hours: u64) -> Self {
        Self {
            metadata: Arc::new(RwLock::new(HashMap::new())),
            cache_file,
            max_age: Duration::from_secs(max_age_hours * 3600),
        }
    }
    
    pub async fn load(&self) -> Result<(), std::io::Error> {
        if self.cache_file.exists() {
            let content = fs::read_to_string(&self.cache_file)?;
            let cached: HashMap<String, RuleMetadata> = serde_json::from_str(&content)?;
            *self.metadata.write().await = cached;
        }
        Ok(())
    }
    
    pub async fn save(&self) -> Result<(), std::io::Error> {
        let metadata = self.metadata.read().await;
        let content = serde_json::to_string_pretty(&*metadata)?;
        fs::write(&self.cache_file, content)?;
        Ok(())
    }
    
    pub async fn is_rule_valid(&self, path: &Path) -> bool {
        let metadata = self.metadata.read().await;
        if let Some(cached) = metadata.get(path.to_str().unwrap_or_default()) {
            if let Ok(file_meta) = fs::metadata(path) {
                if let Ok(modified) = file_meta.modified() {
                    return cached.last_modified == modified && 
                           cached.enabled &&
                           SystemTime::now().duration_since(modified).unwrap() < self.max_age;
                }
            }
        }
        false
    }
    
    pub async fn update_rule(&self, path: &Path, enabled: bool, priority: u8) -> Result<(), std::io::Error> {
        let mut metadata = self.metadata.write().await;
        let file_meta = fs::metadata(path)?;
        let modified = file_meta.modified()?;
        
        let content = fs::read(path)?;
        let hash = format!("{:x}", md5::compute(&content));
        
        metadata.insert(
            path.to_str().unwrap_or_default().to_string(),
            RuleMetadata {
                path: path.to_path_buf(),
                last_modified: modified,
                hash,
                enabled,
                priority,
            }
        );
        
        self.save().await?;
        Ok(())
    }
    
    pub async fn get_enabled_rules(&self) -> Vec<(PathBuf, u8)> {
        let metadata = self.metadata.read().await;
        let mut rules: Vec<_> = metadata.values()
            .filter(|meta| meta.enabled)
            .map(|meta| (meta.path.clone(), meta.priority))
            .collect();
        
        // Ordenar por prioridad (mayor primero)
        rules.sort_by(|a, b| b.1.cmp(&a.1));
        rules
    }
    
    pub async fn disable_rule(&self, path: &Path) -> Result<(), std::io::Error> {
        let mut metadata = self.metadata.write().await;
        if let Some(meta) = metadata.get_mut(path.to_str().unwrap_or_default()) {
            meta.enabled = false;
            self.save().await?;
        }
        Ok(())
    }
    
    pub async fn clean_invalid(&self) -> Result<usize, std::io::Error> {
        let mut metadata = self.metadata.write().await;
        let before_len = metadata.len();
        
        metadata.retain(|_, meta| {
            if let Ok(file_meta) = fs::metadata(&meta.path) {
                if let Ok(modified) = file_meta.modified() {
                    return SystemTime::now().duration_since(modified).unwrap() < self.max_age;
                }
            }
            false
        });
        
        let removed = before_len - metadata.len();
        if removed > 0 {
            self.save().await?;
        }
        
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs::File;
    use std::io::Write;
    
    #[tokio::test]
    async fn test_rule_cache() {
        let temp_dir = tempdir().unwrap();
        let cache_file = temp_dir.path().join("rules.cache");
        let cache = RuleCache::new(cache_file, 24);
        
        // Crear regla de prueba
        let rule_file = temp_dir.path().join("test.yar");
        let mut file = File::create(&rule_file).unwrap();
        file.write_all(b"rule test { condition: true }").unwrap();
        
        // Actualizar caché
        cache.update_rule(&rule_file, true, 1).await.unwrap();
        
        // Verificar regla válida
        assert!(cache.is_rule_valid(&rule_file).await);
        
        // Obtener reglas habilitadas
        let enabled = cache.get_enabled_rules().await;
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].1, 1);
        
        // Deshabilitar regla
        cache.disable_rule(&rule_file).await.unwrap();
        let enabled = cache.get_enabled_rules().await;
        assert_eq!(enabled.len(), 0);
        
        // Limpiar caché
        let removed = cache.clean_invalid().await.unwrap();
        assert_eq!(removed, 0);
    }
} 