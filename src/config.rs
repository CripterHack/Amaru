use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use std::fs;
use std::io;
use winreg::{enums::*, RegKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Ruta al directorio de reglas YARA
    pub yara_rules_path: PathBuf,
    
    /// Habilitar protección en tiempo real
    pub realtime_protection: bool,
    
    /// Habilitar análisis heurístico
    pub heuristic_analysis: bool,
    
    /// Umbral de detección heurística (0-100)
    pub heuristic_threshold: u8,
    
    /// Iniciar automáticamente al encender el sistema
    pub autostart: bool,
    
    /// Rutas a monitorear
    pub monitored_paths: Vec<PathBuf>,
    
    /// Configuración de escaneo
    #[serde(default)]
    pub scan_config: ScanConfig,
    
    /// Configuración de cuarentena
    #[serde(default)]
    pub quarantine_config: QuarantineConfig,
    
    /// Configuración de actualizaciones
    #[serde(default)]
    pub update_config: UpdateConfig,
    
    /// Configuración de la interfaz de usuario
    #[serde(default)]
    pub ui_config: UiConfig,
    
    /// Configuración de rendimiento
    #[serde(default)]
    pub performance_config: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanConfig {
    /// Máximo tamaño de archivo a escanear (en bytes)
    pub max_file_size: u64,
    
    /// Extensiones a escanear
    pub scan_extensions: Vec<String>,
    
    /// Rutas a excluir del escaneo
    pub exclude_paths: Vec<PathBuf>,
    
    /// Número máximo de hilos para escaneo
    pub max_threads: usize,
    
    /// Tiempo máximo de escaneo por archivo (en segundos)
    pub scan_timeout: u64,
    
    /// Programar escaneo automático
    pub scheduled_scan: bool,
    
    /// Hora del escaneo programado (formato 24h)
    pub scheduled_time: u8,
    
    /// Día de la semana para escaneo (0-6, domingo=0)
    pub scheduled_day: Option<u8>,
    
    /// Frecuencia de escaneo
    pub scan_frequency: ScanFrequency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanFrequency {
    Daily,
    Weekly,
    Monthly,
}

impl Default for ScanFrequency {
    fn default() -> Self {
        ScanFrequency::Weekly
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuarantineConfig {
    /// Ruta al directorio de cuarentena
    pub quarantine_path: PathBuf,
    
    /// Máximo espacio para cuarentena (en bytes)
    pub max_size: u64,
    
    /// Días a mantener archivos en cuarentena
    pub retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateConfig {
    /// URL del servidor de actualizaciones
    pub update_url: String,
    
    /// Intervalo de actualización (en segundos)
    pub update_interval: u64,
    
    /// Actualización automática de reglas
    pub auto_update: bool,
    
    /// Clave pública para verificación de actualizaciones
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    /// Tema de la interfaz
    pub theme: Theme,
    
    /// Mostrar notificaciones del sistema
    pub show_notifications: bool,
    
    /// Minimizar a la bandeja del sistema
    pub minimize_to_tray: bool,
    
    /// Mostrar estadísticas en la interfaz principal
    pub show_statistics: bool,
    
    /// Idioma de la interfaz
    pub language: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    Light,
    Dark,
    System,
}

impl Default for Theme {
    fn default() -> Self {
        Theme::System
    }
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: Theme::System,
            show_notifications: true,
            minimize_to_tray: true,
            show_statistics: true,
            language: "es-ES".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Modo de bajo consumo de recursos
    pub low_resource_mode: bool,
    
    /// Prioridad del proceso
    pub process_priority: ProcessPriority,
    
    /// Limitar uso de CPU (porcentaje máximo)
    pub cpu_usage_limit: Option<u8>,
    
    /// Pausa de monitoreo cuando el sistema está en uso intensivo
    pub pause_on_high_usage: bool,
    
    /// Umbral de uso de CPU para pausar monitoreo (%)
    pub high_usage_threshold: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessPriority {
    Low,
    BelowNormal,
    Normal,
    AboveNormal,
    High,
}

impl Default for ProcessPriority {
    fn default() -> Self {
        ProcessPriority::Normal
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            low_resource_mode: false,
            process_priority: ProcessPriority::Normal,
            cpu_usage_limit: None,
            pause_on_high_usage: true,
            high_usage_threshold: 80,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            yara_rules_path: PathBuf::from("signatures"),
            realtime_protection: true,
            heuristic_analysis: true,
            heuristic_threshold: 70,
            autostart: true,
            monitored_paths: vec![
                PathBuf::from("C:\\Program Files"),
                PathBuf::from("C:\\Program Files (x86)"),
                PathBuf::from("C:\\Users"),
            ],
            scan_config: ScanConfig {
                max_file_size: 100 * 1024 * 1024, // 100MB
                scan_extensions: vec![
                    "exe".to_string(),
                    "dll".to_string(),
                    "sys".to_string(),
                    "scr".to_string(),
                    "bat".to_string(),
                    "cmd".to_string(),
                    "ps1".to_string(),
                    "vbs".to_string(),
                    "js".to_string(),
                ],
                exclude_paths: vec![
                    PathBuf::from("C:\\Windows\\WinSxS"),
                    PathBuf::from("C:\\Windows\\SystemResources"),
                ],
                max_threads: num_cpus::get().min(4),
                scan_timeout: 30,
                scheduled_scan: true,
                scheduled_time: 2, // 2 AM
                scheduled_day: Some(0), // Domingo
                scan_frequency: ScanFrequency::Weekly,
            },
            quarantine_config: QuarantineConfig {
                quarantine_path: PathBuf::from("quarantine"),
                max_size: 1024 * 1024 * 1024, // 1GB
                retention_days: 30,
            },
            update_config: UpdateConfig {
                update_url: "https://updates.amaru.dev".to_string(),
                update_interval: 3600, // 1 hora
                auto_update: true,
                public_key: None,
            },
            ui_config: UiConfig::default(),
            performance_config: PerformanceConfig::default(),
        }
    }
}

impl Config {
    /// Cargar configuración desde archivo
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config = toml::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    /// Guardar configuración a archivo
    pub fn save<P: AsRef<std::path::Path>>(&self, path: P) -> io::Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, content)
    }

    /// Validar configuración
    pub fn validate(&self) -> io::Result<()> {
        // Verificar que las rutas existen
        if !self.yara_rules_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Ruta de reglas YARA no encontrada: {}", self.yara_rules_path.display())
            ));
        }

        // Verificar rutas monitoreadas
        for path in &self.monitored_paths {
            if !path.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Ruta monitoreada no encontrada: {}", path.display())
                ));
            }
        }

        // Verificar configuración de cuarentena
        if !self.quarantine_config.quarantine_path.exists() {
            fs::create_dir_all(&self.quarantine_config.quarantine_path)?;
        }

        Ok(())
    }
    
    /// Aplicar configuración al sistema
    pub fn apply_system_settings(&self) -> io::Result<()> {
        // Configurar inicio automático
        set_registry_autostart(self.autostart)?;
        
        // Configurar prioridad del proceso si está disponible
        #[cfg(target_os = "windows")]
        {
            use winapi::um::processthreadsapi::{GetCurrentProcess, SetPriorityClass};
            use winapi::um::winbase::{
                IDLE_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
                ABOVE_NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS,
            };
            
            let priority = match self.performance_config.process_priority {
                ProcessPriority::Low => IDLE_PRIORITY_CLASS,
                ProcessPriority::BelowNormal => BELOW_NORMAL_PRIORITY_CLASS,
                ProcessPriority::Normal => NORMAL_PRIORITY_CLASS,
                ProcessPriority::AboveNormal => ABOVE_NORMAL_PRIORITY_CLASS,
                ProcessPriority::High => HIGH_PRIORITY_CLASS,
            };
            
            unsafe {
                let handle = GetCurrentProcess();
                SetPriorityClass(handle, priority);
            }
        }
        
        Ok(())
    }
}

/// Configurar inicio automático en el registro de Windows
pub fn set_registry_autostart(enable: bool) -> io::Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = r"Software\Microsoft\Windows\CurrentVersion\Run";
    let (key, _) = hkcu.create_subkey(path)?;
    
    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path.to_string_lossy().to_string();
    
    if enable {
        key.set_value("AmaruAntivirus", &exe_path_str)?;
    } else {
        // Si existe la clave, eliminarla
        if key.get_value::<String, _>("AmaruAntivirus").is_ok() {
            key.delete_value("AmaruAntivirus")?;
        }
    }
    
    Ok(())
}

/// Verificar si el inicio automático está habilitado
pub fn is_autostart_enabled() -> io::Result<bool> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = r"Software\Microsoft\Windows\CurrentVersion\Run";
    
    if let Ok(key) = hkcu.open_subkey(path) {
        if let Ok(_) = key.get_value::<String, _>("AmaruAntivirus") {
            return Ok(true);
        }
    }
    
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.realtime_protection);
        assert!(!config.monitored_paths.is_empty());
        assert!(config.scan_config.max_threads > 0);
    }

    #[test]
    fn test_config_save_load() -> io::Result<()> {
        let dir = tempdir()?;
        let config_path = dir.path().join("config.toml");
        
        let config = Config::default();
        config.save(&config_path)?;
        
        let loaded = Config::load(&config_path)?;
        assert_eq!(loaded.realtime_protection, config.realtime_protection);
        assert_eq!(loaded.monitored_paths, config.monitored_paths);
        
        Ok(())
    }

    #[test]
    fn test_config_validation() -> io::Result<()> {
        let dir = tempdir()?;
        let rules_path = dir.path().join("rules");
        fs::create_dir(&rules_path)?;
        
        let mut config = Config::default();
        config.yara_rules_path = rules_path;
        config.monitored_paths = vec![dir.path().to_path_buf()];
        
        assert!(config.validate().is_ok());
        
        Ok(())
    }
} 