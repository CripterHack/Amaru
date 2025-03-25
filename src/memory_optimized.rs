use std::sync::Arc;
use parking_lot::{Mutex, RwLock};
use std::time::{Duration, Instant};
use sysinfo::{System, SystemExt, ProcessExt};
use std::collections::HashMap;
use log::{warn, info, debug};
use std::process;

/// Administrador de recursos de memoria que ayuda a optimizar
/// el consumo del sistema según configuración y carga actual
pub struct MemoryManager {
    /// Sistema para monitorear los recursos del sistema
    system: Mutex<System>,
    /// Límite máximo de memoria permitido (en MB)
    memory_limit_mb: usize,
    /// Límites de cache para diferentes operaciones
    cache_limits: RwLock<HashMap<String, usize>>,
    /// Última vez que se verificó el sistema
    last_check: Mutex<Instant>,
    /// Intervalo para actualizar métricas del sistema
    check_interval: Duration,
    /// Modo de bajo consumo activo
    low_power_mode: bool,
}

/// Estrategia para gestionar la memoria cuando se exceden los límites
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryStrategy {
    /// No hacer nada, solo reportar
    WarnOnly,
    /// Limpiar caches no críticos
    CleanupCaches,
    /// Liberar memoria agresivamente, incluyendo caches críticos
    AggressiveCleanup,
}

impl MemoryManager {
    /// Crea un nuevo administrador de memoria
    pub fn new(memory_limit_mb: usize, low_power_mode: bool) -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        
        Self {
            system: Mutex::new(system),
            memory_limit_mb,
            cache_limits: RwLock::new(HashMap::new()),
            last_check: Mutex::new(Instant::now()),
            check_interval: Duration::from_secs(30),
            low_power_mode,
        }
    }
    
    /// Establece un límite para una cache específica
    pub fn set_cache_limit(&self, cache_name: &str, limit_mb: usize) {
        let mut limits = self.cache_limits.write();
        limits.insert(cache_name.to_string(), limit_mb);
    }
    
    /// Verifica si el sistema está bajo presión de memoria
    pub fn is_memory_pressure(&self) -> bool {
        let mut sys = self.system.lock();
        let mut last_check = self.last_check.lock();
        
        // Solo actualizar cada cierto tiempo para evitar sobrecarga
        if last_check.elapsed() >= self.check_interval {
            sys.refresh_memory();
            *last_check = Instant::now();
        }
        
        let used_memory_mb = (sys.used_memory() / 1024) as usize;
        let total_memory_mb = (sys.total_memory() / 1024) as usize;
        
        // Considerar presión de memoria si usamos más del 85% en modo normal
        // o más del 75% en modo de bajo consumo
        let threshold = if self.low_power_mode { 75 } else { 85 };
        let percentage_used = (used_memory_mb as f64 / total_memory_mb as f64) * 100.0;
        
        percentage_used > threshold as f64
    }
    
    /// Obtiene la estrategia de memoria recomendada basada en la presión actual
    pub fn get_memory_strategy(&self) -> MemoryStrategy {
        let mut sys = self.system.lock();
        sys.refresh_memory();
        sys.refresh_processes();
        
        let used_memory_mb = (sys.used_memory() / 1024) as usize;
        let total_memory_mb = (sys.total_memory() / 1024) as usize;
        let percentage_used = (used_memory_mb as f64 / total_memory_mb as f64) * 100.0;
        
        // Obtener el consumo de este proceso
        let pid = process::id() as usize;
        let process_memory_mb = match sys.process(pid) {
            Some(process) => (process.memory() / 1024) as usize,
            None => 0,
        };
        
        if percentage_used > 95.0 || process_memory_mb > self.memory_limit_mb {
            MemoryStrategy::AggressiveCleanup
        } else if percentage_used > 85.0 {
            MemoryStrategy::CleanupCaches
        } else {
            MemoryStrategy::WarnOnly
        }
    }
    
    /// Comprueba si una cache específica excede su límite
    pub fn is_cache_over_limit(&self, cache_name: &str, current_size_mb: usize) -> bool {
        let limits = self.cache_limits.read();
        
        match limits.get(cache_name) {
            Some(&limit) => current_size_mb > limit,
            None => false, // Sin límite configurado
        }
    }
    
    /// Reduce la memoria reservada para caché cuando sea necesario
    pub fn adjust_cache_memory(&self) {
        let strategy = self.get_memory_strategy();
        
        match strategy {
            MemoryStrategy::AggressiveCleanup => {
                info!("Ejecutando limpieza agresiva de memoria");
                unsafe {
                    // Liberar toda la memoria no utilizada al sistema
                    mimalloc::set_option(mimalloc::Option::ReserveSize, 0);
                    mimalloc::set_option(mimalloc::Option::ResetDecommits, true);
                    mimalloc::reset_heap();
                }
                
                // Incluso en modo agresivo, mantener una caché mínima para rendimiento
                mimalloc::set_option(mimalloc::Option::ReserveSize, 16 * 1024 * 1024);
            }
            MemoryStrategy::CleanupCaches => {
                info!("Limpiando cachés no críticas");
                unsafe {
                    // Reducir la memoria reservada a la mitad
                    let option_val = mimalloc::get_option(mimalloc::Option::ReserveSize);
                    let new_val = option_val / 2;
                    mimalloc::set_option(mimalloc::Option::ReserveSize, new_val);
                }
            }
            MemoryStrategy::WarnOnly => {
                debug!("Uso de memoria dentro de los límites aceptables");
            }
        }
    }
    
    /// Calcula tamaño óptimo de buffer para operaciones grandes
    pub fn optimal_buffer_size(&self, default_size: usize) -> usize {
        if self.is_memory_pressure() {
            // Reducir tamaño de buffer bajo presión de memoria
            default_size / 2
        } else {
            default_size
        }
    }
    
    /// Obtiene estadísticas del sistema actual
    pub fn get_system_stats(&self) -> SystemStats {
        let mut sys = self.system.lock();
        sys.refresh_all();
        
        let pid = process::id() as usize;
        let process_memory = match sys.process(pid) {
            Some(process) => process.memory(),
            None => 0,
        };
        
        SystemStats {
            total_memory_mb: (sys.total_memory() / 1024) as usize,
            used_memory_mb: (sys.used_memory() / 1024) as usize,
            process_memory_mb: (process_memory / 1024) as usize,
            cpu_usage_percent: sys.global_cpu_info().cpu_usage(),
        }
    }
}

/// Estadísticas del sistema para monitoreo
#[derive(Debug, Clone)]
pub struct SystemStats {
    pub total_memory_mb: usize,
    pub used_memory_mb: usize,
    pub process_memory_mb: usize,
    pub cpu_usage_percent: f32,
}

/// Buffer inteligente que se ajusta dinámicamente al uso de memoria
pub struct SmartBuffer<T> {
    data: Vec<T>,
    memory_manager: Arc<MemoryManager>,
    cache_name: String,
    max_elements: usize,
}

impl<T> SmartBuffer<T> {
    /// Crea un nuevo buffer inteligente con límites dinámicos
    pub fn new(
        initial_capacity: usize, 
        max_elements: usize,
        memory_manager: Arc<MemoryManager>,
        cache_name: &str
    ) -> Self {
        // Registrar esta caché con el gestor de memoria
        let buffer_size_estimate = initial_capacity * std::mem::size_of::<T>();
        let buffer_size_mb = buffer_size_estimate / (1024 * 1024);
        
        Self {
            data: Vec::with_capacity(initial_capacity),
            memory_manager,
            cache_name: cache_name.to_string(),
            max_elements,
        }
    }
    
    /// Agrega un elemento, con posible reducción de tamaño si hay presión de memoria
    pub fn push(&mut self, item: T) {
        // Verificar si necesitamos reducir el buffer
        if self.data.len() >= self.max_elements || 
            self.memory_manager.is_memory_pressure() {
            
            // Reducir el buffer a la mitad si está en el límite
            if self.data.len() >= self.max_elements {
                let new_size = self.data.len() / 2;
                self.data.truncate(new_size);
                warn!("Buffer {} reducido a {} elementos por límite alcanzado", 
                      self.cache_name, new_size);
            }
        }
        
        self.data.push(item);
    }
    
    /// Obtiene una referencia a los datos internos
    pub fn get_data(&self) -> &Vec<T> {
        &self.data
    }
    
    /// Limpia el buffer manteniendo la capacidad
    pub fn clear(&mut self) {
        self.data.clear();
    }
    
    /// Libera memoria si hay presión en el sistema
    pub fn optimize_memory(&mut self) {
        if self.memory_manager.is_memory_pressure() {
            let strategy = self.memory_manager.get_memory_strategy();
            
            match strategy {
                MemoryStrategy::AggressiveCleanup => {
                    // Liberar casi toda la memoria
                    self.clear();
                    self.data.shrink_to_fit();
                }
                MemoryStrategy::CleanupCaches => {
                    // Reducir a la mitad
                    if !self.data.is_empty() {
                        let new_size = std::cmp::max(self.data.len() / 2, 1);
                        self.data.truncate(new_size);
                    }
                }
                _ => {} // No hacer nada en otros casos
            }
        }
    }
}