use std::{
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU32, Ordering}},
    collections::HashMap,
    time::{Duration, Instant},
    thread::available_parallelism,
};
use tokio::{
    sync::{RwLock, Semaphore},
    time,
};
use dashmap::DashMap;
use crossbeam_channel::{bounded, Sender, Receiver};
use rayon::{ThreadPool, ThreadPoolBuilder};
use log::{info, warn, debug, error};
use sysinfo::{System, SystemExt, ProcessExt, CpuExt};

use crate::config::{PerformanceConfig, ProcessPriority};

/// Representa el nivel de prioridad del sistema
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemPriority {
    /// Prioridad baja, optimizada para ahorrar recursos
    Low,
    /// Prioridad normal, balance entre rendimiento y consumo
    Normal,
    /// Prioridad alta, máximo rendimiento
    High,
}

/// Tipos de tareas que pueden ser programadas
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskType {
    /// Escaneo de archivos
    Scan,
    /// Monitoreo en tiempo real
    Monitor,
    /// Análisis heurístico
    Analysis,
    /// Verificación de integridad
    Integrity,
    /// Actualización
    Update,
}

/// Resultado de la medición de recursos
#[derive(Debug, Clone)]
pub struct ResourceMetrics {
    /// Uso de CPU en porcentaje (0-100)
    pub cpu_usage: f32,
    /// Memoria usada en bytes
    pub memory_usage: u64,
    /// Número de hilos activos
    pub active_threads: usize,
    /// Tareas en cola pendientes
    pub pending_tasks: usize,
    /// Timestamp de la medición
    pub timestamp: Instant,
}

/// Limites configurables de recursos
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Límite de uso de CPU (porcentaje)
    pub max_cpu_usage: u8,
    /// Máximo número de hilos para tareas
    pub max_thread_count: usize,
    /// Máximo tamaño de batch para procesamiento
    pub max_batch_size: usize,
    /// Intervalo mínimo entre tareas de background (ms)
    pub background_task_interval_ms: u64,
    /// Tiempo máximo de ejecución por tarea (ms)
    pub task_timeout_ms: u64,
}

/// Gestor de recursos del sistema
pub struct ResourceManager {
    /// Pool de hilos para tareas CPU-intensivas
    thread_pool: Arc<ThreadPool>,
    /// Semáforo para limitar tareas concurrentes
    task_limiter: Arc<Semaphore>,
    /// Configuración de rendimiento
    performance_config: Arc<RwLock<PerformanceConfig>>,
    /// Estado activo
    active: Arc<AtomicBool>,
    /// Prioridad actual del sistema
    current_priority: Arc<Mutex<SystemPriority>>,
    /// Sistema para monitoreo de recursos
    system: Arc<Mutex<System>>,
    /// Mapa de tareas programadas (ID -> timestamp)
    scheduled_tasks: Arc<DashMap<u32, Instant>>,
    /// Siguiente ID de tarea
    next_task_id: Arc<AtomicU32>,
    /// Métricas recopiladas
    metrics: Arc<RwLock<ResourceMetrics>>,
    /// Cache optimizada
    task_cache: Arc<DashMap<String, (Vec<u8>, Instant)>>,
    /// Límites de recursos
    limits: Arc<RwLock<ResourceLimits>>,
}

impl ResourceManager {
    /// Crea una nueva instancia del gestor de recursos
    pub fn new(config: PerformanceConfig) -> Self {
        // Determinar número óptimo de hilos basado en configuración
        let num_cpus = available_parallelism().map(|p| p.get()).unwrap_or(4);
        let thread_count = if config.low_resource_mode {
            num_cpus.saturating_div(2).max(1)
        } else {
            match config.process_priority {
                ProcessPriority::Low => num_cpus.saturating_div(3).max(1),
                ProcessPriority::BelowNormal => num_cpus.saturating_div(2).max(1),
                ProcessPriority::Normal => num_cpus,
                ProcessPriority::AboveNormal => num_cpus.saturating_add(1),
                ProcessPriority::High => num_cpus.saturating_add(2),
            }
        };
        
        debug!("Inicializando ResourceManager con {} hilos", thread_count);
        
        // Crear thread pool con configuración optimizada
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .thread_name(|i| format!("amaru-worker-{}", i))
            .stack_size(3 * 1024 * 1024) // 3MB stack
            .build()
            .unwrap();
            
        // Inicializar semáforo para limitar concurrencia
        let max_concurrent = if config.low_resource_mode {
            thread_count.saturating_div(2).max(1)
        } else {
            thread_count
        };
        
        // Configurar límites de recursos según configuración
        let limits = ResourceLimits {
            max_cpu_usage: config.cpu_usage_limit.unwrap_or(90),
            max_thread_count: thread_count,
            max_batch_size: if config.low_resource_mode { 16 } else { 64 },
            background_task_interval_ms: if config.low_resource_mode { 5000 } else { 1000 },
            task_timeout_ms: 30000, // 30 segundos
        };
        
        // Crear métricas iniciales
        let metrics = ResourceMetrics {
            cpu_usage: 0.0,
            memory_usage: 0,
            active_threads: 0,
            pending_tasks: 0,
            timestamp: Instant::now(),
        };
        
        ResourceManager {
            thread_pool: Arc::new(thread_pool),
            task_limiter: Arc::new(Semaphore::new(max_concurrent)),
            performance_config: Arc::new(RwLock::new(config)),
            active: Arc::new(AtomicBool::new(true)),
            current_priority: Arc::new(Mutex::new(SystemPriority::Normal)),
            system: Arc::new(Mutex::new(System::new_all())),
            scheduled_tasks: Arc::new(DashMap::new()),
            next_task_id: Arc::new(AtomicU32::new(1)),
            metrics: Arc::new(RwLock::new(metrics)),
            task_cache: Arc::new(DashMap::with_capacity(1000)),
            limits: Arc::new(RwLock::new(limits)),
        }
    }
    
    /// Inicia el monitoreo de recursos
    pub async fn start_monitoring(&self) {
        let active = self.active.clone();
        let system = self.system.clone();
        let performance_config = self.performance_config.clone();
        let metrics = self.metrics.clone();
        let current_priority = self.current_priority.clone();
        
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(1));
            
            while active.load(Ordering::Relaxed) {
                interval.tick().await;
                
                // Refrescar información del sistema
                let mut sys = system.lock().unwrap();
                sys.refresh_all();
                
                // Obtener uso de CPU y memoria del proceso actual
                let process_cpu = sys.processes()
                    .values()
                    .find(|p| p.pid().as_u32() == std::process::id())
                    .map(|p| p.cpu_usage())
                    .unwrap_or(0.0);
                    
                let process_memory = sys.processes()
                    .values()
                    .find(|p| p.pid().as_u32() == std::process::id())
                    .map(|p| p.memory())
                    .unwrap_or(0);
                
                // Obtener CPU global del sistema
                let global_cpu = sys.global_cpu_info().cpu_usage();
                
                // Actualizar métricas
                let mut metrics_guard = metrics.write().await;
                metrics_guard.cpu_usage = process_cpu;
                metrics_guard.memory_usage = process_memory;
                metrics_guard.timestamp = Instant::now();
                drop(metrics_guard);
                
                // Ajustar prioridad según uso del sistema
                let config = performance_config.read().await;
                if config.pause_on_high_usage && global_cpu > config.high_usage_threshold as f32 {
                    let mut priority = current_priority.lock().unwrap();
                    if *priority != SystemPriority::Low {
                        *priority = SystemPriority::Low;
                        info!("Sistema bajo carga alta ({}%), ajustando a prioridad baja", global_cpu);
                    }
                } else if global_cpu < (config.high_usage_threshold as f32 * 0.8) {
                    let mut priority = current_priority.lock().unwrap();
                    if *priority == SystemPriority::Low {
                        *priority = SystemPriority::Normal;
                        info!("Sistema con carga normal ({}%), restaurando prioridad", global_cpu);
                    }
                }
            }
        });
    }
    
    /// Ejecuta una tarea en el pool de hilos con control de recursos
    pub async fn execute<F, T>(&self, task_type: TaskType, workload: F) -> Result<T, String>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // Verificar la prioridad actual del sistema
        let current_priority = {
            let guard = self.current_priority.lock().unwrap();
            *guard
        };
        
        // Si estamos en prioridad baja, limitamos más agresivamente las tareas
        let (tx, rx) = bounded(1);
        
        // Obtener un permiso del semáforo para limitar concurrencia
        let permit = match current_priority {
            SystemPriority::Low => {
                // Mayor tiempo de espera en modo de baja prioridad
                tokio::time::timeout(
                    Duration::from_millis(500),
                    self.task_limiter.acquire()
                ).await.map_err(|_| "Timeout esperando permiso del semáforo".to_string())?
            },
            _ => self.task_limiter.acquire().await,
        };
        
        // Registrar la tarea
        let task_id = self.next_task_id.fetch_add(1, Ordering::SeqCst);
        self.scheduled_tasks.insert(task_id, Instant::now());
        
        // Actualizar contador de tareas pendientes
        {
            let mut metrics = self.metrics.write().await;
            metrics.pending_tasks += 1;
        }
        
        // Clonar lo necesario para mover al thread pool
        let scheduled_tasks = self.scheduled_tasks.clone();
        let metrics = self.metrics.clone();
        
        // Lanzar tarea con timeout según la prioridad
        let timeout_ms = {
            let limits = self.limits.read().await;
            match current_priority {
                SystemPriority::Low => limits.task_timeout_ms * 2,
                SystemPriority::Normal => limits.task_timeout_ms,
                SystemPriority::High => limits.task_timeout_ms / 2,
            }
        };
        
        self.thread_pool.spawn(move || {
            let start = Instant::now();
            
            // Incrementar contador de hilos activos
            tokio::runtime::Handle::current().block_on(async {
                let mut m = metrics.write().await;
                m.active_threads += 1;
            });
            
            // Ejecutar la tarea
            let result = workload();
            
            // Registrar métricas
            let elapsed = start.elapsed();
            debug!(
                "Tarea {} completada en {:.2} ms", 
                task_id, 
                elapsed.as_millis()
            );
            
            // Actualizar métricas y eliminar tarea completada
            tokio::runtime::Handle::current().block_on(async {
                let mut m = metrics.write().await;
                m.active_threads -= 1;
                m.pending_tasks -= 1;
            });
            
            scheduled_tasks.remove(&task_id);
            tx.send(result).ok();
            drop(permit);
        });
        
        // Esperar el resultado con timeout
        match tokio::time::timeout(Duration::from_millis(timeout_ms), async {
            rx.recv().map_err(|e| format!("Error al recibir resultado: {}", e))
        }).await {
            Ok(result) => result,
            Err(_) => {
                warn!("Timeout ejecutando tarea {}", task_id);
                self.scheduled_tasks.remove(&task_id);
                Err("Timeout ejecutando tarea".to_string())
            }
        }
    }
    
    /// Obtiene las métricas actuales del sistema
    pub async fn get_metrics(&self) -> ResourceMetrics {
        self.metrics.read().await.clone()
    }
    
    /// Limpia tareas antiguas o pendientes que han excedido el timeout
    pub async fn cleanup_stale_tasks(&self) {
        let now = Instant::now();
        let mut cleaned = 0;
        
        // Obtener timeout máximo
        let timeout_ms = {
            let limits = self.limits.read().await;
            limits.task_timeout_ms * 3 // Triple del timeout normal
        };
        
        self.scheduled_tasks.retain(|&_id, &mut timestamp| {
            let keep = now.saturating_duration_since(timestamp).as_millis() < timeout_ms as u128;
            if !keep {
                cleaned += 1;
            }
            keep
        });
        
        if cleaned > 0 {
            warn!("Limpiadas {} tareas bloqueadas o antiguas", cleaned);
            
            // Actualizar métricas
            let mut metrics = self.metrics.write().await;
            metrics.pending_tasks = self.scheduled_tasks.len();
        }
    }
    
    /// Almacena en caché el resultado de una tarea
    pub fn cache_result(&self, key: String, value: Vec<u8>, ttl_secs: u64) {
        // Limpiar caché si alcanza un tamaño considerable
        if self.task_cache.len() > 10000 {
            self.cleanup_cache(5000);
        }
        
        self.task_cache.insert(key, (value, Instant::now() + Duration::from_secs(ttl_secs)));
    }
    
    /// Recupera un resultado cacheado si está disponible y válido
    pub fn get_cached_result(&self, key: &str) -> Option<Vec<u8>> {
        self.task_cache.get(key).and_then(|entry| {
            let (value, expiry) = entry.value();
            if Instant::now() < *expiry {
                Some(value.clone())
            } else {
                self.task_cache.remove(key);
                None
            }
        })
    }
    
    /// Limpia entradas antiguas de la caché
    fn cleanup_cache(&self, retain: usize) {
        let now = Instant::now();
        
        // Primero eliminar entradas expiradas
        self.task_cache.retain(|_, (_, expiry)| *expiry > now);
        
        // Si aún hay demasiadas entradas, eliminar las más antiguas
        if self.task_cache.len() > retain {
            // Convertir a vector para ordenar
            let mut entries: Vec<_> = self.task_cache
                .iter()
                .map(|r| (r.key().clone(), *r.value().1))
                .collect();
            
            // Ordenar por tiempo de expiración ascendente
            entries.sort_by(|a, b| a.1.cmp(&b.1));
            
            // Eliminar las entradas más antiguas
            let to_remove = entries.len() - retain;
            for (key, _) in entries.into_iter().take(to_remove) {
                self.task_cache.remove(&key);
            }
        }
    }
    
    /// Procesa un lote de tareas en paralelo
    pub async fn process_batch<F, T, R>(&self, items: Vec<T>, processor: F) -> Vec<Result<R, String>>
    where
        F: Fn(T) -> R + Send + Sync + 'static,
        T: Send + 'static,
        R: Send + 'static,
    {
        let (tx, rx) = bounded(items.len());
        let processor = Arc::new(processor);
        
        // Determinar tamaño máximo de lote según la configuración
        let batch_size = {
            let limits = self.limits.read().await;
            limits.max_batch_size.min(items.len())
        };
        
        // Procesar en lotes para no saturar el sistema
        for chunk in items.chunks(batch_size) {
            let chunk_vec = chunk.to_vec();
            let tx_clone = tx.clone();
            let processor_clone = processor.clone();
            
            self.execute(TaskType::Scan, move || {
                chunk_vec.into_iter().for_each(|item| {
                    let result = match std::panic::catch_unwind(|| processor_clone(item)) {
                        Ok(res) => Ok(res),
                        Err(_) => Err("Panic en procesamiento de tarea".to_string()),
                    };
                    tx_clone.send(result).ok();
                });
            }).await.ok();
        }
        
        drop(tx);
        rx.iter().collect()
    }
    
    /// Actualiza la configuración de rendimiento
    pub async fn update_performance_config(&self, config: PerformanceConfig) {
        // Calcular nuevo número de hilos según configuración
        let num_cpus = available_parallelism().map(|p| p.get()).unwrap_or(4);
        let new_thread_count = if config.low_resource_mode {
            num_cpus.saturating_div(2).max(1)
        } else {
            match config.process_priority {
                ProcessPriority::Low => num_cpus.saturating_div(3).max(1),
                ProcessPriority::BelowNormal => num_cpus.saturating_div(2).max(1),
                ProcessPriority::Normal => num_cpus,
                ProcessPriority::AboveNormal => num_cpus.saturating_add(1),
                ProcessPriority::High => num_cpus.saturating_add(2),
            }
        };
        
        // Actualizar límites
        {
            let mut limits = self.limits.write().await;
            limits.max_thread_count = new_thread_count;
            limits.max_cpu_usage = config.cpu_usage_limit.unwrap_or(90);
            limits.max_batch_size = if config.low_resource_mode { 16 } else { 64 };
            limits.background_task_interval_ms = if config.low_resource_mode { 5000 } else { 1000 };
        }
        
        // Actualizar configuración
        let mut config_guard = self.performance_config.write().await;
        *config_guard = config;
        
        info!("Configuración de rendimiento actualizada: {} hilos", new_thread_count);
    }
    
    /// Programa una tarea periódica con intervalo adaptativo
    pub async fn schedule_periodic_task<F>(&self, task_type: TaskType, interval: Duration, task: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let active = self.active.clone();
        let current_priority = self.current_priority.clone();
        let limits = self.limits.clone();
        let task = Arc::new(task);
        
        tokio::spawn(async move {
            while active.load(Ordering::Relaxed) {
                // Ajustar intervalo según prioridad actual
                let adjusted_interval = {
                    let priority = {
                        let guard = current_priority.lock().unwrap();
                        *guard
                    };
                    
                    match priority {
                        SystemPriority::Low => interval.saturating_mul(3),
                        SystemPriority::Normal => interval,
                        SystemPriority::High => interval.saturating_div(2),
                    }
                };
                
                // Ejecutar tarea
                task();
                
                // Esperar con intervalo adaptativo
                time::sleep(adjusted_interval).await;
            }
        });
    }
    
    /// Detiene el gestor de recursos
    pub fn shutdown(&self) {
        self.active.store(false, Ordering::SeqCst);
    }
    
    /// Aplica la prioridad del proceso al sistema operativo
    pub fn apply_process_priority(&self) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            use winapi::um::processthreadsapi::{GetCurrentProcess, SetPriorityClass};
            use winapi::um::winbase::{
                IDLE_PRIORITY_CLASS,
                BELOW_NORMAL_PRIORITY_CLASS,
                NORMAL_PRIORITY_CLASS,
                ABOVE_NORMAL_PRIORITY_CLASS,
                HIGH_PRIORITY_CLASS,
            };
            
            let config = match futures::executor::block_on(self.performance_config.read()) {
                guard => guard.process_priority
            };
            
            let priority_class = match config {
                ProcessPriority::Low => IDLE_PRIORITY_CLASS,
                ProcessPriority::BelowNormal => BELOW_NORMAL_PRIORITY_CLASS,
                ProcessPriority::Normal => NORMAL_PRIORITY_CLASS,
                ProcessPriority::AboveNormal => ABOVE_NORMAL_PRIORITY_CLASS,
                ProcessPriority::High => HIGH_PRIORITY_CLASS,
            };
            
            unsafe {
                let handle = GetCurrentProcess();
                if SetPriorityClass(handle, priority_class) == 0 {
                    return Err(format!("Error al establecer prioridad: {}", std::io::Error::last_os_error()));
                }
            }
            
            info!("Prioridad de proceso aplicada: {:?}", config);
            Ok(())
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            warn!("Ajuste de prioridad de proceso no disponible en esta plataforma");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use crate::config::PerformanceConfig;
    
    #[tokio::test]
    async fn test_execute_task() {
        let config = PerformanceConfig::default();
        let manager = ResourceManager::new(config);
        
        let result = manager.execute(TaskType::Scan, || {
            thread::sleep(Duration::from_millis(10));
            42
        }).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }
    
    #[tokio::test]
    async fn test_batch_processing() {
        let config = PerformanceConfig::default();
        let manager = ResourceManager::new(config);
        
        let items = vec![1, 2, 3, 4, 5];
        let results = manager.process_batch(items, |i| i * 2).await;
        
        assert_eq!(results.len(), 5);
        assert_eq!(results[0].as_ref().unwrap(), &2);
        assert_eq!(results[4].as_ref().unwrap(), &10);
    }
    
    #[tokio::test]
    async fn test_cache() {
        let config = PerformanceConfig::default();
        let manager = ResourceManager::new(config);
        
        let key = "test_key".to_string();
        let value = vec![1, 2, 3, 4];
        
        manager.cache_result(key.clone(), value.clone(), 60);
        let cached = manager.get_cached_result(&key);
        
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), value);
    }
    
    #[tokio::test]
    async fn test_metrics() {
        let config = PerformanceConfig::default();
        let manager = ResourceManager::new(config);
        
        // Ejecutar algunas tareas para generar métricas
        for _ in 0..5 {
            manager.execute(TaskType::Scan, || {
                thread::sleep(Duration::from_millis(5));
            }).await.ok();
        }
        
        let metrics = manager.get_metrics().await;
        assert!(metrics.timestamp > Instant::now() - Duration::from_secs(10));
    }
} 