use dashmap::DashMap;
use log::{debug, info, warn};
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex,
    },
    thread::available_parallelism,
    time::{Duration, Instant},
};
use sysinfo::{CpuExt, PidExt, ProcessExt, System, SystemExt};
use tokio::sync::oneshot;
use tokio::{
    sync::{RwLock, Semaphore},
    time,
};

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
    workers: parking_lot::RwLock<Arc<Workers>>,
    monitoring: AtomicBool,
    /// Configuración de rendimiento
    performance_config: Arc<parking_lot::RwLock<PerformanceConfig>>,
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
    metrics: Arc<Mutex<ResourceMetrics>>,
    /// Cache optimizada
    task_cache: Arc<DashMap<String, (Vec<u8>, Instant)>>,
    /// Límites de recursos
    limits: Arc<RwLock<ResourceLimits>>,
}

struct Workers {
    thread_pool: ThreadPool,
    task_limiter: Arc<Semaphore>,
}

impl Workers {
    fn thread_count(config: &PerformanceConfig) -> usize {
        let cpus = available_parallelism().map(|p| p.get()).unwrap_or(1);
        if config.low_resource_mode {
            return (cpus / 2).max(1);
        }
        match config.process_priority {
            ProcessPriority::Low => (cpus / 3).max(1),
            ProcessPriority::BelowNormal => (cpus / 2).max(1),
            ProcessPriority::Normal => cpus,
            ProcessPriority::AboveNormal => cpus.saturating_add(1),
            ProcessPriority::High => cpus.saturating_add(2),
        }
    }

    fn build(config: &PerformanceConfig) -> Result<Self, rayon::ThreadPoolBuildError> {
        let threads = Self::thread_count(config);
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("amaru-worker-{i}"))
            .stack_size(3 * 1024 * 1024)
            .build()?;
        let concurrent = if config.low_resource_mode {
            (threads / 2).max(1)
        } else {
            threads
        };
        Ok(Self {
            thread_pool,
            task_limiter: Arc::new(Semaphore::new(concurrent)),
        })
    }
}

impl ResourceManager {
    /// Crea una nueva instancia del gestor de recursos
    pub fn new(config: PerformanceConfig) -> Self {
        let workers =
            Workers::build(&config).expect("Unable to initialize the resource thread pool");
        let thread_count = workers.thread_pool.current_num_threads();
        debug!("Inicializando ResourceManager con {} hilos", thread_count);

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
            workers: parking_lot::RwLock::new(Arc::new(workers)),
            monitoring: AtomicBool::new(false),
            performance_config: Arc::new(parking_lot::RwLock::new(config)),
            active: Arc::new(AtomicBool::new(true)),
            current_priority: Arc::new(Mutex::new(SystemPriority::Normal)),
            system: Arc::new(Mutex::new(System::new_all())),
            scheduled_tasks: Arc::new(DashMap::new()),
            next_task_id: Arc::new(AtomicU32::new(1)),
            metrics: Arc::new(Mutex::new(metrics)),
            task_cache: Arc::new(DashMap::with_capacity(1000)),
            limits: Arc::new(RwLock::new(limits)),
        }
    }

    /// Inicia el monitoreo de recursos
    pub async fn start_monitoring(&self) {
        if self.monitoring.swap(true, Ordering::AcqRel) {
            return;
        }
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
                let (process_cpu, process_memory, global_cpu) = {
                    let mut sys = system.lock().unwrap();
                    let pid = sysinfo::Pid::from_u32(std::process::id());
                    sys.refresh_cpu();
                    sys.refresh_process(pid);
                    let process = sys.process(pid);
                    (
                        process.map_or(0.0, ProcessExt::cpu_usage),
                        process.map_or(0, ProcessExt::memory),
                        sys.global_cpu_info().cpu_usage(),
                    )
                };
                {
                    let mut metrics = metrics.lock().unwrap();
                    metrics.cpu_usage = process_cpu;
                    metrics.memory_usage = process_memory;
                    metrics.timestamp = Instant::now();
                }
                // Ajustar prioridad según uso del sistema
                let config = performance_config.read();
                if config.pause_on_high_usage && global_cpu > config.high_usage_threshold as f32 {
                    let mut priority = current_priority.lock().unwrap();
                    if *priority != SystemPriority::Low {
                        *priority = SystemPriority::Low;
                        info!(
                            "Sistema bajo carga alta ({}%), ajustando a prioridad baja",
                            global_cpu
                        );
                    }
                } else if global_cpu < (config.high_usage_threshold as f32 * 0.8) {
                    let mut priority = current_priority.lock().unwrap();
                    if *priority == SystemPriority::Low {
                        *priority = SystemPriority::Normal;
                        info!(
                            "Sistema con carga normal ({}%), restaurando prioridad",
                            global_cpu
                        );
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
        if !self.active.load(Ordering::Acquire) {
            return Err("Resource manager stopped".into());
        }
        let priority = *self.current_priority.lock().unwrap();
        let workers = self.workers.read().clone();
        let acquire = workers.task_limiter.clone().acquire_owned();
        let permit = if priority == SystemPriority::Low {
            time::timeout(Duration::from_millis(500), acquire)
                .await
                .map_err(|_| "Task queue timeout")?
        } else {
            acquire.await
        }
        .map_err(|_| "Resource manager stopped")?;
        if !self.active.load(Ordering::Acquire) {
            return Err("Resource manager stopped".into());
        }
        let normal_timeout = self.limits.read().await.task_timeout_ms;
        let timeout = Duration::from_millis(match priority {
            SystemPriority::Low => normal_timeout.saturating_mul(2),
            SystemPriority::Normal => normal_timeout,
            SystemPriority::High => normal_timeout / 2,
        });
        let task_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
        self.scheduled_tasks.insert(task_id, Instant::now());
        self.metrics.lock().unwrap().pending_tasks += 1;
        let metrics = self.metrics.clone();
        let tasks = self.scheduled_tasks.clone();
        let (tx, rx) = oneshot::channel();
        workers.thread_pool.spawn(move || {
            {
                let mut state = metrics.lock().unwrap();
                state.active_threads += 1;
                state.pending_tasks = state.pending_tasks.saturating_sub(1);
            }
            // The task keeps its permit until completion even if its caller times out.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(workload))
                .map_err(|_| format!("{task_type:?} task panicked"));
            tasks.remove(&task_id);
            metrics.lock().unwrap().active_threads -= 1;
            drop(permit);
            let _ = tx.send(result);
        });
        time::timeout(timeout, rx)
            .await
            .map_err(|_| "Task execution timed out")?
            .map_err(|_| "Task worker stopped")?
    }

    /// Obtiene las métricas actuales del sistema
    pub async fn get_metrics(&self) -> ResourceMetrics {
        self.metrics.lock().unwrap().clone()
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
        }
    }

    /// Almacena en caché el resultado de una tarea
    pub fn cache_result(&self, key: String, value: Vec<u8>, ttl_secs: u64) {
        // Limpiar caché si alcanza un tamaño considerable
        if self.task_cache.len() > 10000 {
            self.cleanup_cache(5000);
        }

        self.task_cache
            .insert(key, (value, Instant::now() + Duration::from_secs(ttl_secs)));
    }

    /// Recupera un resultado cacheado si está disponible y válido
    pub fn get_cached_result(&self, key: &str) -> Option<Vec<u8>> {
        let entry = self.task_cache.get(key)?;
        if entry.value().1 > Instant::now() {
            return Some(entry.value().0.clone());
        }
        drop(entry);
        self.task_cache
            .remove_if(key, |_, (_, expiry)| *expiry <= Instant::now());
        None
    }

    /// Limpia entradas antiguas de la caché
    fn cleanup_cache(&self, retain: usize) {
        let now = Instant::now();

        // Primero eliminar entradas expiradas
        self.task_cache.retain(|_, (_, expiry)| *expiry > now);

        // Si aún hay demasiadas entradas, eliminar las más antiguas
        if self.task_cache.len() > retain {
            // Convertir a vector para ordenar
            let mut entries: Vec<_> = self
                .task_cache
                .iter()
                .map(|r| (r.key().clone(), r.value().1))
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
    pub async fn process_batch<F, T, R>(
        &self,
        items: Vec<T>,
        processor: F,
    ) -> Vec<Result<R, String>>
    where
        F: Fn(T) -> R + Send + Sync + 'static,
        T: Send + 'static,
        R: Send + 'static,
    {
        use futures::{stream, StreamExt};
        let limit = self.limits.read().await.max_batch_size.max(1);
        let processor = Arc::new(processor);
        stream::iter(items)
            .map(|item| {
                let processor = processor.clone();
                self.execute(TaskType::Scan, move || processor(item))
            })
            .buffered(limit)
            .collect()
            .await
    }

    /// Actualiza la configuración de rendimiento
    pub async fn update_performance_config(&self, config: PerformanceConfig) {
        let mut limits = self.limits.write().await;
        let new_thread_count = Workers::thread_count(&config);
        let mut current = self.performance_config.write();
        if limits.max_thread_count != new_thread_count
            || current.low_resource_mode != config.low_resource_mode
        {
            match Workers::build(&config) {
                Ok(workers) => *self.workers.write() = Arc::new(workers),
                Err(e) => {
                    warn!("No se pudo actualizar el pool de tareas: {e}");
                    return;
                }
            }
        }
        limits.max_thread_count = new_thread_count;
        limits.max_cpu_usage = config.cpu_usage_limit.unwrap_or(90);
        limits.max_batch_size = if config.low_resource_mode { 16 } else { 64 };
        limits.background_task_interval_ms = if config.low_resource_mode { 5000 } else { 1000 };
        *current = config;
    }

    /// Programa una tarea periódica con intervalo adaptativo
    pub async fn schedule_periodic_task<F>(&self, _task_type: TaskType, interval: Duration, task: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let active = self.active.clone();
        let current_priority = self.current_priority.clone();

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
                        SystemPriority::High => interval / 2,
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
        self.workers.read().task_limiter.close();
    }

    /// Aplica la prioridad del proceso al sistema operativo
    pub fn apply_process_priority(&self) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            use winapi::um::processthreadsapi::{GetCurrentProcess, SetPriorityClass};
            use winapi::um::winbase::{
                ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS,
                IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
            };

            let config = self.performance_config.read().process_priority;

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
                    return Err(format!(
                        "Error al establecer prioridad: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }

            info!("Prioridad de proceso aplicada: {:?}", config);
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err("Ajuste de prioridad de proceso disponible solo en Windows".into())
        }
    }
}

impl Drop for ResourceManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PerformanceConfig;
    use std::thread;

    #[tokio::test]
    async fn test_execute_task() {
        let config = PerformanceConfig::default();
        let manager = ResourceManager::new(config);

        let result = manager
            .execute(TaskType::Scan, || {
                thread::sleep(Duration::from_millis(10));
                42
            })
            .await;

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
        manager.cache_result(key.clone(), value, 0);
        assert!(manager.get_cached_result(&key).is_none());
    }

    #[tokio::test]
    async fn test_metrics() {
        let config = PerformanceConfig::default();
        let manager = ResourceManager::new(config);

        // Ejecutar algunas tareas para generar métricas
        for _ in 0..5 {
            manager
                .execute(TaskType::Scan, || {
                    thread::sleep(Duration::from_millis(5));
                })
                .await
                .ok();
        }

        let metrics = manager.get_metrics().await;
        assert!(metrics.timestamp > Instant::now() - Duration::from_secs(10));
    }
}
