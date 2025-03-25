use std::future::Future;
use std::sync::Arc;
use futures::future::{FutureExt, TryFutureExt};
use tokio::sync::{Semaphore, Mutex, RwLock};
use tokio::task::{JoinHandle, spawn_blocking};
use log::{warn, info, debug, error};
use std::time::{Duration, Instant};
use rayon::ThreadPool;
use futures_locks::RwLock as FuturesRwLock;
use parking_lot::RwLock as ParkingLotRwLock;
use tokio::time::timeout;

use crate::memory_optimized::MemoryManager;

/// Tipos de trabajo que pueden ser gestionados
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WorkType {
    /// Escaneo de archivos, operación intensiva
    FileScan,
    /// Análisis heurístico, operación intensiva de CPU
    HeuristicAnalysis,
    /// Actualizaciones y operaciones de red
    NetworkOperation,
    /// Operaciones del servicio de fondo
    ServiceOperation,
}

/// Resultado de operaciones asíncronas gestionadas
pub enum TaskResult<T> {
    /// Operación completada correctamente
    Completed(T),
    /// Operación cancelada 
    Cancelled,
    /// Operación falló por timeout
    TimedOut,
    /// Error durante la operación
    Error(String),
}

/// Gestor de concurrencia para optimizar recursos del sistema
pub struct ConcurrencyManager {
    /// Límite de tareas concurrentes por tipo
    limits: ParkingLotRwLock<std::collections::HashMap<WorkType, usize>>,
    /// Semáforos por tipo de trabajo para limitar concurrencia
    semaphores: ParkingLotRwLock<std::collections::HashMap<WorkType, Arc<Semaphore>>>,
    /// Número de CPU físicas del sistema
    physical_cores: usize,
    /// Referencia al gestor de memoria
    memory_manager: Arc<MemoryManager>,
    /// Pool de hilos para operaciones síncronas pesadas
    cpu_pool: ParkingLotRwLock<Option<ThreadPool>>,
    /// Timeout por defecto para operaciones
    default_timeout: Duration,
    /// Contador de tareas por tipo
    task_counters: ParkingLotRwLock<std::collections::HashMap<WorkType, usize>>,
}

impl ConcurrencyManager {
    /// Crea una nueva instancia del gestor de concurrencia
    pub fn new(memory_manager: Arc<MemoryManager>) -> Self {
        let physical_cores = num_cpus::get_physical();
        
        // Configuración inicial de límites basada en cores disponibles
        let mut limits = std::collections::HashMap::new();
        limits.insert(WorkType::FileScan, physical_cores * 2);
        limits.insert(WorkType::HeuristicAnalysis, physical_cores);
        limits.insert(WorkType::NetworkOperation, 4);
        limits.insert(WorkType::ServiceOperation, physical_cores / 2);
        
        // Crear semáforos iniciales
        let mut semaphores = std::collections::HashMap::new();
        for (work_type, limit) in &limits {
            semaphores.insert(*work_type, Arc::new(Semaphore::new(*limit)));
        }
        
        // Configurar pool de CPU
        let cpu_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(physical_cores)
            .thread_name(|i| format!("amaru-cpu-{}", i))
            .build()
            .ok();
        
        let mut task_counters = std::collections::HashMap::new();
        for work_type in [WorkType::FileScan, WorkType::HeuristicAnalysis, 
                         WorkType::NetworkOperation, WorkType::ServiceOperation].iter() {
            task_counters.insert(*work_type, 0);
        }
        
        Self {
            limits: ParkingLotRwLock::new(limits),
            semaphores: ParkingLotRwLock::new(semaphores),
            physical_cores,
            memory_manager,
            cpu_pool: ParkingLotRwLock::new(cpu_pool),
            default_timeout: Duration::from_secs(30),
            task_counters: ParkingLotRwLock::new(task_counters),
        }
    }
    
    /// Ajusta los límites de concurrencia basado en la carga del sistema
    pub fn adjust_concurrency_limits(&self) {
        let stats = self.memory_manager.get_system_stats();
        let low_power_conditions = stats.cpu_usage_percent > 80.0 || 
                                 stats.used_memory_mb as f32 / stats.total_memory_mb as f32 > 0.8;
        
        let mut limits = self.limits.write();
        
        if low_power_conditions {
            // Reducir límites en condiciones de alta carga
            limits.insert(WorkType::FileScan, std::cmp::max(1, self.physical_cores));
            limits.insert(WorkType::HeuristicAnalysis, std::cmp::max(1, self.physical_cores / 2));
            limits.insert(WorkType::NetworkOperation, 2);
            limits.insert(WorkType::ServiceOperation, 1);
            
            debug!("Límites de concurrencia reducidos por alta carga del sistema");
        } else {
            // Restaurar límites normales
            limits.insert(WorkType::FileScan, self.physical_cores * 2);
            limits.insert(WorkType::HeuristicAnalysis, self.physical_cores);
            limits.insert(WorkType::NetworkOperation, 4);
            limits.insert(WorkType::ServiceOperation, self.physical_cores / 2);
        }
        
        // Actualizar semáforos con nuevos límites
        let mut semaphores = self.semaphores.write();
        for (work_type, limit) in limits.iter() {
            // Solo actualizar si hay cambio
            if let Some(sem) = semaphores.get(work_type) {
                if sem.available_permits() != *limit {
                    semaphores.insert(*work_type, Arc::new(Semaphore::new(*limit)));
                }
            }
        }
    }
    
    /// Ejecuta una tarea asíncrona con límites de concurrencia
    pub async fn run_task<F, T>(&self, 
                             work_type: WorkType, 
                             task: F,
                             task_timeout: Option<Duration>) -> TaskResult<T>
    where
        F: Future<Output = Result<T, Box<dyn std::error::Error>>> + Send + 'static,
        T: Send + 'static,
    {
        // Incrementar contador de tareas
        {
            let mut counters = self.task_counters.write();
            if let Some(count) = counters.get_mut(&work_type) {
                *count += 1;
            }
        }
        
        // Obtener semáforo para este tipo de trabajo
        let semaphore = {
            let semaphores = self.semaphores.read();
            semaphores.get(&work_type).cloned().unwrap_or_else(|| {
                let limits = self.limits.read();
                let limit = limits.get(&work_type).cloned().unwrap_or(1);
                Arc::new(Semaphore::new(limit))
            })
        };
        
        // Adquirir permiso del semáforo o salir si hay presión del sistema
        let permit = match semaphore.acquire().await {
            Ok(permit) => permit,
            Err(_) => {
                // Decrementar contador
                let mut counters = self.task_counters.write();
                if let Some(count) = counters.get_mut(&work_type) {
                    *count -= 1;
                }
                return TaskResult::Error("No se pudo adquirir permiso del semáforo".to_string());
            }
        };
        
        // Configurar timeout
        let task_timeout = task_timeout.unwrap_or(self.default_timeout);
        let task_with_timeout = timeout(task_timeout, task);
        
        // Ejecutar tarea con timeout
        let result = task_with_timeout.await;
        
        // Liberar el permiso automáticamente cuando se descarta permit
        drop(permit);
        
        // Decrementar contador
        {
            let mut counters = self.task_counters.write();
            if let Some(count) = counters.get_mut(&work_type) {
                *count -= 1;
            }
        }
        
        // Procesar resultado
        match result {
            Ok(Ok(value)) => TaskResult::Completed(value),
            Ok(Err(e)) => TaskResult::Error(format!("Error en tarea: {}", e)),
            Err(_) => TaskResult::TimedOut,
        }
    }
    
    /// Ejecuta una tarea de CPU intensiva en el pool de hilos
    pub fn run_cpu_intensive<F, T>(&self, task: F) -> Result<T, String>
    where
        F: FnOnce() -> Result<T, Box<dyn std::error::Error>> + Send + 'static,
        T: Send + 'static,
    {
        let cpu_pool = self.cpu_pool.read();
        
        match &*cpu_pool {
            Some(pool) => {
                // Ejecutar en el pool de CPU
                let result = std::sync::Arc::new(std::sync::Mutex::new(None));
                let result_clone = result.clone();
                
                pool.install(move || {
                    let task_result = task();
                    let mut result_guard = result_clone.lock().unwrap();
                    *result_guard = Some(task_result);
                });
                
                // Obtener resultado
                let mut result_guard = result.lock().unwrap();
                match result_guard.take() {
                    Some(Ok(value)) => Ok(value),
                    Some(Err(e)) => Err(format!("Error en tarea CPU: {}", e)),
                    None => Err("No se completó la tarea CPU".to_string()),
                }
            },
            None => {
                // Fallback: ejecutar en el hilo actual si no hay pool
                warn!("No hay pool de CPU disponible, ejecutando en hilo actual");
                match task() {
                    Ok(value) => Ok(value),
                    Err(e) => Err(format!("Error en tarea CPU: {}", e)),
                }
            }
        }
    }
    
    /// Ejecuta una tarea asíncrona CPU intensiva en el pool de tokio
    pub async fn run_cpu_intensive_async<F, T>(&self, task: F) -> TaskResult<T>
    where
        F: FnOnce() -> Result<T, Box<dyn std::error::Error>> + Send + 'static,
        T: Send + 'static,
    {
        // Usar spawn_blocking para tareas que bloquean el hilo
        let task_future = spawn_blocking(move || task());
        
        match task_future.await {
            Ok(Ok(value)) => TaskResult::Completed(value),
            Ok(Err(e)) => TaskResult::Error(format!("Error en tarea CPU asíncrona: {}", e)),
            Err(_) => TaskResult::Cancelled,
        }
    }
    
    /// Obtener estadísticas actuales de concurrencia
    pub fn get_concurrency_stats(&self) -> ConcurrencyStats {
        let limits = self.limits.read();
        let counters = self.task_counters.read();
        
        let mut tasks_by_type = std::collections::HashMap::new();
        let mut limits_by_type = std::collections::HashMap::new();
        
        for work_type in [WorkType::FileScan, WorkType::HeuristicAnalysis, 
                         WorkType::NetworkOperation, WorkType::ServiceOperation].iter() {
            tasks_by_type.insert(*work_type, *counters.get(work_type).unwrap_or(&0));
            limits_by_type.insert(*work_type, *limits.get(work_type).unwrap_or(&1));
        }
        
        ConcurrencyStats {
            tasks_by_type,
            limits_by_type,
            physical_cores: self.physical_cores,
        }
    }
}

/// Estadísticas de concurrencia para monitoreo
#[derive(Debug, Clone)]
pub struct ConcurrencyStats {
    pub tasks_by_type: std::collections::HashMap<WorkType, usize>,
    pub limits_by_type: std::collections::HashMap<WorkType, usize>,
    pub physical_cores: usize,
}

/// Tipo de resultado para ejecución de múltiples tareas
pub struct BatchResults<T> {
    /// Resultados exitosos
    pub successful: Vec<T>,
    /// Conteo de errores 
    pub error_count: usize,
    /// Conteo de timeouts
    pub timeout_count: usize,
    /// Tiempo total de ejecución
    pub total_duration: Duration,
}

/// Extensión para ejecutar múltiples tareas en paralelo
impl ConcurrencyManager {
    /// Ejecuta múltiples tareas del mismo tipo en paralelo
    pub async fn run_batch<F, Fut, T>(&self, 
                                   work_type: WorkType,
                                   tasks: Vec<F>,
                                   task_timeout: Option<Duration>) -> BatchResults<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, Box<dyn std::error::Error>>> + Send + 'static,
        T: Send + 'static,
    {
        let start_time = Instant::now();
        let mut handles = Vec::with_capacity(tasks.len());
        
        // Crear futures para cada tarea
        for task_fn in tasks {
            let manager = self.clone();
            let work_type_clone = work_type;
            let timeout_clone = task_timeout;
            
            // Crear la tarea
            let handle = tokio::spawn(async move {
                let future = task_fn();
                manager.run_task(work_type_clone, future, timeout_clone).await
            });
            
            handles.push(handle);
        }
        
        // Esperar a que todas las tareas se completen
        let mut successful = Vec::new();
        let mut error_count = 0;
        let mut timeout_count = 0;
        
        for handle in handles {
            match handle.await {
                Ok(TaskResult::Completed(value)) => successful.push(value),
                Ok(TaskResult::Error(_)) => error_count += 1,
                Ok(TaskResult::TimedOut) => timeout_count += 1,
                Ok(TaskResult::Cancelled) => error_count += 1,
                Err(_) => error_count += 1,
            }
        }
        
        BatchResults {
            successful,
            error_count,
            timeout_count,
            total_duration: start_time.elapsed(),
        }
    }
}

/// Crea una copia del gestor con mismos parámetros para ser enviada entre hilos
impl Clone for ConcurrencyManager {
    fn clone(&self) -> Self {
        // Clonar mapa de límites
        let limits_clone = {
            let limits = self.limits.read();
            limits.clone()
        };
        
        // Clonar semáforos (compartiendo la referencia Arc)
        let semaphores_clone = {
            let semaphores = self.semaphores.read();
            semaphores.clone()
        };
        
        // Clonar contadores
        let counters_clone = {
            let counters = self.task_counters.read();
            counters.clone()
        };
        
        Self {
            limits: ParkingLotRwLock::new(limits_clone),
            semaphores: ParkingLotRwLock::new(semaphores_clone),
            physical_cores: self.physical_cores,
            memory_manager: self.memory_manager.clone(),
            cpu_pool: ParkingLotRwLock::new(self.cpu_pool.read().clone()),
            default_timeout: self.default_timeout,
            task_counters: ParkingLotRwLock::new(counters_clone),
        }
    }
} 