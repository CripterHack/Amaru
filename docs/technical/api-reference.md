# Referencia de la API de Amaru Antivirus

## Introducción

Esta documentación describe las APIs disponibles en Amaru Antivirus para desarrolladores que desean integrar sus aplicaciones con nuestro sistema o extender su funcionalidad. Las APIs se dividen en diferentes categorías según su propósito y nivel de acceso.

## Índice

- [API del Core](#api-del-core)
- [API de Escaneo](#api-de-escaneo)
- [API de Monitoreo](#api-de-monitoreo)
- [API de Configuración](#api-de-configuración)
- [API de Notificaciones](#api-de-notificaciones)
- [API de Eventos](#api-de-eventos)
- [Ejemplos de Uso](#ejemplos-de-uso)

## API del Core

### Inicialización del Core

```rust
/// Inicializa el motor principal de Amaru con la configuración especificada
/// 
/// # Argumentos
/// * `config_path` - Ruta al archivo de configuración o None para usar la configuración por defecto
/// * `log_level` - Nivel de registro (debug, info, warn, error)
/// 
/// # Retorno
/// Resultado con el manejador del core inicializado o un error
pub async fn initialize_core(config_path: Option<PathBuf>, log_level: LogLevel) -> Result<CoreHandle, CoreError>
```

### Finalización del Core

```rust
/// Detiene de forma ordenada todos los servicios del core
/// 
/// # Argumentos
/// * `handle` - Manejador del core obtenido mediante initialize_core
/// 
/// # Retorno
/// Resultado con éxito o error durante el apagado
pub async fn shutdown_core(handle: CoreHandle) -> Result<(), CoreError>
```

### Obtención de Estadísticas

```rust
/// Obtiene estadísticas generales del sistema
/// 
/// # Argumentos
/// * `handle` - Manejador del core
/// 
/// # Retorno
/// Estadísticas del sistema o error
pub async fn get_system_stats(handle: &CoreHandle) -> Result<SystemStats, CoreError>
```

## API de Escaneo

### Escaneo de Archivos

```rust
/// Escanea un archivo o directorio en busca de amenazas
/// 
/// # Argumentos
/// * `handle` - Manejador del core
/// * `path` - Ruta al archivo o directorio a escanear
/// * `options` - Opciones de escaneo personalizadas
/// 
/// # Retorno
/// Resultado del escaneo o error
pub async fn scan_path(handle: &CoreHandle, path: &Path, options: ScanOptions) -> Result<ScanResult, ScanError>
```

### Escaneo de Memoria

```rust
/// Escanea la memoria del proceso especificado
/// 
/// # Argumentos
/// * `handle` - Manejador del core
/// * `pid` - ID del proceso a escanear
/// * `options` - Opciones de escaneo personalizadas
/// 
/// # Retorno
/// Resultado del escaneo o error
pub async fn scan_process(handle: &CoreHandle, pid: u32, options: ScanOptions) -> Result<ScanResult, ScanError>
```

### Cancelación de Escaneo

```rust
/// Cancela un escaneo en progreso
/// 
/// # Argumentos
/// * `scan_id` - ID del escaneo a cancelar
/// 
/// # Retorno
/// Resultado de la operación
pub async fn cancel_scan(scan_id: Uuid) -> Result<(), ScanError>
```

## API de Monitoreo

### Activación del Monitor en Tiempo Real

```rust
/// Activa o desactiva el monitor en tiempo real
/// 
/// # Argumentos
/// * `handle` - Manejador del core
/// * `enabled` - Estado deseado (true para activar, false para desactivar)
/// * `options` - Opciones de configuración para el monitor
/// 
/// # Retorno
/// Resultado de la operación
pub async fn set_realtime_protection(
    handle: &CoreHandle, 
    enabled: bool, 
    options: Option<MonitorOptions>
) -> Result<(), MonitorError>
```

### Estado del Monitor

```rust
/// Obtiene el estado actual del monitor en tiempo real
/// 
/// # Argumentos
/// * `handle` - Manejador del core
/// 
/// # Retorno
/// Estado del monitor o error
pub async fn get_monitor_status(handle: &CoreHandle) -> Result<MonitorStatus, MonitorError>
```

## API de Configuración

### Obtención de Configuración

```rust
/// Obtiene la configuración actual del sistema
/// 
/// # Argumentos
/// * `handle` - Manejador del core
/// 
/// # Retorno
/// Configuración actual o error
pub async fn get_config(handle: &CoreHandle) -> Result<Config, ConfigError>
```

### Actualización de Configuración

```rust
/// Actualiza la configuración del sistema
/// 
/// # Argumentos
/// * `handle` - Manejador del core
/// * `config` - Nueva configuración a aplicar
/// 
/// # Retorno
/// Resultado de la operación
pub async fn update_config(handle: &CoreHandle, config: Config) -> Result<(), ConfigError>
```

## API de Notificaciones

### Envío de Notificaciones

```rust
/// Envía una notificación al usuario
/// 
/// # Argumentos
/// * `handle` - Manejador del core
/// * `notification` - Detalle de la notificación a enviar
/// 
/// # Retorno
/// ID de la notificación enviada o error
pub async fn send_notification(
    handle: &CoreHandle, 
    notification: Notification
) -> Result<String, NotificationError>
```

### Historial de Notificaciones

```rust
/// Obtiene el historial de notificaciones
/// 
/// # Argumentos
/// * `handle` - Manejador del core
/// * `limit` - Número máximo de notificaciones a retornar
/// * `offset` - Desplazamiento desde el inicio
/// 
/// # Retorno
/// Lista de notificaciones o error
pub async fn get_notifications(
    handle: &CoreHandle, 
    limit: usize, 
    offset: usize
) -> Result<Vec<Notification>, NotificationError>
```

## API de Eventos

### Suscripción a Eventos

```rust
/// Se suscribe a eventos específicos del sistema
/// 
/// # Argumentos
/// * `handle` - Manejador del core
/// * `event_types` - Lista de tipos de eventos a los que suscribirse
/// 
/// # Retorno
/// Stream de eventos o error
pub async fn subscribe_to_events(
    handle: &CoreHandle, 
    event_types: Vec<EventType>
) -> Result<impl Stream<Item = Event>, EventError>
```

## Interfaz de Línea de Comandos (CLI)

Además de la API programática, Amaru proporciona una interfaz de línea de comandos con los siguientes comandos:

```
COMANDOS:
  scan       Escanea archivos o directorios
  monitor    Controla la protección en tiempo real
  update     Actualiza las reglas y definiciones
  config     Gestiona la configuración
  quarantine Gestiona los archivos en cuarentena
  stats      Muestra estadísticas del sistema
  help       Muestra esta ayuda
```

## Ejemplos de Uso

### Ejemplo: Escaneo Básico

```rust
use amaru_engine::{initialize_core, scan_path, LogLevel};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Inicializar el core
    let handle = initialize_core(None, LogLevel::Info).await?;
    
    // Escanear un directorio
    let path = Path::new("C:\\Users\\Usuario\\Documentos");
    let scan_options = Default::default();
    let result = scan_path(&handle, path, scan_options).await?;
    
    // Mostrar resultados
    println!("Archivos escaneados: {}", result.scanned_files);
    println!("Amenazas encontradas: {}", result.threats_found);
    
    for threat in result.threats {
        println!("Amenaza: {} - Nivel: {}", threat.name, threat.risk_level);
    }
    
    Ok(())
}
```

### Ejemplo: Monitoreo en Tiempo Real

```rust
use amaru_engine::{initialize_core, set_realtime_protection, LogLevel, MonitorOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Inicializar el core
    let handle = initialize_core(None, LogLevel::Info).await?;
    
    // Configurar opciones del monitor
    let options = MonitorOptions {
        use_heuristics: true,
        monitored_paths: vec![
            "C:\\Program Files".into(),
            "C:\\Users".into(),
        ],
        exclude_paths: vec![
            "C:\\Users\\Usuario\\AppData\\Local\\Temp".into(),
        ],
        ..Default::default()
    };
    
    // Activar la protección en tiempo real
    set_realtime_protection(&handle, true, Some(options)).await?;
    println!("Protección en tiempo real activada");
    
    // Mantener el programa en ejecución
    tokio::signal::ctrl_c().await?;
    println!("Cerrando aplicación...");
    
    Ok(())
}
```

## Códigos de Estado y Errores

Todos los módulos de la API devuelven errores tipados que pueden ser los siguientes:

| Código | Tipo | Descripción |
|--------|------|-------------|
| 1000 | CoreError::InitError | Error al inicializar el core |
| 1001 | CoreError::ShutdownError | Error al detener el core |
| 2000 | ScanError::InvalidPath | Ruta inválida para escanear |
| 2001 | ScanError::AccessDenied | Acceso denegado al archivo o directorio |
| 2002 | ScanError::ScanAborted | Escaneo abortado por el usuario |
| 3000 | MonitorError::AlreadyRunning | El monitor ya está en ejecución |
| 3001 | MonitorError::NotRunning | El monitor no está en ejecución |
| 4000 | ConfigError::InvalidConfig | Configuración inválida |
| 4001 | ConfigError::SaveError | Error al guardar la configuración |

## Consideraciones de Seguridad

Al utilizar las APIs de Amaru, tenga en cuenta las siguientes consideraciones de seguridad:

1. **Privilegios**: Algunas operaciones requieren privilegios elevados
2. **Manejo de datos**: Los resultados del escaneo pueden contener información sensible
3. **Rendimiento**: Las operaciones de escaneo son intensivas en recursos
4. **Concurrencia**: Evite realizar múltiples operaciones de escaneo simultáneas

## Limitaciones

- Las APIs están disponibles únicamente en Windows 10/11 (64-bit)
- Algunas funcionalidades requieren privilegios administrativos
- El número máximo de suscriptores de eventos está limitado a 100 por instancia

## Próximas Funcionalidades

- API REST para integraciones web
- Soporte para entornos multi-usuario
- Extensión de la API de plugins

## Soporte y Contacto

Para preguntas y soporte sobre la API, contacta a:

- Correo: api-support@amaru-antivirus.com
- Foro de desarrolladores: https://dev.amaru-antivirus.com 