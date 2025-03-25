# Arquitectura del Sistema Amaru Antivirus

## Visión General

Amaru Antivirus utiliza una arquitectura modular basada en microservicios, construida principalmente en Rust para el núcleo y JavaScript/TypeScript con Svelte para la interfaz de usuario. Esta arquitectura permite un alto rendimiento, seguridad mejorada y capacidad de ampliación.

![Diagrama de Arquitectura](../assets/images/architecture-diagram.png)

## Componentes Principales

### Core Engine (Rust)

El núcleo de Amaru está escrito en Rust y proporciona los servicios fundamentales de seguridad:

- **Scanner Engine**: Responsable del análisis de archivos y detección de amenazas
- **Yara Engine**: Integración con reglas YARA para detección de patrones
- **Behavioral Analyzer**: Análisis heurístico basado en el comportamiento de archivos
- **Real-time Monitor**: Sistema de monitoreo en tiempo real para protección activa
- **Update Service**: Servicio de actualización de firmas y componentes

### GUI Frontend (Tauri + Svelte)

La interfaz de usuario está desarrollada con Tauri y Svelte, ofreciendo:

- Interfaz moderna y responsiva
- Visualización de estadísticas y eventos
- Panel de configuración
- Gestión de cuarentena
- Centro de notificaciones
- Sistema de ayuda y soporte

### Servicios Auxiliares

- **Resource Manager**: Optimización del uso de recursos del sistema
- **Concurrency Manager**: Gestión de operaciones simultáneas
- **Notification System**: Sistema de notificaciones y alertas
- **Digital Signature**: Verificación de firmas digitales
- **Secure Logging**: Sistema de registro seguro

## Flujo de Datos

1. **Detección de Eventos**: El monitor en tiempo real o el escáner bajo demanda detectan eventos
2. **Análisis**: Los archivos son analizados mediante reglas YARA y análisis heurístico
3. **Verificación**: Se verifican las firmas digitales y se evalúa el nivel de amenaza
4. **Acción**: Se toman acciones según la configuración (cuarentena, eliminación, alerta)
5. **Notificación**: Se notifica al usuario a través del sistema de notificaciones

## Comunicación entre Componentes

Los componentes se comunican a través de:

- Canales de Tokio para comunicación asincrónica en Rust
- Invocación de comandos entre Tauri y la capa de Rust
- WebSockets para actualizaciones en tiempo real de la UI
- Eventos de sistema para notificaciones de nivel OS

## Modelo de Seguridad

Amaru implementa un modelo de seguridad en capas:

1. **Privilegios mínimos**: Cada componente opera con los mínimos privilegios necesarios
2. **Aislamiento**: Los componentes críticos se ejecutan en procesos aislados
3. **Verificación**: Todas las actualizaciones y reglas son verificadas criptográficamente
4. **Encriptación**: Los datos sensibles se almacenan cifrados

## Extensibilidad

La arquitectura permite extensiones mediante:

- Sistema de plugins para escáneres especializados
- API para integraciones con otros sistemas de seguridad
- Configuración de reglas YARA personalizadas
- Scripts de automatización para respuestas personalizadas

## Requisitos de Sistema

- **Sistema Operativo**: Windows 10/11 (64-bit)
- **CPU**: Procesador de 2 núcleos o superior
- **RAM**: Mínimo 4GB (8GB recomendado)
- **Espacio en disco**: 500MB para la instalación básica
- **Dependencias**: Radare2, YARA 4.3+

## Diagrama de Clases

```
+-------------------+     +-------------------+     +-------------------+
|  ScannerService   |---->|    YaraEngine     |---->|    RuleManager    |
+-------------------+     +-------------------+     +-------------------+
         |                        |                         |
         v                        v                         v
+-------------------+     +-------------------+     +-------------------+
| BehavioralAnalyzer|---->|  ConcurrencyMgr   |---->|  ResourceManager  |
+-------------------+     +-------------------+     +-------------------+
         |                        |                         |
         v                        v                         v
+-------------------+     +-------------------+     +-------------------+
| RealtimeMonitor   |---->| NotificationSystem|---->|   ConfigManager   |
+-------------------+     +-------------------+     +-------------------+
         |                        |                         |
         v                        v                         v
+-------------------+     +-------------------+     +-------------------+
|   QuarantineSystem|---->|  UpdateService    |---->|    TauriBackend   |
+-------------------+     +-------------------+     +-------------------+
                                                            |
                                                            v
                                                   +-------------------+
                                                   |    SvelteUI       |
                                                   +-------------------+
```

## Consideraciones de Rendimiento

- Uso de pools de hilos configurables para operaciones intensivas
- Implementación de escaneo incremental para reducir impacto
- Sistema de memoria caché para reglas YARA frecuentes
- Política de suspensión durante carga alta del sistema
- Optimización de uso de memoria para dispositivos con recursos limitados

## Referencias

- [Código Fuente en GitHub](https://github.com/CripterHack/Amaru)
- [Documentación de la API](./api-reference.md)
- [Guía de Desarrollo](./development-guide.md)
- [Especificaciones del Sistema](./system-specs.md) 