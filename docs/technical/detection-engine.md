# Motor de Detección Amaru: Especificaciones Técnicas

Esta especificación recoge el diseño del motor de detección. El catálogo actual reúne reglas YARA clásicas y admite una comprobación independiente con YARA-X. El motor Rust comprueba archivos y búferes con las reglas locales. La suite incluye EICAR y controles negativos. [Motor Rust](../../yara-engine/src/lib.rs) · [Prueba del catálogo](../../yara-engine/tests/signatures.rs) · [Validación con YARA-X](yara-x.md)

El monitor de archivos y el análisis estático con Radare2 tienen implementaciones y pruebas propias. La integración del servicio Windows, las funciones de reputación en la nube, el análisis dinámico en sandbox y los modelos de aprendizaje automático requieren validaciones independientes. [Monitor](../../realtime-monitor/src/lib.rs) · [Analizador estático](../../radare2-analyzer/src/lib.rs) · [Estado del proyecto](../../status_development.md)

## Índice

1. [Arquitectura del Motor](#arquitectura-del-motor)
2. [Algoritmos de Detección](#algoritmos-de-detección)
3. [Implementación del Sistema de Patrones](#implementación-del-sistema-de-patrones)
4. [Optimización de Rendimiento](#optimización-de-rendimiento)
5. [Integración de API](#integración-de-api)
6. [Métricas y Telemetría](#métricas-y-telemetría)
7. [Consideraciones de Implementación](#consideraciones-de-implementación)

## Arquitectura del Motor

El diseño propone una arquitectura modular de microservicios para escalar componentes individuales y actualizarlos por separado. El workspace agrupa los motores implementados como crates de Rust. [Manifiesto](../../Cargo.toml)

### Componentes previstos en la arquitectura

```
+-------------------------+      +------------------------+      +------------------------+
|                         |      |                        |      |                        |
|  Capa de Interceptación |----->|  Núcleo de Análisis   |----->|  Sistema de Decisión   |
|                         |      |                        |      |                        |
+-------------------------+      +------------------------+      +------------------------+
           |                                |                              |
           v                                v                              v
+-------------------------+      +------------------------+      +------------------------+
|                         |      |                        |      |                        |
|  Sistema de Reputación  |<---->|  Base de Conocimiento |<---->|  Motor de Respuesta   |
|                         |      |                        |      |                        |
+-------------------------+      +------------------------+      +------------------------+
```

#### Capa de Interceptación

- **Controladores de Kernel**: Monitorean operaciones a nivel de sistema operativo
  - Hook de sistema de archivos (IRP/minifilter en Windows, kprobes en Linux)
  - Monitoreo de procesos (PsSetCreateProcessNotifyRoutine en Windows)
  - Intercepción de red (WFP en Windows, Netfilter en Linux)

- **Sensores de Usuario**: Monitoreo a nivel de aplicación
  - Hooks de API (IAT/EAT hooking, inline hooking)
  - Monitoreo de navegadores (extensiones, filtros de contenido)
  - Interceptación de eventos de sistema

#### Núcleo de Análisis

- **Motor Estático**: Analiza archivos sin ejecución
  - Parser de formatos (PE, ELF, DEX, PDF, Office, etc.)
  - Desensamblador y analizador de código
  - Extractor de características estáticas

- **Motor Dinámico**: Analiza comportamiento en ejecución
  - Sandbox de ejecución controlada
  - Sistema de emulación de código
  - Analizador de comportamiento en memoria

- **Motor de Análisis Profundo**: Algoritmos avanzados
  - Procesamiento de redes neuronales
  - Motores de reglas complejas
  - Análisis de similitud estructural

#### Sistema de Decisión

- **Fusión de Señales**: Combina resultados de diferentes análisis
- **Motor de Políticas**: Aplica reglas configuradas por el usuario
- **Clasificador Final**: Determina la acción a tomar

### Flujo de datos previsto

1. La capa de interceptación captura eventos (acceso a archivos, ejecución, conexiones)
2. Los eventos se filtran mediante reglas de pre-procesamiento
3. Los elementos que pasan el filtro se analizan en los motores correspondientes
4. El sistema de reputación proporciona datos adicionales de la nube
5. El sistema de decisión evalúa todos los resultados
6. Se ejecuta la acción apropiada (permitir, bloquear, cuarentena, etc.)
7. Se registra la actividad y se actualiza la base de conocimiento

## Algoritmos de Detección

### Detección Basada en Firmas

#### Firmas Tradicionales

- **Hash Criptográfico**: MD5, SHA1, SHA256 para identificación exacta
- **Firmas Parciales**: Secuencias binarias específicas (YARA-like)
- **Firmas Estructurales**: Basadas en estructura del archivo

```
// Ejemplo de regla YARA simplificada
rule TrojanX {
    strings:
        $hex_string = { 8B 45 ?? 83 C0 ?? 89 45 ?? }
        $text_string = "initialize_payload"
    condition:
        $hex_string and $text_string
}
```

#### Firmas Avanzadas

- **Firmas Estadísticas**: Basadas en distribuciones de características
- **Firmas Metamórficas**: Para detectar malware auto-modificable
- **Firmas de Comportamiento**: Secuencias de acciones específicas

### Algoritmos Heurísticos

- **Heurística Estática**: Análisis de características sospechosas
  - Empaquetadores conocidos
  - Secciones anómalas en ejecutables
  - Uso de APIs sospechosas
  - Entropía elevada

- **Heurística Dinámica**: Análisis de comportamiento
  - Acceso a recursos sensibles
  - Patrones de inyección de código
  - Técnicas de persistencia
  - Comunicaciones sospechosas

### Algoritmos de Machine Learning

#### Modelos especificados para desarrollo

- **Clasificadores basados en árboles**
  - Gradient Boosting Trees (XGBoost)
  - Random Forest
  - Configuraciones: profundidad máxima 12, 500 estimadores

- **Redes Neuronales**
  - CNN para análisis de secuencias binarias
  - Arquitectura: 4 capas convolucionales, 2 capas fully-connected
  - Tamaño de entrada: secuencias binarias de 2MB máximo

- **Transformadores**
  - Atención multi-cabeza para secuencias de comportamiento
  - 6 capas de codificador, 8 cabezas de atención
  - Dimensión del modelo: 512

- **Detección de Anomalías**
  - Autoencoders para perfilado de comportamiento normal
  - Isolation Forest para detección de outliers
  - DBSCAN para clustering de comportamientos

#### Características previstas para los modelos

Para análisis estático:
- Histogramas de n-gramas de bytes
- Grafos de importación y exportación
- Secuencias de operadores en código desensamblado
- Metadatos estructurales (tamaños, entropía, etc.)

Para análisis dinámico:
- Secuencias de llamadas a API
- Grafos de dependencia de procesos
- Patrones de acceso a archivos/registro
- Estadísticas de comportamiento de red

#### Pipeline de Entrenamiento

1. Recolección de muestras (benignas y maliciosas)
2. Extracción de características
3. Preprocesamiento y normalización
4. Entrenamiento de modelos con validación cruzada
5. Optimización de hiperparámetros
6. Evaluación en conjuntos de prueba independientes
7. Despliegue en producción con monitoreo

## Implementación del Sistema de Patrones

### Estructura de Base de Conocimiento

El diseño de la base de conocimiento contempla almacenamiento híbrido. La distribución actual incluye el catálogo de archivos de reglas en el repositorio. [Catálogo](../../signatures)

- **Base de Datos Principal**: Almacena metadatos, relaciones y configuraciones
  - Sistema: PostgreSQL/MariaDB
  - Esquema: Normalizado para relaciones complejas entre familias de malware

- **Almacén de Patrones**: Optimizado para búsqueda rápida
  - Sistema: Basado en grafos (Neo4j) para relaciones
  - Índices especializados para búsquedas por similitud

- **Caché Local**: Subconjunto crítico para operación sin conexión
  - Formato: Binario comprimido optimizado para búsqueda
  - Actualización: Diferencial (delta updates)

### Representación de Patrones

Los siguientes esquemas JSON ilustran la representación de patrones propuesta.

#### Patrones Binarios

```json
{
  "pattern_id": "MAL-BIN-12345",
  "type": "binary_sequence",
  "detection_name": "Trojan.GenericKD.12345",
  "severity": "high",
  "confidence_threshold": 0.85,
  "sequences": [
    {
      "offset": "variable",
      "sequence": "4D5A90000300000004000000FFFF",
      "mask": "FFFFFFFFFFFFFFFFFFFFFFFF0000",
      "weight": 0.7
    },
    {
      "offset": "EOF-512",
      "sequence": "504B0506000000000100010052",
      "weight": 0.3
    }
  ],
  "logical_condition": "any",
  "family_relations": ["MAL-FAM-Dridex"]
}
```

#### Patrones de Comportamiento

```json
{
  "pattern_id": "MAL-BHV-54321",
  "type": "behavior_sequence",
  "detection_name": "Ransomware.CryptoLocker",
  "severity": "critical",
  "confidence_threshold": 0.75,
  "behaviors": [
    {
      "api_sequence": [
        {"api": "CryptAcquireContext", "params": {"flags": "CRYPT_SILENT"}},
        {"api": "CryptCreateHash", "params": {"algorithm": "CALG_SHA_256"}},
        {"api": "CryptEncrypt", "repeat_min": 10}
      ],
      "weight": 0.6
    },
    {
      "file_operations": {
        "pattern": "*.* → *.encrypted",
        "min_count": 5,
        "timeframe_seconds": 300
      },
      "weight": 0.4
    }
  ],
  "logical_condition": "all",
  "family_relations": ["MAL-FAM-Ransomware"]
}
```

#### Patrones de Red

```json
{
  "pattern_id": "MAL-NET-98765",
  "type": "network_pattern",
  "detection_name": "Botnet.Trickbot",
  "severity": "high",
  "confidence_threshold": 0.8,
  "indicators": [
    {
      "type": "domain_pattern",
      "pattern": "^[a-z]{8}\\-[a-z]{6}\\.xyz$",
      "weight": 0.5
    },
    {
      "type": "http_request",
      "method": "POST",
      "uri_pattern": "/gate\\.php$",
      "headers": {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 7.0;)"
      },
      "weight": 0.5
    }
  ],
  "logical_condition": "any",
  "family_relations": ["MAL-FAM-Trickbot"]
}
```

### Sistema de Coincidencia de Patrones

La especificación contempla los siguientes algoritmos y parámetros de coincidencia. La ruta de escaneo validada delega la coincidencia en YARA.

- **Aho-Corasick**: Para búsqueda eficiente de múltiples patrones de cadenas
  - Complejidad: O(n + m + z) donde z es el número de coincidencias
  - Implementación optimizada con SIMD para arquitecturas modernas

- **Bloom Filters**: Pre-filtrado rápido antes de análisis completos
  - Configuración: 3 funciones hash, tasa de falsos positivos <0.1%
  - Tamaño: adaptativo según volumen de firmas

- **Algoritmo Rabin-Karp modificado**: Para patrones con wildcards
  - Hash Rolling con ventana deslizante
  - Optimizado para CPU modernas con instrucciones especializadas

- **Árboles de decisión compilados**: Para patrones de comportamiento
  - Transformación de patrones a código nativo optimizado
  - Caché de resultados intermedios para evaluaciones repetidas

## Optimización de Rendimiento

### Estrategias de Optimización

#### Priorización y Filtrado

- **Análisis por Capas**: Progresión de técnicas menos a más intensivas
  - Capa 1: Reputación y hashes (millisegundos)
  - Capa 2: Análisis heurístico ligero (millisegundos)
  - Capa 3: Análisis estático completo (decenas - cientos de millisegundos)
  - Capa 4: Análisis dinámico en sandbox (segundos)

- **Pre-filtrado Inteligente**: 
  - Firma de desarrolladores confiables
  - Reputación contextual
  - Cache de resultados previos

#### Paralelización

- **Procesamiento Multi-núcleo**:
  - Arquitectura de workers independientes
  - Distribución dinámica de carga
  - Pipeline de análisis segmentado

- **Uso de GPU**:
  - Aceleración para modelos CNN y Transformer
  - Implementación con CUDA/TensorRT para NVIDIA
  - Fallback a CPU para sistemas sin GPU compatible

#### Optimización de Memoria

- **Estructuras de Datos Especializadas**:
  - Árboles de prefijos comprimidos para firmas
  - Representaciones sparse para matrices grandes
  - Liberación agresiva de memoria para análisis completos

- **Política de Caché**:
  - LRU para resultados de análisis frecuentes
  - Caché persistente entre reinicios
  - Invalidación inteligente basada en actualizaciones

### Métricas de Rendimiento

La tabla fija objetivos para futuras pruebas. La revisión del repositorio no encontró mediciones publicadas de latencia, CPU ni memoria para estas cargas. El motor YARA clásico omite por defecto los archivos mayores de 100 MiB. Una medición de archivos grandes debe comprobar que se analizaron sus bytes. [Implementación del escaneo](../../yara-engine/src/lib.rs)

| Operación | Tiempo Objetivo | Uso de CPU | Uso de Memoria |
|-----------|-----------------|------------|----------------|
| Verificación de archivo pequeño (<1MB) | <100ms | <10% | <50MB |
| Verificación de archivo mediano (1-100MB) | <1s | <20% | <100MB |
| Verificación de archivo grande (>100MB) | <10s | <30% | <200MB |
| Análisis de comportamiento en tiempo real | Latencia <50ms | <5% continuo | <150MB |
| Análisis completo del sistema | - | <30% medio | <500MB |

## Integración de API

Las firmas C siguientes definen la interfaz de integración prevista. La referencia de desarrollo identifica las entradas Rust disponibles. [Referencia de API](api-reference.md)

### APIs Internas

```c
// Inicialización del motor
DETECTION_STATUS AmEngine_Initialize(
    ENGINE_CONFIG* config,
    ENGINE_CALLBACK callback,
    void* userData
);

// Análisis de archivo
DETECTION_RESULT AmEngine_ScanFile(
    const wchar_t* filePath,
    SCAN_OPTIONS options,
    DETECTION_CALLBACK resultCallback,
    void* userData
);

// Análisis de memoria
DETECTION_RESULT AmEngine_ScanMemory(
    void* buffer,
    size_t bufferSize,
    const wchar_t* contextName,
    SCAN_OPTIONS options,
    DETECTION_CALLBACK resultCallback,
    void* userData
);

// Notificación de evento de comportamiento
DETECTION_STATUS AmEngine_NotifyBehavior(
    BEHAVIOR_EVENT* event,
    PROCESS_CONTEXT* context
);
```

### Hooks de Extensibilidad

El diseño prevé estos puntos de extensión para personalización.

```c
// Configuración de callback personalizado para decisión final
DETECTION_STATUS AmEngine_SetDecisionCallback(
    DECISION_CALLBACK callback,
    void* userData
);

// Registro de proveedores de reputación externos
DETECTION_STATUS AmEngine_RegisterReputationProvider(
    REPUTATION_PROVIDER_INFO* provider,
    REPUTATION_CALLBACK callback
);

// Registro de analizador personalizado
DETECTION_STATUS AmEngine_RegisterCustomAnalyzer(
    const char* analyzerID,
    ANALYZER_INFO* info,
    ANALYZER_CALLBACK callback,
    void* userData
);
```

## Métricas y Telemetría

### Datos previstos

El diseño de telemetría propone recopilar las siguientes categorías con consentimiento del usuario. Su habilitación y destino deben comprobarse antes de describir una instalación que envíe datos.

- **Métricas de Rendimiento**:
  - Tiempos de análisis por tipo de archivo
  - Uso de recursos durante operaciones
  - Tasas de acierto de caché

- **Métricas de Detección**:
  - Coincidencias de patrones (anónimas)
  - Distribución de amenazas detectadas
  - Efectividad de diferentes algoritmos
  - Falsos positivos reportados

- **Muestras Anónimas** (opcional, solicita confirmación):
  - Hashes de archivos desconocidos
  - Características de comportamiento anómalas
  - Nuevos patrones potencialmente maliciosos

### Sistema de Retroalimentación

- **Bucle de Aprendizaje**:
  - Análisis de patrones emergentes
  - Ajuste automático de umbrales
  - Generación de nuevas reglas heurísticas

- **Validación Continua**:
  - Pruebas A/B de nuevos algoritmos
  - Verificación de efectividad de nuevos patrones
  - Monitoreo de tasas de falsos positivos

## Consideraciones de Implementación

### Recursos previstos para el diseño completo

- **Mínimos**:
  - CPU: Arquitectura x86-64 con soporte SSE4.2
  - RAM: 1GB disponible para el motor
  - Almacenamiento: 250MB para instalación básica + 1GB para base de conocimiento

- **Recomendados**:
  - CPU: 4+ núcleos con AVX2
  - GPU: Compatible con CUDA/OpenCL para aceleración ML
  - RAM: 4GB disponible para el motor
  - Almacenamiento SSD: 4GB para caché y base de conocimiento

### Limitaciones previstas para el diseño completo

- Análisis de archivos cifrados requiere interfaces específicas para cada formato
- Algunos algoritmos avanzados pueden no estar disponibles en modo sin conexión
- Detección en arquitecturas no x86 (ARM, RISC-V) tiene subconjunto de capacidades
- Archivos extremadamente grandes (>4GB) utilizan análisis por sectores con menor precisión

### Notas para Desarrolladores

- Priorizar optimización de hot-paths en el proceso de análisis
- Implementar estrategias de recuperación para errores transitorios
- Utilizar profiling para identificar cuellos de botella
- Mantener compatibilidad hacia atrás para formatos de patrones anteriores

---

Para contrastar el diseño con una versión concreta, consulta la revisión de código y su registro de validación. [Estado del proyecto](../../status_development.md)
