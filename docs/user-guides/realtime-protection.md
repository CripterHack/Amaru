# Protección en tiempo real

Esta página conserva los accesos de la ayuda integrada. La guía principal reúne las instrucciones de uso, un ejemplo TOML y la verificación del monitor. [Guía de protección en tiempo real](./real-time-protection.md)

## Componentes de protección

El control **Real-time Protection** corresponde al monitor de archivos del servicio de Windows. Analiza las creaciones, modificaciones y cambios de nombre admitidos en las rutas vigiladas. Puede aportar evidencia YARA, heurística y análisis estático según el archivo y la configuración. [Funcionamiento](./real-time-protection.md#cómo-funciona)

La protección web y de correo, el cortafuegos, la vigilancia del comportamiento de procesos y el bloqueo preventivo de ransomware forman parte del diseño general. Su integración y validación tienen requisitos distintos de los del monitor de archivos. [Componentes y modos previstos](./real-time-protection.md#componentes-y-modos-previstos)

## Configuración de la protección

El servicio lee `monitored_paths`, `realtime_protection` y los filtros de `[scan_config]` de su TOML. El panel de escritorio consulta el estado del servicio y permite cambiar la vigilancia con los permisos correspondientes. [Configuración y ejemplo](./real-time-protection.md#configuración)

## Exclusiones

`scan_config.exclude_paths` admite rutas de archivos o directorios. La carpeta de reglas y el almacén de cuarentena se excluyen de la vigilancia automáticamente. [Filtros y extensiones](./real-time-protection.md#configuración)

## Notificaciones

El motor emite eventos de detección, cambio de estado, cuarentena y errores. El panel refleja el estado comunicado por el servicio. El diseño contempla avisos configurables de bandeja, resúmenes por correo y modo de juego. [Estado y controles](./real-time-protection.md#estado-y-controles) · [Respuesta en cuarentena](./quarantine.md)
