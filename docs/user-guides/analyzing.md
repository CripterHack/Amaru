# Guía de análisis y escaneo

Elige una carpeta pequeña si quieres comprobar el motor por primera vez. Un análisis de escritorio registra los archivos que pudo examinar, los que omitió, los errores y las detecciones. Revisa todos esos datos antes de interpretar el resultado.

## Tipos de análisis

| Opción de escritorio | Alcance |
| --- | --- |
| **Quick scan** | Recorre las carpetas configuradas para el análisis rápido. Por defecto utiliza Descargas, Escritorio y Documentos que existan para el usuario. |
| **Full scan** | Recorre la unidad de sistema de Windows, con los permisos de la sesión y las exclusiones aplicables. |
| **Custom scan** | Recorre la carpeta seleccionada en el diálogo de Windows. También puedes elegir una carpeta de una unidad externa conectada. |
| **Scheduled scan** | Abre la configuración de las tareas programadas. |

Para empezar, abre **Scan**, elige el tipo y pulsa **Start** en la tarjeta correspondiente. Durante la operación se muestran el archivo actual y los contadores. La cancelación conserva el resultado parcial de la sesión. Solo puede estar activo un análisis manual a la vez en la misma instancia de escritorio. [Pantalla de análisis](../../gui/src/routes/Scan.svelte) · [Registro de sesiones](../../gui/src-tauri/src/session.rs)

## Análisis rápido

En **Scan configuration**, la sección **Quick scan folders** permite añadir o retirar carpetas. Pulsa **Save folders** para guardar la selección. Los análisis rápidos manuales y las tareas configuradas para usar esas carpetas comparten la misma selección del usuario.

## Análisis completo

El recorrido examina los archivos regulares accesibles en la unidad de sistema. El tamaño máximo configurado, los permisos y los errores de lectura pueden limitar la cobertura. La pantalla de resultados conserva el recuento de archivos omitidos o fallidos. Para otras unidades usa la selección personalizada.

## Análisis personalizado

En **Scan**, pulsa **Start Custom scan**, selecciona una carpeta y revisa el resultado de la sesión. Para analizar un solo archivo desde una consola de Windows en la carpeta de instalación, utiliza la CLI.

```powershell
.\amaru.exe scan --path "C:\Amaru-Pruebas\documento.txt"
.\amaru.exe scan --path "C:\Amaru-Pruebas" --recursive
```

Puedes usar `--config` para elegir el TOML y `--heuristic=false` para una comprobación sin el motor heurístico. `--radare2` solicita análisis estático con una instalación disponible de Radare2. El escáner independiente de YARA-X ofrece otra vía para verificar las reglas desde el repositorio. [Comandos y opciones](../../src/cli.rs) · [YARA-X](../technical/yara-x.md)

## Análisis programados

1. Abre **Scheduled scan** y localiza **Scheduled quick scan**.
2. Elige la frecuencia diaria o semanal, la hora y, cuando corresponda, el día. Puedes usar las carpetas de análisis rápido del usuario o elegir una ruta concreta.
3. Guarda con **Save schedule** y comprueba la tarea en el Programador de tareas de Windows.

La tarea se registra para la cuenta actual con inicio de sesión interactivo y sus permisos habituales. La configuración de la tarea y su ejecución efectiva son comprobaciones diferentes. Tras la hora prevista, consulta el historial de análisis de esa cuenta y el último resultado de la tarea. [Preferencias de escritorio](../../gui/src-tauri/src/preferences.rs) · [Registro de la tarea](../../src/schedule.ps1)

## Entender los resultados

Las reglas coincidentes identifican patrones del catálogo. La heurística y el análisis estático pueden aportar otros indicadores. El nivel de riesgo expresa la clasificación del motor y un indicador aislado requiere interpretación. Una sesión parcial o cancelada deja archivos sin evaluar.

Las sesiones de escritorio guardan su historial local. La acción **Quarantine** sobre un hallazgo comprueba el contenido antes de aislarlo. La vigilancia del servicio tiene una política de respuesta independiente. [Cuarentena](./quarantine.md) · [Protección en tiempo real](./real-time-protection.md)

## Funciones del diseño pendientes

El diseño también contempla análisis de procesos en memoria y sectores de arranque, inspección de contenido dentro de archivos comprimidos, análisis al conectar dispositivos, integración con el menú contextual del Explorador y perfiles guardados para cada análisis personalizado. La periodicidad mensual, al arrancar o por inactividad y el envío automático de informes requieren integración y pruebas específicas. [Estado de desarrollo](../../status_development.md)
