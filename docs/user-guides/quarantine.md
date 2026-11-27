# Gestión de la cuarentena

Amaru puede retirar un archivo de su ruta original y guardar una copia cifrada. Una detección y una entrada en cuarentena son dos resultados distintos. Para confirmar el aislamiento, consulta la entrada correspondiente en el almacén que utilizó el escáner.

## Acceso a la cuarentena

En la aplicación de escritorio, abre **Quarantine** en la navegación lateral. La tabla muestra los archivos de la cuarentena de escritorio. Para guardar un hallazgo de una sesión de análisis, elige **Quarantine** junto al resultado y confirma. Amaru vuelve a comprobar el SHA-256 del archivo antes de moverlo. Si el contenido cambió después del análisis, vuelve a escanearlo.

El servicio de Windows también puede guardar archivos en su propia cuarentena. Con la ruta relativa predeterminada, el escritorio utiliza el directorio de datos locales de la aplicación y el servicio resuelve la ruta desde su configuración. El origen del análisis determina qué almacén debes consultar. [Integración de escritorio](../../gui/src-tauri/src/desktop.rs) · [Servicio de Windows](../../src/service.rs)

## Elementos en cuarentena

La tabla muestra el nombre del archivo, la ruta original, el motivo, la fecha de aislamiento y el tamaño original. El catálogo también guarda el identificador de la entrada y el SHA-256. Dos archivos con el mismo contenido pueden pertenecer a entradas distintas.

El almacén guarda los bytes con AES-256-GCM. En las entradas actuales, el cifrado autentica también los metadatos de la entrada. La clave local y el catálogo son necesarios para la recuperación. Restringe el acceso a la carpeta y, si haces una copia de seguridad, conserva juntos la clave, el catálogo y los archivos cifrados. [Implementación de cuarentena](../../src/quarantine.rs)

## Acciones con archivos en cuarentena

### Restaurar

1. Selecciona la entrada o entradas y pulsa **Restore Selected**.
2. Revisa la cantidad de archivos y confirma.
3. Comprueba la ruta original. Amaru verifica el contenido recuperado y crea el archivo allí. Si el destino ya está ocupado, conserva el archivo existente y devuelve un error.

La restauración crea un archivo con el contenido recuperado. Los permisos, los atributos y las marcas de tiempo del archivo nuevo dependen del directorio de destino y del sistema operativo. Los filtros de vigilancia siguen vigentes. El monitor puede volver a detectar un archivo restaurado. Para un lote, cada entrada se procesa por separado. Tras un error, revisa la lista antes de reintentar las operaciones pendientes.

### Eliminar

Selecciona las entradas, pulsa **Delete Selected** y confirma la eliminación permanente. Comprueba el nombre y la ruta antes de confirmar. La acción elimina la copia que Amaru usaría para restaurar el archivo. [Pantalla de cuarentena](../../gui/src/routes/Quarantine.svelte)

### ¿Cómo gestiono un falso positivo?

Conserva el nombre de la regla, el SHA-256 y la versión del catálogo para revisar la detección. Confirma el origen y la integridad del archivo con el proveedor antes de restaurarlo. Si presentas un informe público, omite los archivos privados y los datos personales que pudiera contener la ruta. [Incidencias de Amaru](https://github.com/CripterHack/Amaru/issues)

## Configuración de la cuarentena

El archivo TOML que carga el motor admite estos valores. Si ya existe la tabla `[quarantine_config]`, edita sus claves en el mismo lugar.

```toml
[quarantine_config]
quarantine_path = "quarantine"
max_size = 1073741824
retention_days = 30
auto_quarantine = false
```

- **Ubicación.** Elige un directorio con espacio y permisos adecuados. Cambiar la ruta indica al motor que abra otro almacén. Para conservar acceso a los archivos anteriores, conserva su carpeta completa.
- **Capacidad.** El valor predeterminado es 1 GiB. El límite contabiliza los tamaños originales registrados. El sistema de archivos también necesita espacio para el cifrado, el catálogo y las escrituras temporales.
- **Retención.** La operación de limpieza del núcleo utiliza 30 días por defecto. La planificación periódica y el aviso previo de eliminación forman parte del diseño pendiente de integración.
- **Respuesta automática.** Con `auto_quarantine = false` el monitor informa de la detección. Al establecerlo en `true`, intenta aislar los hallazgos de riesgo alto o crítico cuyo contenido siga coincidiendo con el analizado. Los análisis manuales de escritorio permiten al usuario elegir los hallazgos que desea aislar. [Configuración](../../src/config.rs) · [Protección en tiempo real](./real-time-protection.md)

## Diseño y estado de las funciones

La especificación de cuarentena también contempla una vista forense detallada, restaurar en otra ruta o añadir una exclusión, volver a analizar dentro del almacén, enviar una muestra al laboratorio, comprimir archivos y programar reglas de retención por amenaza. La validación de estas funciones requiere su integración con el motor, sus controles de usuario y pruebas en Windows. Los accesos directos desde la bandeja y las notificaciones pertenecen al mismo diseño.

## Solución de problemas

| Situación | Qué hacer |
| --- | --- |
| La ruta de restauración está ocupada | Revisa el archivo actual y decide dónde conservarlo antes de reintentar. |
| El motor indica falta de espacio o de permisos | Comprueba el límite configurado, el espacio libre, el directorio original y los permisos del usuario o servicio. |
| Se informa de un fallo de autenticación, de clave o de catálogo | Conserva el almacén completo para su revisión. Sustituir la clave impide descifrar las entradas asociadas a la anterior. |
| El archivo cambió después del análisis | Repite el análisis para tomar la decisión con el contenido actual. |
| El escritorio muestra una lista vacía | Verifica qué motor aisló el archivo y qué ruta de cuarentena utilizó. |
