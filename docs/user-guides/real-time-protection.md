# Protección en tiempo real

El servicio de Windows de Amaru vigila cambios del sistema de archivos en las rutas configuradas. Cuando recibe la creación o modificación de un archivo, o un cambio de nombre hacia una ruta admitida, lo pone en la cola de análisis. La aplicación de escritorio consulta al servicio para mostrar su estado.

## Cómo funciona

1. El monitor registra las rutas de `monitored_paths`. En los directorios, la vigilancia incluye sus subdirectorios.
2. El monitor agrupa eventos cercanos y aplica los filtros de extensión y ruta. Para un archivo renombrado, evalúa el destino.
3. El motor analiza los bytes con el catálogo YARA configurado. Con la heurística activa, examina indicadores estáticos y, en archivos PE compatibles, importaciones, secciones y recursos. El análisis con Radare2 depende de la disponibilidad de esa herramienta.
4. Un hallazgo genera un evento de detección. Con la política predeterminada el archivo permanece en su ruta. La configuración permite además intentar la cuarentena automática para riesgo alto o crítico, tras verificar que el contenido sigue coincidiendo con la evidencia.

La vigilancia se ejecuta de forma asíncrona después del evento de archivo. El estado activo indica que el monitor está en marcha. Una comprobación de acceso previa a la ejecución requeriría otro mecanismo. [Monitor de archivos](../../realtime-monitor/src/lib.rs) · [Motor y respuesta a eventos](../../src/lib.rs)

## Estado y controles

En el panel de escritorio, **Real-time Protection** consulta el estado del servicio. Usa ese interruptor para habilitar o deshabilitar la vigilancia. Si la interfaz informa de que el servicio está inaccesible, comprueba la instalación y sus permisos antes de interpretar el estado. Los cambios de control requieren permisos sobre el servicio de Windows.

En una consola de Windows, abre la carpeta de instalación de Amaru y consulta el estado del servicio con este comando.

```powershell
.\amaru.exe service --action status
```

En esta versión, `monitor --action start`, `stop` y `status` también administran o consultan el servicio de Windows completo. Para cambiar únicamente la vigilancia durante la ejecución, utiliza el control de escritorio. [Comandos de la aplicación](../../src/main.rs) · [Panel de escritorio](../../gui/src/routes/Dashboard.svelte)

## Configuración

Edita el archivo TOML utilizado por la instancia del servicio. Los valores de nivel superior se escriben antes de la primera tabla. Si una tabla ya existe, modifica sus campos. Este ejemplo vigila una carpeta de prueba existente y deja las decisiones de aislamiento al usuario.

```toml
realtime_protection = true
monitored_paths = ['C:\Amaru-Pruebas']
heuristic_analysis = true

[scan_config]
scan_extensions = ["exe", "dll", "ps1", "txt"]
exclude_paths = ['C:\Amaru-Pruebas\Resultados']
max_file_size = 104857600

[quarantine_config]
auto_quarantine = false
```

- **Rutas vigiladas.** Usa rutas absolutas y accesibles para la cuenta del servicio. Un dispositivo externo puede vigilarse mediante una ruta configurada y disponible al iniciar el monitor.
- **Extensiones.** Se escriben sin el punto y se comparan sin distinguir mayúsculas. Una lista vacía admite cualquier extensión. El ejemplo incluye `txt` para poder comprobar la vigilancia con un archivo de texto de prueba.
- **Exclusiones.** Son rutas de archivos o directorios. Una exclusión de directorio incluye sus descendientes. El motor también excluye sus carpetas de reglas y cuarentena.
- **Tamaño.** El límite predeterminado es 100 MiB. Un error de lectura o de tamaño deja el análisis incompleto.
- **Aplicación.** Para que el servicio cargue un TOML modificado, reinícialo con los permisos correspondientes. El interruptor de escritorio controla el monitor de la instancia en ejecución. [Valores predeterminados](../../src/config.rs) · [Cuarentena](./quarantine.md)

## Verificación y solución de problemas

El siguiente comando comprueba la firma instalada con la prueba benigna EICAR y un control limpio.

```powershell
.\amaru.exe test-eicar
```

La prueba anterior verifica el catálogo en memoria. Para comprobar también el monitor, utiliza una carpeta de prueba vigilada, mantén la cuarentena automática desactivada y crea en ella el archivo de prueba oficial con una extensión admitida. Comprueba el evento de detección y el estado del archivo. Otros productos de seguridad del equipo también pueden detectar la muestra. [Archivo oficial de prueba EICAR](https://www.eicar.org/download-anti-malware-testfile/) · [Pruebas del monitor integrado](../../src/core_services.rs)

| Síntoma | Comprobación |
| --- | --- |
| El servicio arranca pero la ruta esperada no se vigila | Revisa las rutas configuradas, sus permisos y los mensajes de registro de cada ruta. |
| No aparece una detección | Comprueba el catálogo con `test-eicar`, la extensión, el tamaño y las exclusiones. Un archivo existente puede analizarse manualmente. |
| El registro indica que la cola está llena | Identifica las rutas comunicadas y vuelve a analizarlas manualmente. Revisa qué carpetas generan el volumen de cambios. |
| Se detectó un archivo y sigue presente | Comprueba la política `auto_quarantine`, el nivel de riesgo y los errores de cuarentena. |
| Un archivo legítimo genera alertas | Verifica su procedencia, el hash y la regla coincidente antes de modificar las exclusiones. |

## Componentes y modos previstos

El diseño general contempla protección web y de correo, observación de procesos y registro, prevención de vulnerabilidades y protección de carpetas frente al ransomware. También describe perfiles de juego y máxima seguridad, filtrado por proceso o dirección web, avisos por correo y pausas temporizadas. Estos componentes necesitan su propia implementación, integración y validación en Windows. El control de escritorio habilitado corresponde al monitor de archivos. [Descripción general del proyecto](../../README.md)
