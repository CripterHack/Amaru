# Instalador de desarrollo de Amaru para Windows x64

El paquete incluye la interfaz Tauri/Svelte en `amaru-antivirus.exe`, el núcleo y la CLI en `amaru.exe`, la configuración y las reglas YARA oficiales y personalizadas. La versión del paquete y las pruebas de Windows disponibles se registran en el [informe de desarrollo](../status_development.md).

## Construcción

En Windows x64 se requieren el toolchain Rust MSVC del proyecto, Visual Studio Build Tools, las dependencias nativas, Node.js y npm, y NSIS 3. El servidor de compilación necesita acceso a las dependencias fijadas en los lockfiles. El equipo de destino requiere Microsoft Edge WebView2 Evergreen Runtime. El instalador comprueba el registro de WebView2 y devuelve el código 2 si falta. [Distribución oficial del runtime](https://learn.microsoft.com/microsoft-edge/webview2/concepts/distribution)

Ejecuta este comando desde la raíz del repositorio.

```powershell
.\scripts\build_installer.ps1 -Force
```

El script instala las dependencias del frontend con `npm ci`, compila sus recursos y ejecuta Cargo con `--locked` para ambos binarios. Tauri usa `custom-protocol` para servir los recursos de la propia aplicación. Antes de ejecutar NSIS se comprueban las cabeceras PE x64 de ambos archivos. El instalador generado se mueve a `target\x86_64-pc-windows-msvc\release\AmaruAV-Setup.exe` tras una compilación correcta. [Script de construcción](../scripts/package.ps1) · [Receta NSIS](unified_installer.nsi)

Con ambos ejecutables ya compilados en ese directorio, este comando construye un instalador temporal y lo descarta al acabar.

```powershell
.\scripts\build_installer.ps1 -VerifyOnly
```

## Instalación y actualización

Los accesos directos del escritorio y del menú Inicio abren la GUI. En una ubicación protegida de Program Files, el instalador registra el servicio `AmaruAntivirus` con inicio automático y espera a que arranque. SCM controla el inicio de la protección. El instalador elimina las entradas de autoarranque heredadas de la aplicación en las vistas de registro del equipo y del usuario que ejecuta la instalación.

La ubicación personalizada se puede seleccionar en el asistente o con `/D`, como último argumento de una instalación silenciosa. Fuera de una carpeta protegida de Program Files se instalan la GUI, la CLI y sus recursos. Para registrar el servicio se verifican las ACL del destino y de sus ancestros, los archivos existentes y los puntos de reanálisis. Si ya existe un servicio registrado desde otra instalación, el instalador se detiene. [Comprobación de la ubicación](protected-directory.ps1) · [Control del servicio](service-control.ps1)

Para actualizar, cierra el escritorio y selecciona la misma carpeta. El instalador consulta las vistas de registro de 32 y 64 bits y comprueba que ambas identifiquen una sola instalación. Detiene el servicio antes de sustituir los binarios. Si estaba en ejecución, lo vuelve a arrancar. Si estaba detenido, conserva ese estado. Actualiza las firmas oficiales y conserva `config.toml`, `.env`, los registros, la cuarentena y las reglas personalizadas.

La desinstalación detiene y elimina el servicio de esa ubicación, sus accesos directos y las tareas de análisis rápido cuya acción y ejecutable corresponden a esa copia de Amaru. El modo silencioso conserva los datos del usuario. El asistente interactivo ofrece una opción explícita para borrar la configuración y los datos de la instalación. Los datos del escritorio se guardan en el perfil del usuario.

## Prueba de la instalación

En un runner Windows x64 desechable, con permisos de administrador, WebView2 instalado y sin una instalación previa de Amaru, ejecuta la prueba de instalación.

```powershell
.\scripts\test-installed.ps1
```

La prueba usa una carpeta propia de Program Files. Verifica los accesos directos, abre una ventana Tauri, ejecuta el autocontrol EICAR, comprueba el análisis rápido y su historial, y consulta el estado del servicio con la CLI y el SCM. El canal IPC de solo lectura debe confirmar que el monitor está activo. La prueba registra y recupera análisis diarios y semanales con permisos limitados, comprueba la hora y el día y elimina la programación mediante el script que usa la GUI. También configura un destino desde la CLI, comprueba su ruta, desactiva la tarea y verifica que las preferencias de rutas rápidas del escritorio conserven el mismo SHA-256. Aplica dos actualizaciones con el servicio detenido y en ejecución. Finalmente desinstala y comprueba que se conserva el contenido de prueba y se retiran la tarea programada, los ejecutables instalados, el catálogo oficial y la carpeta de accesos directos. [Prueba de instalación](../scripts/test-installed.ps1)

El uso de Radare2 desde el servicio requiere que `r2.exe` resida en una carpeta protegida de Program Files. Si esa condición falla, el servicio continúa con YARA y heurística. En la GUI y la CLI interactivas se conserva el descubrimiento de Radare2 según la configuración del usuario. El paquete de desarrollo no incorpora los ejecutables opcionales de Radare2 o ClamAV ni sus bases externas. La publicación de una release firmada y las pruebas de eficacia del antivirus se siguen por separado en el [estado del proyecto](../status_development.md).
