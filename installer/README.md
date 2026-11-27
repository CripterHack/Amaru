# Instalador de desarrollo de Amaru para Windows

El instalador NSIS empaqueta el ejecutable Rust x64, la configuración del repositorio y el árbol de firmas YARA. Los binarios históricos del directorio `installer/` son anteriores a este procedimiento. La validación del servicio, del escritorio Tauri y de las dependencias nativas en Windows 11 sigue pendiente. El estado de publicación se registra en el [informe de desarrollo](../status_development.md).

## Requisitos

Se requiere un entorno Windows de desarrollo con PowerShell 5.1 o superior, Rust para `x86_64-pc-windows-msvc`, Visual Studio Build Tools, las dependencias nativas del proyecto y NSIS 3. El script busca `makensis.exe` en el PATH y en la carpeta NSIS de Program Files (x86).

## Construcción y verificación

Desde la raíz del repositorio, compila y empaqueta el ejecutable del checkout actual con este comando.

```powershell
.\scripts\build_installer.ps1 -Force
```

El script ejecuta Cargo con `--locked`, comprueba la cabecera PE x64 y compila [unified_installer.nsi](unified_installer.nsi) en un directorio temporal. Solo al concluir NSIS mueve el nuevo instalador a `target\x86_64-pc-windows-msvc\release\AmaruAV-Setup.exe`. Un fallo de compilación termina el comando con error. La ruta de salida puede seguir conteniendo el resultado de una compilación anterior.

Para verificar el empaquetado de un ejecutable previamente compilado, ejecuta ambos comandos y comprueba que cada uno termine correctamente.

```powershell
cargo build --locked --release --package amaru --bin amaru --target x86_64-pc-windows-msvc --target-dir target
.\scripts\build_installer.ps1 -VerifyOnly
```

La verificación descarta el instalador temporal. Una compilación real del proyecto y una prueba de instalación, arranque, detección y desinstalación en Windows 11 siguen siendo necesarias para validar una versión distribuible.

## Estructura

- [scripts/package.ps1](../scripts/package.ps1) implementa la compilación y la verificación utilizadas por los puntos de entrada.
- [unified_installer.nsi](unified_installer.nsi) define el empaquetado, los accesos directos, el inicio automático y la desinstalación.
- [license.txt](license.txt) y [amaru-app.ico](amaru-app.ico) son los recursos que NSIS utiliza al compilar el instalador.
