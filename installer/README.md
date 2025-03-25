# Instalador Amaru Antivirus

Este directorio contiene todos los archivos necesarios para generar el instalador de Amaru Antivirus para Windows.

## Estructura de archivos

- `unified_installer.nsi`: Script NSIS principal que define la estructura del instalador
- `amaru-app.ico`: Icono de la aplicación usado en el instalador
- `license.txt`: Archivo de licencia mostrado durante la instalación
- `AmaruAV-Setup.exe`: Instalador generado (después de la compilación)

## Requisitos previos

Para compilar el instalador, necesitarás:

1. [NSIS (Nullsoft Scriptable Install System)](https://nsis.sourceforge.io/Download) versión 3.0 o superior
2. El archivo ejecutable de Amaru Antivirus (`amaru.exe`)
3. PowerShell 5.1 o superior

## Cómo compilar el instalador

Existen varias formas de compilar el instalador:

### Método 1: Usando el script de verificación y compilación

```powershell
# Desde el directorio raíz del proyecto
.\scripts\build_installer.ps1
```

Este script:
- Verifica que todos los componentes necesarios estén disponibles
- Comprueba la sintaxis del script NSIS
- Genera el instalador si todas las verificaciones son correctas

### Método 2: Usando NSIS directamente

```powershell
# Desde el directorio raíz del proyecto
& "C:\Program Files (x86)\NSIS\makensis.exe" /V4 /DOUTDIR=".\installer" /DLICENSEFILE=".\installer\license.txt" /DEXEDIR=".\installer" ".\installer\unified_installer.nsi"
```

## Parámetros configurables

El script `unified_installer.nsi` acepta los siguientes parámetros:

- `OUTDIR`: Directorio de salida para el instalador
- `LICENSEFILE`: Ruta al archivo de licencia
- `EXEDIR`: Directorio donde se encuentra el ejecutable

## Mantenimiento

Para mantener el instalador:

1. Todas las actualizaciones deben hacerse en `unified_installer.nsi`
2. Los scripts obsoletos se han eliminado o respaldado usando `.\scripts\cleanup_legacy.ps1`
3. La configuración de versión se establece mediante el parámetro `PRODUCT_VERSION` en el script principal

## Solución de problemas

Si encuentras problemas al compilar el instalador:

1. Verifica que NSIS esté correctamente instalado
2. Asegúrate de que todos los archivos necesarios estén presentes
3. Ejecuta el script de verificación: `.\scripts\build_installer.ps1 -VerifyOnly`

## Estructura del instalador generado

El instalador creado:

1. Detecta instalaciones previas y ofrece desinstalarlas
2. Instala Amaru Antivirus en Program Files (x64 o x86 según arquitectura)
3. Crea atajos en el menú inicio y escritorio
4. Registra la aplicación para inicio automático
5. Proporciona un desinstalador completo

## Mejores prácticas

- Mantén un único script NSIS principal (`unified_installer.nsi`)
- Utiliza el script de compilación para verificar la integridad
- Actualiza la versión en el script principal antes de compilar

El instalador creado:

1. Detecta instalaciones previas y ofrece desinstalarlas
2. Instala Amaru Antivirus en Program Files (x64 o x86 según arquitectura)
3. Crea atajos en el menú inicio y escritorio
4. Registra la aplicación para inicio automático
5. Proporciona un desinstalador completo

## Mejores prácticas

- Mantén un único script NSIS principal (`unified_installer.nsi`)
- Utiliza el script de compilación para verificar la integridad
- Actualiza la versión en el script principal antes de compilar 