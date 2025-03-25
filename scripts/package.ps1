# Script mejorado para crear instalador Amaru Antivirus
# Versión con soporte UTF-8 mejorado y detección de iconos

# Configurar correctamente la codificación para PowerShell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Configurar UTF-8 para todo el entorno de PowerShell
$env:LC_ALL = "es-ES.UTF-8"

# Verificar que podemos escribir caracteres acentuados
Write-Host "Configuración de codificación UTF-8 completada. Probando acentos: áéíóúñ" -ForegroundColor Cyan

# Obtener la ruta absoluta del directorio actual
$ProjectRoot = (Get-Location).Path
Write-Host "Directorio del proyecto: $ProjectRoot" -ForegroundColor Green

# Crear directorios necesarios
New-Item -ItemType Directory -Force -Path "$ProjectRoot\target\release" -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Force -Path "$ProjectRoot\installer" -ErrorAction SilentlyContinue | Out-Null

# Definir rutas importantes
$InstallerDir = "$ProjectRoot\installer"
$TargetPath = "$ProjectRoot\target\release\amaru.exe"
$IconDestPath = "$ProjectRoot\installer\amaru-app.ico"
$LicensePath = "$ProjectRoot\installer\license.txt"
# Usar exclusivamente unified_installer.nsi como script principal
$InstallerScript = "$ProjectRoot\installer\unified_installer.nsi"
$OutputPath = "$ProjectRoot\installer\AmaruAV-Setup.exe"

# Verificar si existe el script unificado, y si no, crear error
if (-not (Test-Path $InstallerScript)) {
    Write-Error "No se encontró el script NSIS unificado en: $InstallerScript"
    Write-Error "Este script requiere el archivo unified_installer.nsi para funcionar."
    exit 1
}

# Verificar que los parámetros NSIS están definidos
if ($ScriptContent -match "!ifndef OUTDIR" -and 
    $ScriptContent -match "!ifndef LICENSEFILE" -and 
    $ScriptContent -match "!ifndef EXEDIR") {
    Write-Host "✓ Los parámetros NSIS están correctamente definidos" -ForegroundColor Green
} else {
    Write-Warning "⚠ El script no define correctamente los parámetros necesarios para NSIS"
}

# Buscar y preparar el icono
function Find-ApplicationIcon {
    # Buscar el icono de la aplicación en varias ubicaciones posibles
    $IconLocations = @(
        "$ProjectRoot\amaru-app.ico",
        "$ProjectRoot\amaru-app.png",
        "$ProjectRoot\amaru-isotipo-white.ico",
        "$ProjectRoot\assets\icons\amaru-app.ico",
        "$ProjectRoot\assets\amaru-app.ico",
        "$ProjectRoot\resources\amaru-app.ico",
        "$InstallerDir\amaru-app.ico"
    )

    foreach ($location in $IconLocations) {
        if (Test-Path $location) {
            $IconPath = $location
            Write-Host "Encontrado icono en: $IconPath" -ForegroundColor Green
            
            # Copiar al directorio del instalador si no está ya allí
            $IconDestPath = "$InstallerDir\amaru-app.ico"
            if ($location -ne $IconDestPath) {
                try {
                    Copy-Item -Path $location -Destination $IconDestPath -Force
                    Write-Host "Icono copiado a: $IconDestPath" -ForegroundColor Green
                    return $IconDestPath
                } catch {
                    Write-Warning "No se pudo copiar el icono: $_"
                }
            } else {
                return $IconPath
            }
        }
    }
    
    Write-Warning "No se encontró ningún icono de la aplicación. Se usará un icono predeterminado."
    return $null
}

# Buscar el ejecutable de la aplicación
function Find-ApplicationExecutable {
    $PossibleExecutables = @(
        "$ProjectRoot\target\release\amaru.exe",
        "$ProjectRoot\build\amaru.exe",
        "$ProjectRoot\dist\amaru.exe",
        "$ProjectRoot\amaru.exe"
    )
    
    foreach ($ExePath in $PossibleExecutables) {
        if (Test-Path $ExePath) {
            Write-Host "Encontrado ejecutable en: $ExePath" -ForegroundColor Green
            
            # Copiar al directorio del instalador
            try {
                Copy-Item -Path $ExePath -Destination "$InstallerDir\amaru.exe" -Force
                Write-Host "Ejecutable copiado a: $InstallerDir\amaru.exe" -ForegroundColor Green
                return "$InstallerDir\amaru.exe"
            } catch {
                Write-Warning "No se pudo copiar el ejecutable: $_"
                return $ExePath
            }
        }
    }
    
    Write-Warning "No se encontró el ejecutable de la aplicación."
    return $null
}

# Encontrar el compilador NSIS
function Find-NsisCompiler {
    $nsisCommandName = "makensis.exe"
    
    # Buscar en PATH
    $nsisPath = Get-Command $nsisCommandName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    
    if (-not $nsisPath) {
        $commonPaths = @(
            "C:\Program Files (x86)\NSIS\makensis.exe",
            "C:\Program Files\NSIS\makensis.exe",
            "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
            "$env:ProgramFiles\NSIS\makensis.exe"
        )
        
        foreach ($path in $commonPaths) {
            if (Test-Path $path) {
                $nsisPath = $path
                break
            }
        }
    }
    
    if (-not $nsisPath) {
        Write-Error "No se encontró el compilador NSIS (makensis.exe). Por favor instale NSIS desde: https://nsis.sourceforge.io/Download"
        return $null
    }
    
    Write-Host "Compilador NSIS encontrado en: $nsisPath" -ForegroundColor Green
    return $nsisPath
}

# Compilar el instalador NSIS
function Invoke-AmaruNSISInstaller {
    param (
        [string]$NsisScript = $InstallerScript,
        [string]$LicenseFile = $LicensePath,
        [string]$ExeDir = $InstallerDir,
        [string]$OutputDir = $InstallerDir,
        [version]$TargetVersion = "1.0.0"
    )
    
    # Verificar que el script NSIS existe
    if (-not (Test-Path $NsisScript)) {
        Write-Error "No se encontró el script NSIS en: $NsisScript"
        return $false
    }
    
    # Verificar que el archivo de licencia existe
    if (-not (Test-Path $LicenseFile)) {
        Write-Error "No se encontró el archivo de licencia en: $LicenseFile"
        return $false
    }
    
    # Verificar que el directorio de salida existe
    if (-not (Test-Path $OutputDir)) {
        try {
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        } catch {
            Write-Error "No se pudo crear el directorio de salida: $OutputDir"
            return $false
        }
    }
    
    # Buscar el compilador NSIS
    $nsisPath = Find-NsisCompiler
    if (-not $nsisPath) {
        return $false
    }
    
    # Construir los parámetros para NSIS
    $nsisParams = @(
        "/V4",  # Modo verboso para depuración
        "/DOUTDIR=`"$OutputDir`"",
        "/DLICENSEFILE=`"$LicenseFile`"",
        "/DEXEDIR=`"$ExeDir`"",
        "/DPRODUCT_VERSION=`"$TargetVersion`"",
        "`"$NsisScript`""
    )
    
    # Ejecutar el compilador NSIS
    Write-Host "Compilando instalador NSIS..." -ForegroundColor Yellow
    Write-Host "Comando: $nsisPath $nsisParams" -ForegroundColor Gray
    
    try {
        $process = Start-Process -FilePath $nsisPath -ArgumentList $nsisParams -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            # Verificar que se creó el instalador
            $installerPath = "$OutputDir\AmaruAV-Setup.exe"
            if (Test-Path $installerPath) {
                Write-Host "Instalador creado correctamente en: $installerPath" -ForegroundColor Green
                return $true
            } else {
                Write-Error "NSIS salió con código de éxito pero no se encontró el instalador en: $installerPath"
                return $false
            }
        } else {
            Write-Error "NSIS salió con código de error: $($process.ExitCode)"
            return $false
        }
    } catch {
        Write-Error "Error al ejecutar el compilador NSIS: $_"
        return $false
    }
}

# Buscar el icono y el ejecutable
$IconPath = Find-ApplicationIcon
$ExecutablePath = Find-ApplicationExecutable

# Verificar integración completa
Write-Host "Resumen de verificación de integración:" -ForegroundColor Yellow
Write-Host "=================================" -ForegroundColor Yellow

$Integration = @{
    "Script package.ps1 disponible" = Test-Path $PSCommandPath
    "Script unified_installer.nsi disponible" = Test-Path $InstallerScript
    "Archivo de licencia disponible" = Test-Path $LicensePath
    "Ejecutable disponible" = ($ExecutablePath -ne $null)
    "Icono disponible" = ($IconPath -ne $null)
}

foreach ($Key in $Integration.Keys) {
    if ($Integration[$Key]) {
        Write-Host "✓ $Key" -ForegroundColor Green
    } else {
        Write-Host "✗ $Key" -ForegroundColor Red
    }
}

# Preguntar si desea compilar el instalador
$BuildInstaller = Read-Host "¿Desea probar la creación del instalador? (S/N)"
if ($BuildInstaller -eq "S" -or $BuildInstaller -eq "s") {
    $Result = Invoke-AmaruNSISInstaller -NsisScript $InstallerScript -LicenseFile $LicensePath -ExeDir $InstallerDir
    if ($Result) {
        Write-Host "Instalador creado correctamente." -ForegroundColor Green
    } else {
        Write-Error "Error al crear el instalador."
    }
} else {
    Write-Host "Operación cancelada por el usuario." -ForegroundColor Yellow
}

# Función principal para exportación
function New-AmaruInstaller {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Version = "1.0.0",
        
        [Parameter(Mandatory = $false)]
        [string]$OutputDir = "$ProjectRoot\installer",
        
        [Parameter(Mandatory = $false)]
        [string]$NsisScript = "$ProjectRoot\installer\unified_installer.nsi"
    )
    
    # Verificar el script NSIS
    if (-not (Test-Path $NsisScript)) {
        Write-Error "No se encontró el script NSIS: $NsisScript"
        return $false
    }
    
    # Compilar el instalador con los parámetros proporcionados
    $Result = Invoke-AmaruNSISInstaller -NsisScript $NsisScript -LicenseFile $LicensePath -ExeDir $InstallerDir -OutputDir $OutputDir -TargetVersion $Version
    
    return $Result
}

# Exportar la función para uso en otros scripts
Export-ModuleMember -Function New-AmaruInstaller