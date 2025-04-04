# Script para verificar y construir el instalador Amaru Antivirus
# Implementa el principio de responsabilidad única, donde cada función tiene un propósito específico

# Configuración de codificación
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

# Directorio principal del proyecto
$ProjectRoot = (Get-Location).Path
Write-Host "Directorio del proyecto: $ProjectRoot" -ForegroundColor Green

# Rutas críticas para el instalador
$InstallerDir = "$ProjectRoot\installer"
$UnifiedScript = "$InstallerDir\unified_installer.nsi"
$LicenseFile = "$InstallerDir\license.txt"
$IconFile = "$InstallerDir\amaru-app.ico"

# Función para verificar si una herramienta está disponible
function Test-CommandAvailable {
    param (
        [string]$Command
    )
    
    try {
        $null = Get-Command $Command -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Función para buscar el compilador NSIS
function Find-NsisCompiler {
    $NsisPath = $null
    
    # Verificar si makensis.exe está en el PATH
    if (Test-CommandAvailable "makensis") {
        $NsisPath = (Get-Command "makensis").Source
        Write-Host "Compilador NSIS encontrado en PATH: $NsisPath" -ForegroundColor Green
        return $NsisPath
    }
    
    # Buscar en ubicaciones comunes
    $CommonPaths = @(
        "C:\Program Files (x86)\NSIS\makensis.exe",
        "C:\Program Files\NSIS\makensis.exe",
        "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
        "$env:ProgramFiles\NSIS\makensis.exe"
    )
    
    foreach ($Path in $CommonPaths) {
        if (Test-Path $Path) {
            Write-Host "Compilador NSIS encontrado en: $Path" -ForegroundColor Green
            return $Path
        }
    }
    
    Write-Error "No se pudo encontrar el compilador NSIS (makensis.exe). Por favor, instálelo desde https://nsis.sourceforge.io/Download"
    return $null
}

# Función para verificar la sintaxis del script NSIS
function Test-NsisSyntax {
    param (
        [string]$ScriptPath,
        [string]$NsisPath
    )
    
    if (-not (Test-Path $ScriptPath)) {
        Write-Error "El script NSIS no existe: $ScriptPath"
        return $false
    }
    
    try {
        $Process = Start-Process -FilePath $NsisPath -ArgumentList "/CMDHELP" -NoNewWindow -Wait -PassThru
        if ($Process.ExitCode -ne 0) {
            Write-Error "Error al ejecutar el compilador NSIS."
            return $false
        }
        
        # Verificar la sintaxis sin compilar
        $Process = Start-Process -FilePath $NsisPath -ArgumentList "/P /V1 `"$ScriptPath`"" -NoNewWindow -Wait -PassThru
        
        if ($Process.ExitCode -eq 0) {
            Write-Host "La sintaxis del script NSIS es correcta." -ForegroundColor Green
            return $true
        } else {
            Write-Error "El script NSIS contiene errores de sintaxis."
            return $false
        }
    } catch {
        Write-Error "Error al verificar la sintaxis del script NSIS: $_"
        return $false
    }
}

# Función para verificar archivos críticos
function Test-InstallerComponents {
    $Components = @{
        "Script NSIS" = Test-Path $UnifiedScript
        "Archivo de licencia" = Test-Path $LicenseFile
        "Icono de la aplicación" = Test-Path $IconFile
    }
    
    $AllValid = $true
    
    Write-Host "Verificando componentes del instalador:" -ForegroundColor Yellow
    foreach ($Component in $Components.Keys) {
        if ($Components[$Component]) {
            Write-Host "✓ $Component disponible" -ForegroundColor Green
        } else {
            Write-Host "✗ $Component no encontrado" -ForegroundColor Red
            $AllValid = $false
        }
    }
    
    return $AllValid
}

# Función principal para verificar y construir el instalador
function Invoke-InstallerBuild {
    param (
        [switch]$VerifyOnly,
        [switch]$Force
    )
    
    # Paso 1: Verificar que el compilador NSIS está disponible
    $NsisPath = Find-NsisCompiler
    if (-not $NsisPath) {
        return $false
    }
    
    # Paso 2: Verificar que todos los componentes necesarios existen
    if (-not (Test-InstallerComponents)) {
        Write-Error "Faltan componentes necesarios para construir el instalador."
        return $false
    }
    
    # Paso 3: Verificar la sintaxis del script NSIS
    if (-not (Test-NsisSyntax -ScriptPath $UnifiedScript -NsisPath $NsisPath)) {
        return $false
    }
    
    # Si solo se solicita verificación, terminar aquí
    if ($VerifyOnly) {
        Write-Host "Verificación completada con éxito." -ForegroundColor Green
        return $true
    }
    
    # Paso 4: Preguntar si se desea construir el instalador (a menos que se fuerce)
    if (-not $Force) {
        $Response = Read-Host "¿Desea construir el instalador? (S/N)"
        if ($Response -ne "S" -and $Response -ne "s") {
            Write-Host "Operación cancelada por el usuario." -ForegroundColor Yellow
            return $true
        }
    }
    
    # Paso 5: Construir el instalador
    Write-Host "Construyendo el instalador..." -ForegroundColor Yellow
    
    try {
        $Process = Start-Process -FilePath $NsisPath -ArgumentList "/V2 `"$UnifiedScript`"" -NoNewWindow -Wait -PassThru
        
        if ($Process.ExitCode -eq 0) {
            $InstallerPath = "$InstallerDir\AmaruAV-Setup.exe"
            if (Test-Path $InstallerPath) {
                Write-Host "Instalador creado exitosamente en: $InstallerPath" -ForegroundColor Green
                return $true
            } else {
                Write-Error "El compilador NSIS terminó correctamente, pero no se encontró el instalador."
                return $false
            }
        } else {
            Write-Error "Error al compilar el instalador. Código de salida: $($Process.ExitCode)"
            return $false
        }
    } catch {
        Write-Error "Error durante la construcción del instalador: $_"
        return $false
    }
}

# Ejecución principal
# Verificar parámetros en package.ps1...
Write-Host "Verificando parámetros en package.ps1..." -ForegroundColor Yellow

# Usar parámetros para permitir diferentes modos de ejecución
param (
    [switch]$VerifyOnly,
    [switch]$Force
)

# Invocar la función principal con los parámetros proporcionados
Invoke-InstallerBuild -VerifyOnly:$VerifyOnly -Force:$Force 
