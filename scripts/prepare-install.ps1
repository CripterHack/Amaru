# Script para preparar el entorno antes de la instalación
# Asegura que todos los módulos y dependencias estén disponibles

# Configurar utf-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

# Definir las rutas
$ProjectRoot = (Get-Location).Path
$BuildDir = "$ProjectRoot\target\release"
$DistDir = "$ProjectRoot\dist"
$InstallerDir = "$ProjectRoot\installer"
$ModulesDir = "$ProjectRoot\modules"

# Crear directorios necesarios
$Dirs = @(
    "$BuildDir",
    "$DistDir",
    "$InstallerDir",
    "$DistDir\x64",
    "$DistDir\x86"
)

foreach ($Dir in $Dirs) {
    if (-not (Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        Write-Host "Creado directorio: $Dir" -ForegroundColor Green
    }
}

# Verificar que el ejecutable principal existe
if (-not (Test-Path "$BuildDir\amaru.exe")) {
    Write-Warning "No se encuentra el ejecutable principal en $BuildDir\amaru.exe"
    $BuildExe = Read-Host "¿Desea ejecutar 'cargo build --release' para compilar el proyecto? (S/N)"
    if ($BuildExe -eq "S" -or $BuildExe -eq "s") {
        Write-Host "Compilando proyecto..." -ForegroundColor Yellow
        Push-Location $ProjectRoot
        cargo build --release
        Pop-Location
    } else {
        Write-Error "El ejecutable principal es necesario para continuar. Abortando."
        exit 1
    }
}

# Verificar y copiar las DLLs y dependencias
Write-Host "Verificando dependencias de módulos..." -ForegroundColor Yellow

# Dependencias del módulo YARA
$YaraDeps = @{
    "yara-engine" = @("yara-x64.dll", "libyara.dll")
    "radare2-analyzer" = @("radare2-x64.dll", "r_core.dll")
    "realtime-monitor" = @()
}

# Buscar dependencias en ubicaciones típicas
$PossibleDllPaths = @(
    "$ProjectRoot\yara-engine\deps",
    "$ProjectRoot\deps",
    "$ProjectRoot\target\deps",
    "$ProjectRoot\yara-engine\target\release",
    "$ProjectRoot\radare2-analyzer\deps",
    "$ProjectRoot\radare2-analyzer\target\release",
    "C:\Program Files\YARA\bin",
    "C:\Program Files (x86)\YARA\bin",
    "C:\Program Files\radare2\bin",
    "C:\Program Files (x86)\radare2\bin"
)

# Comprobar y resolver dependencias
foreach ($Module in $YaraDeps.Keys) {
    foreach ($Dll in $YaraDeps[$Module]) {
        $Found = $false
        
        foreach ($Path in $PossibleDllPaths) {
            $DllPath = "$Path\$Dll"
            if (Test-Path $DllPath) {
                # Copiar a la carpeta de distribución
                Copy-Item -Path $DllPath -Destination "$DistDir\x64\$Dll" -Force
                Write-Host "Copiado $Dll para $Module desde $DllPath" -ForegroundColor Green
                $Found = $true
                break
            }
        }
        
        if (-not $Found) {
            Write-Warning "No se encuentra $Dll para el módulo $Module"
            
            # Preguntar qué hacer
            $DownloadDll = Read-Host "¿Desea descargar automáticamente las dependencias faltantes? (S/N)"
            if ($DownloadDll -eq "S" -or $DownloadDll -eq "s") {
                # Aquí se podría implementar un código para descargar automáticamente
                # las dependencias desde un repositorio o URL conocida
                Write-Host "Esta funcionalidad no está implementada en este script." -ForegroundColor Yellow
            }
        }
    }
}

# Copiar el ejecutable principal al directorio del instalador
Copy-Item -Path "$BuildDir\amaru.exe" -Destination "$InstallerDir\amaru.exe" -Force
Write-Host "Copiado ejecutable principal a $InstallerDir\amaru.exe" -ForegroundColor Green

# Copiar iconos y recursos
$IconSources = @(
    "$ProjectRoot\amaru-app.ico",
    "$ProjectRoot\amaru-app.png",
    "$ProjectRoot\amaru-isotipo-white.ico",
    "$ProjectRoot\assets\icons\amaru-app.ico"
)

$IconFound = $false
foreach ($IconSource in $IconSources) {
    if (Test-Path $IconSource) {
        Copy-Item -Path $IconSource -Destination "$InstallerDir\amaru-app.ico" -Force
        Write-Host "Copiado icono desde $IconSource" -ForegroundColor Green
        $IconFound = $true
        break
    }
}

if (-not $IconFound) {
    Write-Warning "No se encontró un icono para la aplicación"
}

# Copiar configuración de ejemplo al instalador
if (Test-Path "$ProjectRoot\config.toml") {
    Copy-Item -Path "$ProjectRoot\config.toml" -Destination "$InstallerDir\config.toml" -Force
    Write-Host "Copiada configuración de ejemplo" -ForegroundColor Green
}

# Copiar reglas YARA al instalador
$YaraRulesDir = "$ProjectRoot\signatures"
if (Test-Path $YaraRulesDir) {
    if (-not (Test-Path "$InstallerDir\signatures")) {
        New-Item -ItemType Directory -Path "$InstallerDir\signatures" -Force | Out-Null
    }
    
    # Copiar reglas YARA
    Get-ChildItem -Path "$YaraRulesDir\*.yar" -Recurse | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination "$InstallerDir\signatures\$($_.Name)" -Force
        Write-Host "Copiada regla YARA: $($_.Name)" -ForegroundColor Green
    }
}

# Copiar licencia
$LicenseFile = "$ProjectRoot\LICENSE"
if (Test-Path $LicenseFile) {
    Copy-Item -Path $LicenseFile -Destination "$InstallerDir\license.txt" -Force
    Write-Host "Copiada licencia" -ForegroundColor Green
}

# Verificar que NSIS está instalado
$NsisPath = "C:\Program Files (x86)\NSIS\makensis.exe"
if (-not (Test-Path $NsisPath)) {
    $NsisPath = "C:\Program Files\NSIS\makensis.exe"
    if (-not (Test-Path $NsisPath)) {
        Write-Warning "No se encuentra NSIS instalado. Es necesario para compilar el instalador."
        $InstallNsis = Read-Host "¿Desea abrir el navegador para descargar NSIS? (S/N)"
        if ($InstallNsis -eq "S" -or $InstallNsis -eq "s") {
            Start-Process "https://nsis.sourceforge.io/Download"
        }
    }
}

# Compilar el instalador
$CompileInstaller = Read-Host "¿Desea compilar el instalador ahora? (S/N)"
if ($CompileInstaller -eq "S" -or $CompileInstaller -eq "s") {
    Write-Host "Compilando instalador..." -ForegroundColor Yellow
    
    # Variables para NSIS
    $NsisVars = @(
        "/DOUTDIR=$InstallerDir",
        "/DEXEDIR=$InstallerDir",
        "/DLICENSEFILE=$InstallerDir\license.txt"
    )
    
    # Ejecutar NSIS
    if (Test-Path $NsisPath) {
        & $NsisPath $NsisVars "$ProjectRoot\scripts\installer.nsi"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Instalador creado con éxito en $InstallerDir\AmaruAV-Setup.exe" -ForegroundColor Green
        } else {
            Write-Error "Error al compilar el instalador. Código de salida: $LASTEXITCODE"
        }
    } else {
        Write-Error "No se puede compilar el instalador porque no se encuentra NSIS."
    }
}

Write-Host "Preparación completada." -ForegroundColor Green 