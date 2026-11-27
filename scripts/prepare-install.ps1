# Script para preparar el entorno antes de la instalación
# Asegura que todos los módulos y dependencias estén disponibles

# Configurar utf-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'

# Definir las rutas
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$DistDir = "$ProjectRoot\dist"

# Crear directorios necesarios
$Dirs = @(
    "$DistDir",
    "$DistDir\x64",
    "$DistDir\x86"
)

foreach ($Dir in $Dirs) {
    if (-not (Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        Write-Host "Creado directorio: $Dir" -ForegroundColor Green
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

$CompileInstaller = Read-Host "¿Desea compilar el instalador ahora? (S/N)"
if ($CompileInstaller -in @('s', 'y')) {
    & (Join-Path $PSScriptRoot 'package.ps1')
}

Write-Host "Preparación completada." -ForegroundColor Green
