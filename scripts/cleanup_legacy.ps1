# Script para eliminar archivos obsoletos y mantener solo el instalador unificado
# Aplica el principio de responsabilidad única al centrarse únicamente en la limpieza

# Configuración de codificación
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Directorio principal del proyecto
$ProjectRoot = (Get-Location).Path
Write-Host "Directorio del proyecto: $ProjectRoot" -ForegroundColor Green

# Rutas de scripts obsoletos que deben ser respaldados y eliminados
$ObsoleteFiles = @(
    # Scripts NSIS duplicados
    @{
        Path = "$ProjectRoot\installer\setup.nsi"
        BackupPath = "$ProjectRoot\installer\backup\setup.nsi.bak"
        Description = "Script NSIS antiguo (setup.nsi)"
    },
    @{
        Path = "$ProjectRoot\scripts\installer.nsi"
        BackupPath = "$ProjectRoot\scripts\backup\installer.nsi.bak"
        Description = "Script NSIS alternativo (installer.nsi)"
    }
)

# Función para crear un respaldo antes de eliminar
function Backup-ObsoleteFile {
    param (
        [string]$SourcePath,
        [string]$BackupPath
    )
    
    if (-not (Test-Path $SourcePath)) {
        return $false
    }
    
    # Crear directorio de respaldo si no existe
    $BackupDir = Split-Path -Path $BackupPath -Parent
    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    }
    
    try {
        Copy-Item -Path $SourcePath -Destination $BackupPath -Force
        Write-Host "Respaldo creado: $BackupPath" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Error al crear respaldo de $SourcePath`: $_"
        return $false
    }
}

# Función para eliminar archivo obsoleto
function Remove-ObsoleteFile {
    param (
        [string]$Path,
        [string]$Description
    )
    
    if (-not (Test-Path $Path)) {
        Write-Host "Archivo no encontrado: $Description" -ForegroundColor Yellow
        return $true
    }
    
    try {
        Remove-Item -Path $Path -Force
        Write-Host "Eliminado: $Description" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Error al eliminar $Description`: $_"
        return $false
    }
}

# Función principal para limpiar archivos obsoletos
function Invoke-LegacyCleanup {
    param (
        [switch]$Force,
        [switch]$NoBackup
    )
    
    Write-Host "Iniciando limpieza de archivos obsoletos..." -ForegroundColor Yellow
    
    # Asegurarse de que existe el script unificado antes de eliminar los otros
    $UnifiedScript = "$ProjectRoot\installer\unified_installer.nsi"
    if (-not (Test-Path $UnifiedScript)) {
        Write-Error "No se encontró el script unificado en $UnifiedScript"
        Write-Error "No se pueden eliminar archivos obsoletos sin tener el script unificado."
        return $false
    }
    
    # Confirmar la operación si no se fuerza
    if (-not $Force) {
        $Response = Read-Host "Se eliminarán los scripts obsoletos. ¿Desea continuar? (S/N)"
        if ($Response -ne "S" -and $Response -ne "s") {
            Write-Host "Operación cancelada por el usuario." -ForegroundColor Yellow
            return $true
        }
    }
    
    $Success = $true
    
    # Procesar cada archivo obsoleto
    foreach ($File in $ObsoleteFiles) {
        # Crear respaldo si es necesario
        if (-not $NoBackup) {
            $BackupResult = Backup-ObsoleteFile -SourcePath $File.Path -BackupPath $File.BackupPath
            if (-not $BackupResult) {
                Write-Warning "No se pudo crear respaldo de $($File.Description), se omitirá la eliminación."
                $Success = $false
                continue
            }
        }
        
        # Eliminar el archivo
        $RemoveResult = Remove-ObsoleteFile -Path $File.Path -Description $File.Description
        if (-not $RemoveResult) {
            $Success = $false
        }
    }
    
    # Informar resultado final
    if ($Success) {
        Write-Host "Limpieza de archivos obsoletos completada con éxito." -ForegroundColor Green
    } else {
        Write-Warning "La limpieza se completó con algunos errores."
    }
    
    return $Success
}

# Usar parámetros para permitir diferentes modos de ejecución
param (
    [switch]$Force,
    [switch]$NoBackup
)

# Invocar la función principal con los parámetros proporcionados
Invoke-LegacyCleanup -Force:$Force -NoBackup:$NoBackup 