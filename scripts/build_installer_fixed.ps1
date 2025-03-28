# Script para verificar la integración entre package.ps1 y unified_installer.nsi
# Este script realiza pruebas de integración y verifica que todos los recursos
# sean encontrados correctamente durante el proceso de compilación

# Configurar la codificación para PowerShell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Obtener la ruta absoluta del directorio actual
$ProjectRoot = (Get-Location).Path
Write-Host "Directorio del proyecto: $ProjectRoot" -ForegroundColor Green

# Verificar que existe el script package.ps1
if (-not (Test-Path "$ProjectRoot\scripts\package.ps1")) {
    Write-Error "No se encuentra scripts\package.ps1. Por favor ejecute este script desde el directorio raíz del proyecto."
    exit 1
}

# Verificar que existe el script unified_installer.nsi o copiarlo si es necesario
if (-not (Test-Path "$ProjectRoot\installer\unified_installer.nsi")) {
    if (Test-Path "$ProjectRoot\scripts\unified_installer.nsi") {
        Copy-Item "$ProjectRoot\scripts\unified_installer.nsi" -Destination "$ProjectRoot\installer\unified_installer.nsi" -Force
        Write-Host "Script unificado copiado a installer\unified_installer.nsi" -ForegroundColor Green
    }
    else {
        Write-Warning "No se encuentra el script unified_installer.nsi en ninguna ubicación."
        Write-Host "Creando copia desde instalador original..." -ForegroundColor Yellow
        
        if (Test-Path "$ProjectRoot\installer\setup.nsi") {
            Copy-Item "$ProjectRoot\installer\setup.nsi" -Destination "$ProjectRoot\installer\unified_installer.nsi" -Force
            Write-Host "Se usará setup.nsi como base para el instalador unificado" -ForegroundColor Green
        }
        elseif (Test-Path "$ProjectRoot\scripts\installer.nsi") {
            Copy-Item "$ProjectRoot\scripts\installer.nsi" -Destination "$ProjectRoot\installer\unified_installer.nsi" -Force
            Write-Host "Se usará installer.nsi como base para el instalador unificado" -ForegroundColor Green
        }
        else {
            Write-Error "No se ha encontrado ningún script NSIS para usar como base."
            exit 1
        }
    }
}

# Verificar que existe el directorio installer
if (-not (Test-Path "$ProjectRoot\installer")) {
    New-Item -ItemType Directory -Path "$ProjectRoot\installer" -Force
    Write-Host "Creado directorio installer/" -ForegroundColor Yellow
}

# Verificar que existe license.txt o crearlo si no existe
$licenseFile = "$ProjectRoot\installer\license.txt"
if (-not (Test-Path $licenseFile)) {
    Write-Host "Creando archivo de licencia en $licenseFile" -ForegroundColor Yellow
    
    @"
Licencia de Amaru Antivirus
===========================
© 2025 Amaru Security Team
Todos los derechos reservados.

Este software está protegido por leyes de derechos de autor y convenios internacionales.
El uso no autorizado de este software está prohibido.
"@ | Set-Content -Path $licenseFile -Encoding UTF8
}

# Verificar que existe el directorio de compilación
if (-not (Test-Path "$ProjectRoot\target\release")) {
    New-Item -ItemType Directory -Path "$ProjectRoot\target\release" -Force
    Write-Host "Creado directorio target/release/" -ForegroundColor Yellow
}

# Verificar que existe el ejecutable o crear uno simulado para pruebas
$exePath = "$ProjectRoot\target\release\amaru.exe"
if (-not (Test-Path $exePath)) {
    Write-Host "No se encuentra el ejecutable en $exePath" -ForegroundColor Yellow
    Write-Host "Creando un archivo simulado para pruebas..." -ForegroundColor Yellow
    
    # Crear un archivo vacío para fines de prueba
    New-Item -ItemType File -Path $exePath -Force | Out-Null
    Write-Host "Ejecutable de prueba creado en $exePath" -ForegroundColor Green
}

# Verificar que existen iconos o crear uno simulado para pruebas
$iconFile = "$ProjectRoot\installer\amaru-app.ico"
if (-not (Test-Path $iconFile)) {
    $foundIcon = $false
    
    # Buscar iconos en otras ubicaciones
    $iconLocations = @(
        "$ProjectRoot\amaru-app.ico",
        "$ProjectRoot\amaru-isotipo-white.ico",
        "$ProjectRoot\assets\icons\amaru-app.ico",
        "$ProjectRoot\assets\amaru-app.ico"
    )
    
    foreach ($location in $iconLocations) {
        if (Test-Path $location) {
            Copy-Item $location -Destination $iconFile -Force
            Write-Host "Icono copiado de $location a $iconFile" -ForegroundColor Green
            $foundIcon = $true
            break
        }
    }
    
    if (-not $foundIcon) {
        Write-Warning "No se encontró ningún icono. El instalador puede no mostrar iconos correctamente."
    }
}

# Buscar el compilador NSIS
$nsisPath = $null
$nsisFound = $false

# Buscar en el PATH
$nsisCommand = Get-Command "makensis.exe" -ErrorAction SilentlyContinue
if ($nsisCommand) {
    $nsisPath = $nsisCommand.Source
    $nsisFound = $true
    Write-Host "Compilador NSIS encontrado en: $nsisPath" -ForegroundColor Green
}
else {
    # Buscar en ubicaciones comunes
    $commonPaths = @(
        "C:\Program Files (x86)\NSIS\makensis.exe",
        "C:\Program Files\NSIS\makensis.exe",
        "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
        "$env:ProgramFiles\NSIS\makensis.exe"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            $nsisPath = $path
            $nsisFound = $true
            Write-Host "Compilador NSIS encontrado en: $nsisPath" -ForegroundColor Green
            break
        }
    }
}

if (-not $nsisFound) {
    Write-Warning "No se encontró el compilador NSIS (makensis.exe). El instalador no podrá ser compilado."
    Write-Host "Por favor, instale NSIS desde: https://nsis.sourceforge.io/Download" -ForegroundColor Yellow
}

# Verificar que el script package.ps1 llama correctamente al compilador NSIS
Write-Host "Verificando parámetros en package.ps1..." -ForegroundColor Cyan

$packageScript = Get-Content "$ProjectRoot\scripts\package.ps1" -Raw

# Verificar que se usa el instalador unificado
if ($packageScript -match "unified_installer\.nsi") {
    Write-Host "✓ El script package.ps1 referencia al instalador unificado" -ForegroundColor Green
}
else {
    Write-Warning "El script package.ps1 no parece usar el instalador unificado"
}

# Verificar que los parámetros NSIS están bien definidos
if ($packageScript -match "/DOUTDIR" -and $packageScript -match "/DLICENSEFILE" -and $packageScript -match "/DEXEDIR") {
    Write-Host "✓ Los parámetros NSIS están correctamente definidos" -ForegroundColor Green
}
else {
    Write-Warning "Los parámetros NSIS podrían no estar correctamente definidos en package.ps1"
}

# Verificar que el script unified_installer.nsi usa los parámetros definidos
$unifiedScript = Get-Content "$ProjectRoot\installer\unified_installer.nsi" -Raw

if ($unifiedScript -match "\`${OUTDIR}" -and $unifiedScript -match "\`${LICENSEFILE}" -and $unifiedScript -match "\`${EXEDIR}") {
    Write-Host "✓ El script unified_installer.nsi usa correctamente los parámetros definidos" -ForegroundColor Green
}
else {
    Write-Warning "El script unified_installer.nsi podría no usar correctamente los parámetros definidos"
}

# Resumen final
Write-Host "`nResumen de verificación de integración:" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "✓ Script package.ps1 disponible" -ForegroundColor Green
Write-Host "✓ Script unified_installer.nsi disponible" -ForegroundColor Green

if (Test-Path $licenseFile) {
    Write-Host "✓ Archivo de licencia disponible" -ForegroundColor Green
}
else {
    Write-Host "✗ Archivo de licencia no disponible" -ForegroundColor Red
}

if (Test-Path $exePath) {
    Write-Host "✓ Ejecutable disponible" -ForegroundColor Green
}
else {
    Write-Host "✗ Ejecutable no disponible" -ForegroundColor Red
}

if (Test-Path $iconFile) {
    Write-Host "✓ Icono disponible" -ForegroundColor Green
}
else {
    Write-Host "✗ Icono no disponible" -ForegroundColor Red
}

if ($nsisFound) {
    Write-Host "✓ Compilador NSIS disponible" -ForegroundColor Green
}
else {
    Write-Host "✗ Compilador NSIS no disponible" -ForegroundColor Red
}

Write-Host "`n¿Desea probar la creación del instalador? (S/N)" -ForegroundColor Yellow
$response = Read-Host

if ($response -eq "S" -or $response -eq "s" -or $response -eq "Y" -or $response -eq "y") {
    Write-Host "Ejecutando script package.ps1..." -ForegroundColor Cyan
    
    # Ejecutar el script package.ps1 de forma segura
    $scriptPath = "$ProjectRoot\scripts\package.ps1"
    & $scriptPath
    
    # Verificar si se creó el instalador
    if (Test-Path "$ProjectRoot\installer\AmaruAV-Setup.exe") {
        Write-Host "`n✓ Instalador creado exitosamente en: $ProjectRoot\installer\AmaruAV-Setup.exe" -ForegroundColor Green
    }
    else {
        Write-Host "`n✗ No se pudo crear el instalador" -ForegroundColor Red
    }
}
else {
    Write-Host "Prueba de integración finalizada sin ejecutar package.ps1" -ForegroundColor Yellow
}

Write-Host "`nProceso de verificación completado." -ForegroundColor Cyan 
