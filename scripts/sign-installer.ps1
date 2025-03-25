# Script para firmar digitalmente el instalador de Amaru Antivirus
# Este script requiere un certificado digital válido y la herramienta signtool de Windows SDK

param (
    [Parameter(Mandatory=$true)]
    [string]$InstallerPath,
    
    [Parameter(Mandatory=$false)]
    [string]$CertificatePath = "certificates\amaru-cert.pfx",
    
    [Parameter(Mandatory=$false)]
    [string]$CertificatePassword = $null,
    
    [Parameter(Mandatory=$false)]
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

# Definir colores para la salida
$colorSuccess = "Green"
$colorError = "Red"
$colorInfo = "Cyan"
$colorWarning = "Yellow"

# Mostrar banner
Write-Host "====================================================" -ForegroundColor $colorInfo
Write-Host "      FIRMA DIGITAL DEL INSTALADOR AMARU" -ForegroundColor $colorInfo
Write-Host "====================================================" -ForegroundColor $colorInfo
Write-Host ""

# Verificar que el instalador existe
if (-not (Test-Path $InstallerPath)) {
    Write-Host "ERROR: No se encontró el instalador en la ruta especificada: $InstallerPath" -ForegroundColor $colorError
    exit 1
}

# Verificar que el certificado existe
if (-not (Test-Path $CertificatePath)) {
    Write-Host "ERROR: No se encontró el certificado en la ruta especificada: $CertificatePath" -ForegroundColor $colorError
    exit 1
}

# Verificar la existencia de signtool.exe
$signtool = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
if ($null -eq $signtool) {
    # Buscar signtool en ubicaciones comunes
    $potentialPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0*\x64\signtool.exe",
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\x64\signtool.exe",
        "${env:ProgramFiles(x86)}\Microsoft SDKs\Windows\v*\bin\x64\signtool.exe"
    )
    
    $signtoolPath = $null
    foreach ($path in $potentialPaths) {
        $matches = Resolve-Path $path -ErrorAction SilentlyContinue
        if ($matches) {
            $signtoolPath = $matches[-1].Path
            break
        }
    }
    
    if ($null -eq $signtoolPath) {
        Write-Host "ERROR: No se encontró signtool.exe. Asegúrese de que Windows SDK está instalado." -ForegroundColor $colorError
        Write-Host "Puede descargarlo desde: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/" -ForegroundColor $colorInfo
        exit 1
    }
} else {
    $signtoolPath = $signtool.Source
}

Write-Host "Usando signtool desde: $signtoolPath" -ForegroundColor $colorInfo
Write-Host "Firmando instalador: $InstallerPath" -ForegroundColor $colorInfo
Write-Host "Con certificado: $CertificatePath" -ForegroundColor $colorInfo
Write-Host "Usando servidor de timestamping: $TimestampServer" -ForegroundColor $colorInfo
Write-Host ""

# Preparar comando de firma
$signCommand = @(
    "sign",
    "/f", "`"$CertificatePath`"",
    "/tr", "`"$TimestampServer`"",
    "/td", "sha256",
    "/fd", "sha256",
    "/d", "`"Amaru Antivirus Installer`"",
    "/du", "`"https://amaruantivirus.org`""
)

# Agregar contraseña si se proporcionó
if ($CertificatePassword) {
    $signCommand += "/p"
    $signCommand += "`"$CertificatePassword`""
}

# Agregar el archivo a firmar
$signCommand += "`"$InstallerPath`""

# Ejecutar comando de firma
try {
    Write-Host "Ejecutando proceso de firma..." -ForegroundColor $colorInfo
    $process = Start-Process -FilePath $signtoolPath -ArgumentList $signCommand -NoNewWindow -Wait -PassThru
    
    if ($process.ExitCode -eq 0) {
        Write-Host "¡Firma digital completada con éxito!" -ForegroundColor $colorSuccess
        
        # Verificar la firma
        Write-Host "Verificando firma digital..." -ForegroundColor $colorInfo
        $verifyCommand = @("verify", "/pa", "`"$InstallerPath`"")
        $process = Start-Process -FilePath $signtoolPath -ArgumentList $verifyCommand -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Host "¡Verificación de firma exitosa!" -ForegroundColor $colorSuccess
            
            # Calcular y mostrar el hash SHA-256 del instalador
            $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")
            $fileStream = [System.IO.File]::OpenRead($InstallerPath)
            $hashBytes = $hashAlgorithm.ComputeHash($fileStream)
            $fileStream.Close()
            $hashString = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
            
            Write-Host "SHA-256 del instalador firmado: $hashString" -ForegroundColor $colorInfo
            
            # Guardar el hash en un archivo
            $hashFilePath = "$InstallerPath.sha256"
            $hashString | Out-File -FilePath $hashFilePath -Encoding utf8
            Write-Host "Hash guardado en: $hashFilePath" -ForegroundColor $colorInfo
            
            exit 0
        } else {
            Write-Host "ERROR: La verificación de la firma falló." -ForegroundColor $colorError
            exit 1
        }
    } else {
        Write-Host "ERROR: La firma digital falló con código de salida $($process.ExitCode)" -ForegroundColor $colorError
        exit 1
    }
} catch {
    Write-Host "ERROR: Se produjo una excepción durante el proceso de firma:" -ForegroundColor $colorError
    Write-Host $_.Exception.Message -ForegroundColor $colorError
    exit 1
} 