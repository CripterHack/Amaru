# Script para asegurar que todos los archivos utilicen UTF-8 sin BOM
# Esta herramienta revisa todos los archivos del proyecto y los convierte a UTF-8 si es necesario

# Configurar codificaciÃ³n para PowerShell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "Verificando y corrigiendo codificaciÃ³n UTF-8 en archivos del proyecto..." -ForegroundColor Cyan

# Tipos de archivos a verificar
$fileTypes = @("*.cs", "*.ps1", "*.nsi", "*.xml", "*.config", "*.txt", "*.md", "*.json")

# FunciÃ³n para convertir archivos a UTF-8 sin BOM
function ConvertTo-UTF8WithoutBOM {
    param (
        [string]$filePath
    )
    
    try {
        # Detectar la codificaciÃ³n actual del archivo
        $bytes = [System.IO.File]::ReadAllBytes($filePath)
        $encoding = $null
        
        # Detectar BOM
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            $encoding = "UTF-8 with BOM"
            $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::UTF8)
        }
        elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
            $encoding = "UTF-16 LE"
            $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::Unicode)
        }
        elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
            $encoding = "UTF-16 BE"
            $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::BigEndianUnicode)
        }
        else {
            # Intentar detectar automÃ¡ticamente la codificaciÃ³n
            $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::Default)
            $encoding = "Default (ANSI/Other)"
            
            # Verificar si hay caracteres no UTF-8 vÃ¡lidos
            $utf8Encoding = [System.Text.Encoding]::UTF8
            $bytes = $utf8Encoding.GetBytes($content)
            $roundTrip = $utf8Encoding.GetString($bytes)
            
            if ($content -ne $roundTrip) {
                $encoding = "Non-UTF8 compatible"
            }
        }
        
        # Guardar como UTF-8 sin BOM
        $utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($filePath, $content, $utf8NoBomEncoding)
        
        return $encoding
    }
    catch {
        Write-Warning "Error al procesar $filePath`: $_"
        return "Error"
    }
}

# Directorio principal del proyecto
$projectRoot = (Get-Location).Path

# Buscar y procesar todos los archivos
foreach ($fileType in $fileTypes) {
    $files = Get-ChildItem -Path $projectRoot -Filter $fileType -Recurse -File
    
    foreach ($file in $files) {
        $oldEncoding = ConvertTo-UTF8WithoutBOM -filePath $file.FullName
        
        if ($oldEncoding -ne "UTF-8 without BOM") {
            Write-Host "Convertido: $($file.FullName) - De: $oldEncoding a UTF-8 sin BOM" -ForegroundColor Green
        }
    }
}

Write-Host "Proceso completado. Todos los archivos han sido convertidos a UTF-8 sin BOM." -ForegroundColor Green 