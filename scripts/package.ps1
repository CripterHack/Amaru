[CmdletBinding()]
param([switch]$VerifyOnly)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$installer = Join-Path $root 'installer'
$target = 'x86_64-pc-windows-msvc'
$targetDir = Join-Path $root 'target'
$exeDir = Join-Path $targetDir "$target/release"
$gui = Join-Path $root 'gui'

if (-not $VerifyOnly) {
    Push-Location -LiteralPath $root
    try {
        Push-Location -LiteralPath $gui
        try {
            & npm.cmd ci
            if ($LASTEXITCODE -ne 0) { throw 'npm ci failed in gui.' }
            & npm.cmd run build
            if ($LASTEXITCODE -ne 0) { throw 'The GUI assets failed to build.' }
        } finally { Pop-Location }
        & cargo build --locked --release --package amaru --bin amaru --target $target --target-dir $targetDir
        if ($LASTEXITCODE -ne 0) {
            throw 'Cargo failed to build the Amaru executable.'
        }
        & cargo build --locked --release --manifest-path (Join-Path $gui 'src-tauri/Cargo.toml') --features custom-protocol --bin amaru-antivirus --target $target --target-dir $targetDir
        if ($LASTEXITCODE -ne 0) { throw 'Cargo failed to build the Tauri desktop executable.' }
    } finally {
        Pop-Location
    }
}

# Older preparation scripts could leave an empty file named amaru.exe.
# Check the PE signature and x64 machine field before passing the file to NSIS.
foreach ($name in @('amaru.exe', 'amaru-antivirus.exe')) {
    $exe = Join-Path $exeDir $name
    $stream = [IO.File]::OpenRead($exe)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) {
            throw "Missing DOS header in $exe"
        }
        $stream.Position = 0x3C
        $header = $reader.ReadUInt32()
        if ($header -lt 64 -or $header -gt ($stream.Length - 26)) {
            throw "Invalid PE header offset in $exe"
        }
        $stream.Position = $header
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) {
            throw "Expected an x64 Windows executable in $exe"
        }
    } finally {
        $reader.Dispose()
    }
}

$nsis = (Get-Command 'makensis.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $nsis) {
    $nsis = Join-Path ${env:ProgramFiles(x86)} 'NSIS/makensis.exe'
    if (-not (Test-Path -LiteralPath $nsis -PathType Leaf)) {
        throw 'Install NSIS 3 or add makensis.exe to PATH.'
    }
}

# Compile into an empty directory so a previous installer cannot satisfy this check.
$stage = Join-Path $targetDir ('nsis-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    & $nsis '/V2' "/DOUTDIR=$stage" "/DEXEDIR=$exeDir" (Join-Path $installer 'unified_installer.nsi')
    if ($LASTEXITCODE -ne 0) {
        throw "NSIS failed with exit code $LASTEXITCODE."
    }
    $output = Get-Item -LiteralPath (Join-Path $stage 'AmaruAV-Setup.exe')
    if ($output.Length -eq 0) {
        throw 'NSIS generated an empty installer.'
    }

    if ($VerifyOnly) {
        Write-Host 'NSIS compiled the development installer successfully.'
    } else {
        $destination = Join-Path $exeDir $output.Name
        Move-Item -LiteralPath $output.FullName -Destination $destination -Force
        Write-Host "Development installer created at $destination"
    }
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
