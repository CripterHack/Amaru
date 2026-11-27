#Requires -Version 7.2
[CmdletBinding()]
param([switch]$Release)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
$dumpbin = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find 'VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe' | Select-Object -First 1
if (-not $dumpbin) { throw 'Visual Studio x64 dumpbin is required to inspect PE imports.' }

if ($Release) {
    $folder = Join-Path $root 'target/x86_64-pc-windows-msvc/release'
    $images = @((Join-Path $folder 'amaru.exe'), (Join-Path $folder 'amaru-antivirus.exe'))
} else {
    # Cargo's artifact record identifies the lib-test even when a cache contains multiple builds.
    $manifest = Join-Path $root 'Cargo.toml'
    $artifacts = @(cargo test --locked --package amaru --lib --no-run --message-format=json --manifest-path $manifest |
        ForEach-Object { $_ | ConvertFrom-Json })
    if ($LASTEXITCODE -ne 0) { throw 'Unable to build the Amaru library test executable.' }
    $images = @($artifacts | Where-Object {
        $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'amaru' -and
        $_.target.kind -contains 'lib' -and $_.profile.test -and $_.executable
    } | ForEach-Object executable)
    if ($images.Count -ne 1) { throw 'Expected one Amaru library test artifact.' }
}

foreach ($image in $images) {
    if (-not [IO.File]::Exists($image)) { throw "Missing PE artifact $([IO.Path]::GetFileName($image))." }
    $headers = @(& $dumpbin /nologo /imports $image)
    if ($LASTEXITCODE -ne 0) { throw 'dumpbin could not inspect the PE import table.' }
    $modules = @($headers | ForEach-Object { if ($_ -match '^\s*([\w.+-]+\.dll)\s*$') { $Matches[1] } })
    if (-not $modules.Count) { throw 'No DLL imports could be identified.' }
    $name = [IO.Path]::GetFileName($image)
    if ($modules -contains 'vertdll.dll') {
        throw "$name imports VertDll.dll, which is reserved for VBS enclaves. Use the desktop synchronization APIs."
    }
    Write-Host "$name passed the desktop DLL import check ($($modules.Count) import descriptors)."
}
