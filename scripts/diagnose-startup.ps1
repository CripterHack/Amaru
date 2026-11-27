#Requires -Version 7.2
[CmdletBinding()]
param([switch]$NoDefaultFeatures)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This diagnostic requires a Windows GitHub Actions runner.'
}

$repo = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $repo 'Cargo.toml'
$system = [Environment]::SystemDirectory
$windows = Split-Path -Parent $system
$pf = [Environment]::GetFolderPath('ProgramFiles')
$pf86 = [Environment]::GetFolderPath('ProgramFilesX86')
$locations = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)

function Add-Location([string]$path, [string]$label) {
    if ($path -match '^[a-zA-Z]:[\\/]') {
        $full = [IO.Path]::GetFullPath($path).TrimEnd('\')
        [void]$locations.TryAdd($full, $label)
    }
}
function Get-LocationLabel([string]$path) {
    $directory = [IO.Path]::GetDirectoryName($path)
    if ($directory -and $locations.ContainsKey($directory)) { return $locations[$directory] }
    if ($path.StartsWith("$windows\", [StringComparison]::OrdinalIgnoreCase)) { return 'Windows' }
    return 'other'
}

# Only the library test artifact Cargo identifies for this checkout is eligible for execution.
$metadata = (& cargo metadata --format-version 1 --no-deps --locked --manifest-path $manifest 2>$null) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed.' }
$package = @($metadata.packages | Where-Object { $_.name -eq 'amaru' -and $_.manifest_path -eq $manifest })
if ($package.Count -ne 1) { throw 'Cannot identify the local Amaru package.' }
$build = @('test','--locked','--package','amaru','--lib','--no-run','--message-format=json','--manifest-path',$manifest)
if ($NoDefaultFeatures) { $build += '--no-default-features' }
$artifacts = @(& cargo @build 2>$null | ForEach-Object { $_ | ConvertFrom-Json })
if ($LASTEXITCODE -ne 0) { throw 'No diagnostics available because the library test did not compile.' }
$test = @($artifacts | Where-Object {
    $_.reason -eq 'compiler-artifact' -and $_.package_id -eq $package[0].id -and
    $_.profile.test -and $_.target.kind -contains 'lib' -and $_.executable
})
if ($test.Count -ne 1) { throw 'Cargo did not report a unique library test executable.' }
$exe = [IO.Path]::GetFullPath($test[0].executable)
$target = [IO.Path]::GetFullPath($metadata.target_directory).TrimEnd('\')
if (-not $exe.StartsWith("$target\",[StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($exe) -notmatch '^amaru-[a-f0-9]+\.exe$' -or -not [IO.File]::Exists($exe)) {
    throw 'Cargo reported an unexpected test artifact.'
}
$imageDir = Split-Path -Parent $exe
Add-Location $imageDir 'image'
Add-Location $system 'System32'
Add-Location $windows 'Windows'
Add-Location $repo 'checkout'
$i = 0
foreach ($searchPath in ($artifacts | Where-Object reason -eq 'build-script-executed').linked_paths) {
    Add-Location ($searchPath -replace '^(native|dependency|all)=','') "cargo-link[$i]"
    $i++
}
$i = 0
foreach ($path in $env:Path.Split(';',[StringSplitOptions]::RemoveEmptyEntries)) {
    Add-Location $path.Trim('"') "inherited-PATH[$i]"
    $i++
}

# Select tools from Visual Studio, Windows Kits or the registered Microsoft WinDbg package.
$vswhere = Join-Path $pf86 'Microsoft Visual Studio\Installer\vswhere.exe'
$dumpbin = if ([IO.File]::Exists($vswhere)) {
    & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find 'VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe' |
        Select-Object -First 1
}
$readobj = Join-Path $pf 'LLVM\bin\llvm-readobj.exe'
if ($dumpbin -and [IO.File]::Exists($dumpbin)) {
    $deps = @(& $dumpbin /nologo /dependents $exe | ForEach-Object {
        if ($_ -match '^\s*([\w.+-]+\.dll)\s*$') { $Matches[1] }
    })
} elseif ([IO.File]::Exists($readobj)) {
    $deps = @(& $readobj --coff-imports $exe | ForEach-Object {
        if ($_ -match '^\s*Name:\s*([\w.+-]+\.dll)\s*$') { $Matches[1] }
    })
} else { $deps = @(); Write-Host 'No Visual Studio dumpbin or LLVM readobj found.' }
foreach ($dll in ($deps | Sort-Object -Unique)) {
    $found = @($locations.GetEnumerator() | Where-Object { [IO.File]::Exists([IO.Path]::Combine($_.Key,$dll)) } | ForEach-Object Value)
    if (-not $found.Count) { $found = @('no file in inspected directories; may be an API set') }
    Write-Host ("Import {0} -> {1}" -f $dll, ($found -join ', '))
}

$debugDirs = @((Join-Path $pf86 'Windows Kits\10\Debuggers\x64'), (Join-Path $pf 'Windows Kits\10\Debuggers\x64'))
if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
    $app = Get-AppxPackage -Name Microsoft.WinDbg -ErrorAction SilentlyContinue | Where-Object PublisherId -eq '8wekyb3d8bbwe' | Select-Object -First 1
    if ($app.InstallLocation) { $debugDirs += Join-Path $app.InstallLocation 'amd64' }
}
$cdb = $debugDirs | ForEach-Object { Join-Path $_ 'cdb.exe' } | Where-Object { [IO.File]::Exists($_) } | Select-Object -First 1
$gflags = $debugDirs | ForEach-Object { Join-Path $_ 'gflags.exe' } | Where-Object { [IO.File]::Exists($_) } | Select-Object -First 1
$scratch = [IO.Directory]::CreateTempSubdirectory('amaru-startup-').FullName

function Invoke-Isolated([string]$program,[string[]]$arguments,[int]$timeout) {
    $start = [Diagnostics.ProcessStartInfo]::new($program)
    $start.UseShellExecute = $false
    $start.WorkingDirectory = $scratch
    $start.Environment['PATH'] = "$system;$windows"
    $start.Environment.Remove('_NT_SYMBOL_PATH') | Out-Null
    $start.Environment.Remove('_NT_ALT_SYMBOL_PATH') | Out-Null
    foreach ($arg in $arguments) { $start.ArgumentList.Add($arg) }
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        $out = $process.StandardOutput.ReadToEndAsync()
        $err = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($timeout * 1000)) { $process.Kill($true); throw 'Diagnostic child timed out.' }
        [pscustomobject]@{ Code = $process.ExitCode; Text = $out.GetAwaiter().GetResult() + $err.GetAwaiter().GetResult(); Pid = $process.Id }
    } finally { $process.Dispose() }
}

# Give the debugger an identical private copy in the same directory for DLL search equivalence.
# The unique image name ensures the short-lived loader flag cannot affect the service or other tests.
$probeName = 'amaru-loader-' + [guid]::NewGuid().ToString('N') + '.exe'
$probe = Join-Path $imageDir $probeName
$ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$probeName"
$flagRequested = $false
try {
    $observedAt = Get-Date
    $run = Invoke-Isolated $exe @('--list') 30
    Write-Host ('Library test --list with temporary cwd and Windows-only PATH returned 0x{0:X8}' -f $run.Code)
    if ($run.Code -eq 0) { return }

    # Log only matched event fields, never a whole event message, environment, dump or local path.
    $events = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$observedAt; Id=1000,1001,33} -MaxEvents 30 -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        if (-not $event.Message -or -not $event.Message.Contains([IO.Path]::GetFileName($exe),[StringComparison]::OrdinalIgnoreCase)) { continue }
        $modules = [regex]::Matches($event.Message,'(?i)[\w.+-]+\.dll\b').Value | Sort-Object -Unique
        $codes = [regex]::Matches($event.Message,'(?i)\b0x[a-f\d]{8}\b').Value | Sort-Object -Unique
        Write-Host ("Application event {0} ID {1}; modules {2}; codes {3}" -f $event.ProviderName,$event.Id,($modules -join ', '),($codes -join ', '))
    }
    if (-not $cdb) { Write-Host 'Microsoft CDB is unavailable on this runner.'; return }
    [IO.File]::Copy($exe,$probe)
    if ($gflags -and -not (Test-Path -LiteralPath $ifeo)) {
        $flagRequested = $true
        $null = & $gflags /i $probeName +sls 2>$null
        Write-Host "Per-image loader snaps activation exit $LASTEXITCODE"
    } else { Write-Host 'Using CDB module events without loader snaps.' }

    $debug = Invoke-Isolated $cdb @('-sins','-y',$scratch,'-G','-c','g;q',$probe,'--list') 45
    Write-Host ('CDB exit 0x{0:X8}' -f $debug.Code)
    $details = @($debug.Text -split '\r?\n' | Where-Object { $_ -match '(?i)ModLoad:|LdrpCallInitRoutine|DLL_INIT_FAILED|ERROR:|exception code' })
    foreach ($line in ($details | Select-Object -Last 40)) {
        $modules = [regex]::Matches($line,'(?i)[\w.+-]+\.(dll|exe)\b').Value
        $codes = [regex]::Matches($line,'(?i)\b(?:0x)?[8c][\da-f]{7}\b').Value
        if ($line -match '(?i)^ModLoad:\s*\S+\s+\S+\s+(.+?\.(?:dll|exe))\s*$') {
            $loaded = $Matches[1]
            Write-Host ("Loaded {0} [{1}]" -f ([IO.Path]::GetFileName($loaded)), (Get-LocationLabel $loaded))
        } elseif ($modules -or $codes) {
            $label = if ($line -match '(?i)ERROR:|DLL_INIT_FAILED|exception code') { 'Loader error' } else { 'Loader initialization' }
            Write-Host ("{0}: {1} {2}" -f $label, ($modules -join ', '), ($codes -join ', '))
        }
    }
} finally {
    if ($flagRequested) {
        $null = & $gflags /i $probeName -sls 2>$null
        if (Test-Path -LiteralPath $ifeo) { Remove-Item -LiteralPath $ifeo -Force }
    }
    [IO.File]::Delete($probe)
    [IO.Directory]::Delete($scratch,$true)
}
