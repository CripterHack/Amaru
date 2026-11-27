[CmdletBinding()]
param(
    [string]$Installer = (Join-Path (Split-Path -Parent $PSScriptRoot) 'target/x86_64-pc-windows-msvc/release/AmaruAV-Setup.exe')
)

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the test on an elevated disposable Windows runner.' }
if (-not [Environment]::Is64BitProcess) { throw 'Run the smoke test with x64 PowerShell.' }
$installerPath = (Get-Item -LiteralPath $Installer).FullName
$product = 'Amaru Antivirus'
$name = 'AmaruAntivirus'
$uninstallKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$product"
$runKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
$dir = Join-Path $env:ProgramFiles ('Amaru CI ' + [guid]::NewGuid().ToString('N'))
$cli = Join-Path $dir 'amaru.exe'
$desktop = Join-Path $dir 'amaru-antivirus.exe'
$uninstaller = Join-Path $dir 'uninstall.exe'
$userSession = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'com.amaru.antivirus'
$taskName = 'Amaru-QuickScan-' + $principal.Identity.User.Value

$commonPrograms = [Environment]::GetFolderPath('CommonPrograms')
$shortcutPaths = @((Join-Path $commonPrograms "$product/$product.lnk"), (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) "$product.lnk"))

function Read-RegistryValue($hive, $view, $path, $field) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
    try {
        $key = $base.OpenSubKey($path)
        if ($key) { try { return $key.GetValue($field) } finally { $key.Dispose() } }
    } finally { $base.Dispose() }
}

function Assert-NoRunEntries {
    foreach ($view in 'Registry64','Registry32') {
        foreach ($hive in 'LocalMachine','CurrentUser') {
            if ($null -ne (Read-RegistryValue $hive $view $runKey $product)) { throw "Unexpected Run entry in $hive/$view." }
        }
    }
}
function Test-ProductRegistration {
    foreach ($view in 'Registry64','Registry32') {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine',$view)
        try {
            $key = $base.OpenSubKey($uninstallKey)
            if ($key) { $key.Dispose(); return $true }
        } finally { $base.Dispose() }
    }
    return $false
}
function Invoke-Setup($file,$arguments) {
    $process=Start-Process -FilePath $file -ArgumentList $arguments -Wait -PassThru
    if ($process.ExitCode -eq 2) { throw 'Amaru requires the Microsoft Edge WebView2 Evergreen Runtime.' }
    if ($process.ExitCode -ne 0) { throw "Installer failed ($($process.ExitCode)): $file" }
}
function Invoke-Cli([string[]]$Arguments) {
    $output = & $cli @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Installed CLI failed ($LASTEXITCODE): $Arguments" }
    return ($output -join "`n")
}
function Assert-ServiceState([string]$Expected) {
    if ((Invoke-Cli @('service','--action','status')).Trim() -ne $Expected -or (Get-Service -Name $name).Status -ne $Expected) { throw "Expected service state $Expected." }
}
function Assert-Preserved($files) {
    foreach ($file in $files.Keys) {
        if ((Get-FileHash -LiteralPath $file).Hash -ne $files[$file]) { throw "Changed user data: $file" }
    }
}
function Test-DesktopLaunch {
    $process = Start-Process -FilePath $desktop -WorkingDirectory $env:TEMP -PassThru
    try {
        $deadline=(Get-Date).AddSeconds(60)
        do {
            $process.Refresh()
            if ($process.HasExited) { throw "Installed desktop exited during startup ($($process.ExitCode))." }
            if ($process.MainWindowHandle -ne [IntPtr]::Zero) { return }
            Start-Sleep -Milliseconds 300
        } while ((Get-Date) -lt $deadline)
        throw 'The installed desktop did not create its application window.'
    } finally {
        $process.Refresh()
        if (-not $process.HasExited) {
            [void]$process.CloseMainWindow()
            if (-not $process.WaitForExit(5000)) { $process.Kill(); $process.WaitForExit() }
        }
        $process.Dispose()
    }
}

if ((Get-Service -Name $name -ErrorAction SilentlyContinue) -or (Test-ProductRegistration) -or (Test-Path -LiteralPath $dir)) {
    throw 'The smoke test requires a clean runner without an existing Amaru installation.'
}
if ((Test-Path -LiteralPath $userSession) -or (Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue)) {
    throw 'The runner already has an Amaru desktop session or scheduled task.'
}
Assert-NoRunEntries
foreach ($link in $shortcutPaths) { if (Test-Path -LiteralPath $link) { throw "Existing Amaru shortcut: $link" } }

try {
    Invoke-Setup $installerPath "/S /D=$dir"
    foreach ($file in @($cli,$desktop,$uninstaller,(Join-Path $dir 'config.toml'),(Join-Path $dir 'signatures/official/eicar_test.yar'))) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing installed file: $file" }
    }
    if ((Read-RegistryValue 'LocalMachine' 'Registry64' $uninstallKey 'InstallLocation') -ne $dir) { throw 'Incorrect registered installation directory.' }
    $shell=New-Object -ComObject WScript.Shell
    foreach ($link in $shortcutPaths) {
        if (-not (Test-Path -LiteralPath $link) -or $shell.CreateShortcut($link).TargetPath -ne $desktop) { throw "Incorrect shortcut target: $link" }
    }
    Assert-NoRunEntries
    Assert-ServiceState 'Running'
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'"
    if ($service.StartMode -ne 'Auto' -or $service.PathName -notin @("`"$cli`" service-run","$cli service-run")) { throw 'Unexpected SCM registration.' }

    Push-Location -LiteralPath $env:TEMP
    try {
        $result=Invoke-Cli @('test-eicar')
        if ($result -notmatch 'EICAR_Test_File' -or $result -notmatch 'negative control') { throw "Unexpected EICAR result: $result" }
        Test-DesktopLaunch
        $scanFolder = Join-Path $dir 'smoke-input'
        [void][IO.Directory]::CreateDirectory($scanFolder)
        [IO.File]::WriteAllText((Join-Path $scanFolder 'clean.txt'),'ordinary test document')
        [void][IO.Directory]::CreateDirectory($userSession)
        $quickPaths = ConvertTo-Json -Compress -InputObject @($scanFolder)
        [IO.File]::WriteAllText((Join-Path $userSession 'quick-paths.json'), $quickPaths, [Text.UTF8Encoding]::new($false))
        $before = @(Get-ChildItem (Join-Path $userSession 'history/*.json') -ErrorAction SilentlyContinue | ForEach-Object Name)
        $scheduled = Start-Process -FilePath $desktop -ArgumentList '--scheduled-quick-scan' -WorkingDirectory $env:TEMP -PassThru
        if (-not $scheduled.WaitForExit(60000)) { $scheduled.Kill(); throw 'The installed quick scan timed out.' }
        if ($scheduled.ExitCode -ne 0) { throw "The installed quick scan failed ($($scheduled.ExitCode))." }
        $newHistory = @(Get-ChildItem (Join-Path $userSession 'history/*.json') | Where-Object { $_.Name -notin $before })
        if ($newHistory.Count -eq 0) { throw 'The installed quick scan did not record history.' }
        $history = Get-Content -LiteralPath $newHistory[-1].FullName -Raw | ConvertFrom-Json
        if ($null -eq $history) { throw 'The quick scan wrote empty history.' }
        $action = New-ScheduledTaskAction -Execute $desktop -Argument '--scheduled-quick-scan'
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(1)
        Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Trigger $trigger -User $principal.Identity.Name | Out-Null

    } finally { Pop-Location }

    [void](Invoke-Cli @('service','--action','stop'))
    Assert-ServiceState 'Stopped'
    $configFile=Join-Path $dir 'config.toml'
    [IO.File]::AppendAllText($configFile,"`r`n# CI user configuration`r`n")
    $custom=Join-Path $dir 'signatures/custom/ci-rule.yar'
    [IO.File]::WriteAllText($custom,'rule AmaruCiUserRule { condition: false }')
    $quarantine=Join-Path $dir 'quarantine/ci-user-item.dat'
    $logPath=Join-Path $dir 'logs/ci-user.log'
    [IO.File]::WriteAllText($quarantine,'ci quarantine data')
    [IO.File]::WriteAllText($logPath,'ci log data')
    $hashes=@{}
    foreach ($file in @($configFile,$custom,$quarantine,$logPath,(Join-Path $dir '.env'))) { $hashes[$file]=(Get-FileHash -LiteralPath $file).Hash }

    Invoke-Setup $installerPath "/S /D=$dir"
    Assert-ServiceState 'Stopped'
    Assert-Preserved $hashes
    [void](Invoke-Cli @('service','--action','start'))
    Assert-ServiceState 'Running'
    Invoke-Setup $installerPath "/S /D=$dir"
    Assert-ServiceState 'Running'
    Assert-NoRunEntries
    Assert-Preserved $hashes

    # _?= runs the NSIS uninstaller in place so the caller receives its actual exit status.
    Invoke-Setup $uninstaller "/S _?=$dir"
    if ((Get-Service -Name $name -ErrorAction SilentlyContinue) -or (Test-ProductRegistration)) { throw 'Uninstall left a registered service or product.' }
    foreach ($file in @($cli,$desktop) + $shortcutPaths) { if (Test-Path -LiteralPath $file) { throw "Uninstall left $file." } }
    if (Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue) { throw 'Uninstall left the Amaru quick scan task.' }
    if (-not (Test-Path -LiteralPath $newHistory[-1].FullName)) { throw 'Uninstall removed desktop history.' }
    Assert-Preserved $hashes
    Write-Host 'Installed CLI, desktop window, EICAR, SCM, upgrade and data-preserving uninstall passed.'
} finally {
    # Only clean the unique installation and service that this test created.
    $remaining = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'"
    if ($remaining -and $remaining.PathName -in @("`"$cli`" service-run","$cli service-run")) {
        Stop-Service -Name $name -ErrorAction SilentlyContinue
        & "$env:SystemRoot\System32\sc.exe" delete $name | Out-Null
    }
    if ((Test-Path -LiteralPath $uninstaller) -and (Test-ProductRegistration)) {
        Invoke-Setup $uninstaller "/S _?=$dir"
    }
    $remainingTask=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($remainingTask -and @($remainingTask.Actions).Count -eq 1 -and $remainingTask.Actions[0].Execute -eq $desktop -and $remainingTask.Actions[0].Arguments -ceq '--scheduled-quick-scan') {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false
    }
    if (Test-Path -LiteralPath $userSession) { Remove-Item -LiteralPath $userSession -Recurse -Force }
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
}
