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
function Invoke-Uninstall {
    # Running a private copy delivers NSIS's actual exit status and lets it delete the installed uninstaller.
    $copyDir = Join-Path $env:ProgramFiles ('Amaru CI maintenance ' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($copyDir)
    try {
        $copy = Join-Path $copyDir 'uninstall.exe'
        Copy-Item -LiteralPath $uninstaller -Destination $copy
        Invoke-Setup $copy "/S _?=$dir"
    } finally { Remove-Item -LiteralPath $copyDir -Recurse -Force }
}

function Read-ProtectionStatus {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'amaru-protection-status', [IO.Pipes.PipeDirection]::In, [IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $pipe.Connect(10000)
        $byte = [byte[]]::new(1)
        $read = $pipe.ReadAsync($byte, 0, 1)
        if (-not $read.Wait(10000) -or $read.Result -ne 1) { throw 'The status pipe failed to return the monitoring state.' }
        return $byte[0]
    } finally { $pipe.Dispose() }
}

function Invoke-ServiceCommand($Command) {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'amaru-service', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    $response = [IO.MemoryStream]::new()
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    try {
        $pipe.Connect(10000)
        $request = $utf8.GetBytes((ConvertTo-Json -InputObject $Command -Depth 6 -Compress))
        $write = $pipe.WriteAsync($request, 0, $request.Length)
        if (-not $write.Wait(10000)) { throw 'The administrative pipe did not accept the request.' }
        # The protocol exchanges one complete JSON value per request, without a delimiter.
        $buffer = [byte[]]::new(8192)
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while ($clock.ElapsedMilliseconds -lt 30000) {
            $read = $pipe.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $read.Wait([int][Math]::Max(0, 30000 - $clock.ElapsedMilliseconds))) { break }
            if ($read.Result -eq 0) { throw 'The administrative pipe closed before a complete response.' }
            $response.Write($buffer, 0, $read.Result)
            if ($response.Length -gt 16MB) { throw 'The administrative pipe exceeded its response limit.' }
            # Strings and objects are the only response variants. An inner quote or brace can end a partial read.
            if ($buffer[$read.Result - 1] -notin 34,125) { continue }
            try {
                $json = $utf8.GetString($response.GetBuffer(), 0, [int]$response.Length)
                return (ConvertFrom-Json -InputObject $json -ErrorAction Stop)
            } catch { continue }
        }
        throw 'Timed out waiting for a complete response from the administrative pipe.'
    } finally { $response.Dispose(); $pipe.Dispose() }
}

function Get-ServiceQuarantine {
    $reply = Invoke-ServiceCommand 'GetQuarantineList'
    if ($null -eq $reply.QuarantineList) { throw "Unexpected quarantine list response: $($reply | ConvertTo-Json -Compress)" }
    return $reply.QuarantineList
}

function Test-ServiceQuarantine($Folder) {
    $source = Join-Path $Folder 'quarantine-smoke.bin'
    $reason = 'Amaru CI quarantine round trip'
    $content = [byte[]]@(0, 65, 109, 97, 114, 117, 10, 255)
    [IO.File]::WriteAllBytes($source, $content)
    $digest = [Security.Cryptography.SHA256]::Create()
    try { $expectedHash = [Convert]::ToBase64String($digest.ComputeHash($content)) } finally { $digest.Dispose() }
    $reply = Invoke-ServiceCommand @{ QuarantineFile = @{ path = $source; reason = $reason } }
    if ($reply -cne 'Ok' -or (Test-Path -LiteralPath $source)) { throw "The service did not quarantine the input: $reply" }
    # Rust canonicalizes the original parent, which can add the Windows extended path prefix.
    $matches = @(Get-ServiceQuarantine | Where-Object { $_.original_path -in @($source, ('\\?\' + $source)) -and $_.reason -ceq $reason })
    if ($matches.Count -ne 1 -or !$matches[0].id -or $matches[0].file_size -ne $content.Length -or $matches[0].hash -cne $expectedHash) {
        throw 'The quarantine list does not identify the original path, reason, length and SHA-256.'
    }
    $id = $matches[0].id
    $restore = @{ RestoreFromQuarantine = @{ entry_id = $id } }
    [IO.File]::WriteAllText($source, 'existing user file')
    $occupiedHash = (Get-FileHash -LiteralPath $source).Hash
    $reply = Invoke-ServiceCommand $restore
    if (!$reply.Error -or (Get-FileHash -LiteralPath $source).Hash -ne $occupiedHash -or $id -notin @((Get-ServiceQuarantine).id)) {
        throw 'Restoring to an occupied path must preserve its content and retain the quarantine entry.'
    }
    Remove-Item -LiteralPath $source
    $reply = Invoke-ServiceCommand $restore
    if ($reply -cne 'Ok' -or $id -in @((Get-ServiceQuarantine).id)) { throw 'Restoring to the available path did not release the quarantine entry.' }
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($source)) -cne [Convert]::ToBase64String($content)) {
        throw 'The restored bytes differ from the original sample.'
    }
}

function Invoke-Schedule($mode, $frequency = 'daily', $time = '03:17', $day = '0') {
    $settings = @{ AMARU_SCHEDULE_EXE=$desktop; AMARU_SCHEDULE_MODE=$mode; AMARU_SCHEDULE_FREQUENCY=$frequency; AMARU_SCHEDULE_TIME=$time; AMARU_SCHEDULE_DAY=$day }
    $saved = @{}
    foreach ($key in $settings.Keys) {
        $saved[$key] = [Environment]::GetEnvironmentVariable($key)
        [Environment]::SetEnvironmentVariable($key, $settings[$key])
    }
    try {
        $ps = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell/v1.0/powershell.exe'
        $script = Join-Path (Split-Path -Parent $PSScriptRoot) 'src/schedule.ps1'
        $result = & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script
        if ($LASTEXITCODE -ne 0) { throw "Task scheduling operation '$mode' failed ($LASTEXITCODE)." }
        return ($result | ConvertFrom-Json)
    } finally {
        foreach ($key in $settings.Keys) { [Environment]::SetEnvironmentVariable($key, $saved[$key]) }
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

function Test-ScheduledRun([string]$Arguments, [int]$ExpectedFiles) {
    $pattern = Join-Path $userSession 'history/*.json'
    $before = @(Get-ChildItem $pattern -ErrorAction SilentlyContinue | ForEach-Object Name)
    $process = Start-Process -FilePath $desktop -ArgumentList $Arguments -WorkingDirectory $env:TEMP -PassThru
    try {
        if (-not $process.WaitForExit(60000)) { $process.Kill(); throw 'The installed scheduled scan timed out.' }
        if ($process.ExitCode -ne 0) { throw "The installed scheduled scan failed ($($process.ExitCode))." }
    } finally { $process.Dispose() }
    $created = @(Get-ChildItem $pattern | Where-Object { $_.Name -notin $before })
    if ($created.Count -ne 1) { throw 'The installed scheduled scan must produce one new history entry.' }
    $record = Get-Content -LiteralPath $created[0].FullName -Raw | ConvertFrom-Json
    if ($record.scan_type -cne 'scheduled' -or $record.status -cne 'completed' -or $record.files_scanned -ne $ExpectedFiles -or $record.files_failed -ne 0) {
        throw "Expected a completed scheduled scan of $ExpectedFiles files."
    }
    return $created[0].FullName
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
    if ((Read-ProtectionStatus) -ne 1) { throw 'The installed service reported inactive real-time monitoring.' }
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'"
    if ($service.StartMode -ne 'Auto' -or $service.PathName -notin @("`"$cli`" service-run","$cli service-run")) { throw 'Unexpected SCM registration.' }
    foreach ($setting in @(@('false','Manual'), @('true','Auto'))) {
        [void](Invoke-Cli @('autostart', ('--enable=' + $setting[0])))
        $mode = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'").StartMode
        if ($mode -ne $setting[1]) { throw "Expected SCM startup mode $($setting[1]), got $mode." }
        Assert-ServiceState 'Running'
        Assert-NoRunEntries
    }

    Push-Location -LiteralPath $env:TEMP
    try {
        $result=Invoke-Cli @('test-eicar')
        if ($result -notmatch 'EICAR_Test_File' -or $result -notmatch 'negative control') { throw "Unexpected EICAR result: $result" }
        Test-DesktopLaunch
        $scanFolder = Join-Path $dir 'smoke-input'
        [void][IO.Directory]::CreateDirectory($scanFolder)
        [IO.File]::WriteAllText((Join-Path $scanFolder 'clean.txt'),'ordinary test document')
        Test-ServiceQuarantine $scanFolder
        [void][IO.Directory]::CreateDirectory($userSession)
        $quickPaths = ConvertTo-Json -Compress -InputObject @($scanFolder)
        [IO.File]::WriteAllText((Join-Path $userSession 'quick-paths.json'), $quickPaths, [Text.UTF8Encoding]::new($false))
        $desktopHistory = Test-ScheduledRun '--scheduled-quick-scan' 2
        foreach ($entry in @(@('daily','03:17','0'), @('weekly','05:23','3'))) {
            [void](Invoke-Schedule 'set' $entry[0] $entry[1] $entry[2])
            $stored = Invoke-Schedule 'get'
            if ($stored.frequency -ne $entry[0] -or $stored.time -ne $entry[1] -or $stored.day -ne [int]$entry[2]) { throw 'Schedule did not round-trip.' }
            $registered = Get-ScheduledTask -TaskName $taskName -TaskPath '\'
            if ($registered.Principal.RunLevel -ne 'Limited' -or $registered.Principal.LogonType -ne 'Interactive' -or $registered.Actions[0].Execute -ne $desktop -or $registered.Actions[0].Arguments -cne '--scheduled-quick-scan') {
                throw 'Unexpected quick scan task privileges or program.'
            }
        }
        [void](Invoke-Schedule 'remove')
        if ($null -ne (Invoke-Schedule 'get')) { throw 'The quick scan task was not removed.' }
        $preferencesFile=Join-Path $userSession 'quick-paths.json'
        $preferencesHash=(Get-FileHash -LiteralPath $preferencesFile).Hash
        $cliTarget = Join-Path $dir 'single CLI target.txt'
        [IO.File]::WriteAllText($cliTarget, 'one ordinary document outside the desktop scan folder')
        foreach ($entry in @(@('daily','04:18','0'), @('weekly','06:24','0'))) {
            $argsList = @('schedule',('--' + $entry[0]),'--time',$entry[1],'--path',$cliTarget)
            if ($entry[0] -eq 'weekly') { $argsList += @('--day','Sunday') }
            [void](Invoke-Cli $argsList)
            $cliSchedule = Invoke-Cli @('schedule','--status') | ConvertFrom-Json
            if ($cliSchedule.frequency -ne $entry[0] -or $cliSchedule.time -ne $entry[1] -or $cliSchedule.day -ne 0 -or $cliSchedule.path -cne $cliTarget) {
                throw 'CLI scheduling did not preserve the selected trigger and scan target.'
            }
            $registered=Get-ScheduledTask -TaskPath '\' -TaskName $taskName
            $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cliTarget))
            if ($registered.Actions.Count -ne 1 -or $registered.Actions[0].Execute -ne $desktop -or $registered.Actions[0].Arguments -cne "--scheduled-quick-scan --path-base64 $encoded") {
                throw 'The registered CLI schedule does not match the installed desktop or its encoded path.'
            }
        }
        $cliHistory = Test-ScheduledRun $registered.Actions[0].Arguments 1
        [void](Invoke-Cli @('schedule','--disable'))
        if ($null -ne (Invoke-Cli @('schedule','--status') | ConvertFrom-Json)) { throw 'CLI schedule was not disabled.' }
        [void](Invoke-Cli @('schedule','--daily','--time','03:17','--path',$cliTarget))
        if ((Get-FileHash -LiteralPath $preferencesFile).Hash -ne $preferencesHash) { throw 'CLI scheduling changed the desktop quick paths.' }
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

    Invoke-Uninstall
    if ((Get-Service -Name $name -ErrorAction SilentlyContinue) -or (Test-ProductRegistration)) { throw 'Uninstall left a registered service or product.' }
    foreach ($file in @($cli,$desktop,$uninstaller,(Split-Path -Parent $shortcutPaths[0]),(Join-Path $dir 'signatures/official')) + $shortcutPaths) { if (Test-Path -LiteralPath $file) { throw "Uninstall left $file." } }
    if (Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue) { throw 'Uninstall left the Amaru quick scan task.' }
    foreach ($record in $desktopHistory, $cliHistory) {
        if (-not (Test-Path -LiteralPath $record)) { throw 'Uninstall removed a scheduled scan history entry.' }
    }
    Assert-Preserved $hashes
    Write-Host 'Installed CLI, desktop window, EICAR, SCM, IPC quarantine, upgrade and data-preserving uninstall passed.'
} finally {
    # Only clean the unique installation and service that this test created.
    $remaining = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'"
    if ($remaining -and $remaining.PathName -in @("`"$cli`" service-run","$cli service-run")) {
        Stop-Service -Name $name -ErrorAction SilentlyContinue
        & "$env:SystemRoot\System32\sc.exe" delete $name | Out-Null
    }
    if ((Test-Path -LiteralPath $uninstaller) -and (Test-ProductRegistration)) {
        Invoke-Uninstall
    }
    $remainingTask=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($remainingTask -and @($remainingTask.Actions).Count -eq 1 -and $remainingTask.Actions[0].Execute -eq $desktop -and ($remainingTask.Actions[0].Arguments -ceq '--scheduled-quick-scan' -or ($encoded -and $remainingTask.Actions[0].Arguments -ceq "--scheduled-quick-scan --path-base64 $encoded"))) {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false
    }
    if (Test-Path -LiteralPath $userSession) { Remove-Item -LiteralPath $userSession -Recurse -Force }
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
}
