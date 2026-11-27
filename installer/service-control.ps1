[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Prepare', 'Install', 'Remove')][string]$Phase,
    [Parameter(Mandatory)][string]$Directory,
    [ValidateSet('New', 'Running', 'Stopped')][string]$Previous = 'New'
)

$ErrorActionPreference = 'Stop'
$name = 'AmaruAntivirus'
$directoryPath = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
$cli = Join-Path $directoryPath 'amaru.exe'

. (Join-Path $PSScriptRoot 'protected-directory.ps1')

function Test-QuickScanArguments([string]$Arguments) {
    if ($Arguments -ceq '--scheduled-quick-scan') { return $true }
    if ($Arguments -cnotmatch '^--scheduled-quick-scan --path-base64 ([A-Za-z0-9+/]+={0,2})\z') { return $false }
    $encoded = $Matches[1]
    try {
        $bytes = [Convert]::FromBase64String($encoded)
        if ([Convert]::ToBase64String($bytes) -cne $encoded) { return $false }
        $path = [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        return $path.IndexOf([char]0) -lt 0 -and $path -match '^(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+)'
    } catch { return $false }
}

function Get-OwnedService {
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'"
    if ($svc) {
        $allowedImages = @("`"$cli`" service-run", "$cli service-run")
        if ($svc.PathName -notin $allowedImages) {
            throw "The existing $name service belongs to another installation: $($svc.PathName)"
        }
    }
    return $svc
}

function Stop-OwnedService {
    $controller = Get-Service -Name $name
    if ($controller.Status -ne 'Stopped') {
        $controller.Stop()
        $controller.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
    }
}

try {
    $desktop = Join-Path $directoryPath 'amaru-antivirus.exe'
    if ($Phase -ne 'Install') {
        $active = Get-CimInstance -ClassName Win32_Process -Filter "Name='amaru-antivirus.exe'" |
            Where-Object { $_.ExecutablePath -eq $desktop }
        if ($active) { throw 'Close the installed Amaru desktop and retry.' }
    }
    $svc = Get-OwnedService
    if ($Phase -eq 'Remove') {
        # Inspect task actions as well as names before removing a per-user schedule.
        foreach ($task in Get-ScheduledTask | Where-Object { $_.TaskPath -eq '\' -and $_.TaskName -match '^Amaru-QuickScan-S-1-\d+(?:-\d+)+$' }) {
            $actions = @($task.Actions)
            if ($actions.Count -eq 1 -and $actions[0].Execute -and $actions[0].Execute.Trim('"') -eq $desktop -and (Test-QuickScanArguments $actions[0].Arguments)) {
                Unregister-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -Confirm:$false
            }
        }
        if ($svc) {
            Stop-OwnedService
            & (Join-Path ([Environment]::SystemDirectory) 'sc.exe') delete $name | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "SCM deletion failed ($LASTEXITCODE)." }
        }
        exit 0
    }
    if (-not (Test-ProtectedDirectory -Directory $directoryPath)) {
        if ($svc) { throw 'The installed service directory is no longer trusted.' }
        Write-Output 'Desktop and CLI installation only. Service registration requires a protected Program Files directory.'
        exit 20
    }
    if ($Phase -eq 'Prepare') {
        if (-not $svc) { exit 0 }
        $wasRunning = $svc.State -ne 'Stopped' -and $svc.State -ne 'Stop Pending'
        Stop-OwnedService
        if ($wasRunning) { exit 11 } else { exit 10 }
    }
    if (($Previous -eq 'New') -ne ($null -eq $svc)) { throw 'Service registration changed during installation.' }
    if ($Previous -eq 'New') {
        & $cli service --action install
        if ($LASTEXITCODE -ne 0) { throw "Service registration failed ($LASTEXITCODE)." }
    }
    if ($Previous -ne 'Stopped') {
        try {
            Start-Service -Name $name
            (Get-Service -Name $name).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
        } catch {
            if ($Previous -eq 'New') {
                Stop-OwnedService
                & (Join-Path ([Environment]::SystemDirectory) 'sc.exe') delete $name | Out-Null
            }
            throw
        }
    }
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
