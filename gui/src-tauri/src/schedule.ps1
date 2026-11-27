$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$name = 'Amaru-QuickScan-' + $identity.User.Value
$exe = $env:AMARU_SCHEDULE_EXE
$argument = '--scheduled-quick-scan'
function Read-Task {
    # An empty root folder and a failed Task Scheduler query have different outcomes.
    @(Get-ScheduledTask | Where-Object { $_.TaskPath -eq '\' -and $_.TaskName -eq $name }) | Select-Object -First 1
}
try {
    $task = Read-Task
    if ($task -and ($task.Actions.Count -ne 1 -or $task.Actions[0].Execute -ne $exe -or $task.Actions[0].Arguments -ne $argument)) {
        throw 'A task with this name belongs to another installation.'
    }
    switch ($env:AMARU_SCHEDULE_MODE) {
        'set' {
            $time = [datetime]::ParseExact($env:AMARU_SCHEDULE_TIME, 'HH:mm', [cultureinfo]::InvariantCulture)
            if ($env:AMARU_SCHEDULE_FREQUENCY -eq 'daily') {
                $trigger = New-ScheduledTaskTrigger -Daily -At $time
            } else {
                $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek ([DayOfWeek][int]$env:AMARU_SCHEDULE_DAY) -At $time
            }
            $action = New-ScheduledTaskAction -Execute $exe -Argument $argument
            $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
            $options = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew
            $task = Register-ScheduledTask -TaskName $name -TaskPath '\' -Trigger $trigger -Principal $principal -Action $action -Settings $options -Force
        }
        'remove' {
            if ($task) { Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false }
            $task = $null
        }
    }
    if (!$task) { Write-Output 'null'; exit 0 }
    if ($task.Triggers.Count -ne 1 -or !$task.Settings.Enabled -or !$task.Triggers[0].Enabled) {
        throw 'The scheduled task has been changed. Inspect the task in Windows Task Scheduler.'
    }
    $trigger = $task.Triggers[0]
    $day = 0
    switch ($trigger.CimClass.CimClassName) {
        'MSFT_TaskDailyTrigger' { $frequency = 'daily' }
        'MSFT_TaskWeeklyTrigger' {
            $frequency = 'weekly'
            $days = @(0..6 | Where-Object { $trigger.DaysOfWeek -eq (1 -shl $_) })
            if ($days.Count -ne 1) { throw 'The task uses an unsupported set of weekdays.' }
            $day = $days[0]
        }
        default { throw 'The task uses an unsupported trigger.' }
    }
    $time = [datetime]::Parse($trigger.StartBoundary, [cultureinfo]::InvariantCulture).ToString('HH:mm')
    @{frequency=$frequency;time=$time;day=$day} | ConvertTo-Json -Compress
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
