function Test-ProtectedDirectory {
    param([Parameter(Mandatory)][string]$Directory)
    $directoryPath = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
    try {
        $key = $registry.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion')
        try {
            $roots = @($key.GetValue('ProgramFilesDir'), $key.GetValue('ProgramFilesDir (x86)')) | Where-Object { $_ }
        } finally { if ($key) { $key.Dispose() } }
    } finally { $registry.Dispose() }
    $root = $roots | Where-Object {
        $directoryPath.StartsWith(($_.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    if (-not $root) { return $false }

    # A permissive ancestor or a junction permits replacement of a privileged image.
    $trusted = @('S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $sid = [System.Security.Principal.SecurityIdentifier]
    $writeMask = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    function Test-SafeItem($item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        $acl = Get-Acl -LiteralPath $item.FullName
        if ($acl.GetOwner($sid).Value -notin $trusted) { return $false }
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $descriptor.DiscretionaryAcl) { return $false }
        foreach ($rule in $acl.GetAccessRules($true, $true, $sid)) {
            if ($rule.AccessControlType -ne 'Allow' -or -not ($rule.FileSystemRights -band $writeMask)) { continue }
            if ($rule.IdentityReference.Value -eq 'S-1-3-0' -and ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
            if ($rule.IdentityReference.Value -notin $trusted) { return $false }
        }
        return $true
    }
    $path = $directoryPath
    while ($path) {
        if ((Test-Path -LiteralPath $path) -and -not (Test-SafeItem (Get-Item -LiteralPath $path -Force))) { return $false }
        if ($path -eq $root) { break }
        $path = Split-Path -Parent $path
    }
    if (Test-Path -LiteralPath $directoryPath) {
        $pending = [Collections.Generic.Stack[IO.DirectoryInfo]]::new()
        $pending.Push([IO.DirectoryInfo]::new($directoryPath))
        while ($pending.Count -gt 0) {
            foreach ($entry in $pending.Pop().EnumerateFileSystemInfos()) {
                if (-not (Test-SafeItem $entry)) { return $false }
                if ($entry -is [IO.DirectoryInfo]) { $pending.Push($entry) }
            }
        }
    }
    return $true
}
