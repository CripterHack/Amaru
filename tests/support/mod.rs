//! Minimal PE32+ fixture for exercising metadata readers. The only section is read-only data.
//! There is no entry point or executable section, and the import library is fictitious.

pub fn import_fixture(names: &[&str], extra: &[u8]) -> Vec<u8> {
    const RVA: u32 = 0x1000;
    let mut imports = vec![0; 40]; // Import descriptor followed by its null terminator.
    let dll = RVA + imports.len() as u32;
    imports.extend_from_slice(b"amaru-fixture.dll\0");
    while imports.len() % 8 != 0 {
        imports.push(0);
    }
    let table = imports.len();
    imports.resize(table + 8 * (names.len() + 1), 0);
    for (i, name) in names.iter().enumerate() {
        if imports.len() % 2 != 0 {
            imports.push(0);
        }
        let name_rva = RVA + imports.len() as u32;
        put32(&mut imports, table + 8 * i, name_rva);
        imports.extend_from_slice(&[0, 0]); // Hint.
        imports.extend_from_slice(name.as_bytes());
        imports.push(0);
    }
    put32(&mut imports, 0, RVA + table as u32);
    put32(&mut imports, 12, dll);
    put32(&mut imports, 16, RVA + table as u32);
    imports.extend_from_slice(extra);
    let virtual_size = imports.len() as u32;
    imports.resize(imports.len().next_multiple_of(512), 0);

    let mut image = vec![0; 512];
    image[..2].copy_from_slice(b"MZ");
    put32(&mut image, 60, 128);
    image[128..132].copy_from_slice(b"PE\0\0");
    let coff = 132;
    put16(&mut image, coff, 0x8664); // AMD64.
    put16(&mut image, coff + 2, 1);
    put16(&mut image, coff + 16, 240);
    put16(&mut image, coff + 18, 0x2022);
    let opt = coff + 20;
    put16(&mut image, opt, 0x20b);
    put32(&mut image, opt + 32, RVA);
    put32(&mut image, opt + 36, 512);
    put32(
        &mut image,
        opt + 56,
        (RVA + virtual_size).next_multiple_of(RVA),
    );
    put32(&mut image, opt + 60, 512);
    put16(&mut image, opt + 68, 3);
    put32(&mut image, opt + 108, 16);
    put32(&mut image, opt + 120, RVA);
    put32(&mut image, opt + 124, 40);
    let section = opt + 240;
    image[section..section + 6].copy_from_slice(b".rdata");
    put32(&mut image, section + 8, virtual_size);
    put32(&mut image, section + 12, RVA);
    put32(&mut image, section + 16, imports.len() as u32);
    put32(&mut image, section + 20, 512);
    put32(&mut image, section + 36, 0x40000040); // Readable initialized data.
    image.extend(imports);
    image
}

fn put16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

// Symbol sets for controlled metadata fixtures. The test library exports no code.
#[allow(dead_code)]
pub const INJECTION: &[&str] = &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"];
#[allow(dead_code)]
pub const ENCRYPTION: &[&str] = &[
    "CryptEncrypt",
    "CryptAcquireContext",
    "BCryptEncrypt",
    "CreateFile",
    "WriteFile",
    "DeleteFile",
    "RemoveDirectory",
    "GetLogicalDrives",
    "GetDriveType",
    "FindFirstFile",
];
#[allow(dead_code)]
pub const KEY_INPUT: &[&str] = &[
    "SetWindowsHookEx",
    "GetAsyncKeyState",
    "GetKeyState",
    "GetKeyboardState",
    "RegisterRawInputDevices",
    "GetRawInputData",
    "AttachThreadInput",
    "MapVirtualKey",
];
#[allow(dead_code)]
pub const NETWORK: &[&str] = &[
    "recv",
    "SSL_read",
    "PR_Read",
    "HttpOpenRequest",
    "InternetOpen",
    "InternetConnect",
    "HttpSendRequest",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpSendRequest",
    "socket",
    "connect",
    "send",
    "WSASend",
    "WSAConnect",
    "InternetReadFile",
    "InternetWriteFile",
    "WSAStartup",
    "gethostbyname",
    "getaddrinfo",
    "DnsQuery",
    "SSL_write",
    "PR_Write",
    "URLDownloadToFile",
];
#[allow(dead_code)]
pub const PERSISTENCE: &[&str] = &[
    "RegSetValueEx",
    "RegCreateKeyEx",
    "RegOpenKeyEx",
    "SHGetSpecialFolderPath",
    "GetStartupInfo",
    "WinExec",
    "CreateService",
    "StartService",
    "Shell32.dll",
    "CurrentVersion\\Run",
    "Schedule\\TaskCache",
    "StartupItems",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
    "schtasks.exe",
    "at.exe",
    "wmic.exe",
    "STARTUP",
];
#[allow(dead_code)]
pub const ENVIRONMENT: &[&str] = &[
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugString",
    "GetTickCount",
    "QueryPerformanceCounter",
    "GetSystemTime",
    "Sleep",
    "SleepEx",
    "WaitForSingleObject",
    "timeGetTime",
    "GetProcessHeap",
    "HeapAlloc",
    "VirtualAlloc",
    "VirtualProtect",
    "NtSetInformationProcess",
    "ZwSetInformationThread",
    "NtQueryInformationProcess",
    "vmware.exe",
    "vbox.exe",
    "vboxtray.exe",
    "qemu",
];
