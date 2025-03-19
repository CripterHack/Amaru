/*
 * Amaru Official Trojan Detection Rules
 * Description: Rules for detecting common trojan families
 * Author: Amaru Contributors
 * License: GPL-2.0
 */

rule Trojan_Emotet {
    meta:
        description = "Detects Emotet banking trojan"
        author = "Amaru Project"
        reference = "https://www.cisa.gov/news-events/alerts/2018/07/20/emotet-malware"
        confidence = "high"
        severity = "high"
    
    strings:
        $s1 = "emotet" nocase wide ascii
        $s2 = "trickbot" nocase wide ascii
        
        $api1 = "GetWindowsDirectoryA" wide ascii
        $api2 = "GetTempPathA" wide ascii
        $api3 = "CreateServiceA" wide ascii
        $api4 = "OpenProcessToken" wide ascii
        
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" wide ascii
        
        $cmd = "powershell -nop -w hidden -encodedcommand" wide ascii
        
        $mutex = "Global\\M" wide ascii
        
        $pdb = "C:\\Users\\[^\\\\]+\\source\\repos" wide ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        ((any of ($s*)) or
         (all of ($api*) and any of ($reg*)) or
         ($cmd and 2 of ($api*)) or
         ($mutex and 2 of ($api*)) or
         $pdb)
}

rule Trojan_Remcos {
    meta:
        description = "Detects Remcos RAT"
        author = "Amaru Project"
        reference = "https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/remcos-a-rat-in-the-wild"
        confidence = "high"
        severity = "high"
    
    strings:
        $s1 = "Remcos" nocase wide ascii
        $s2 = "remcos.exe" nocase wide ascii
        $s3 = "Breaking-Security.Net" nocase wide ascii
        
        $cfg1 = "password=" wide ascii
        $cfg2 = "mutex=" wide ascii
        $cfg3 = "keyname=" wide ascii
        $cfg4 = "serverhash=" wide ascii
        
        $str1 = "cmd.exe /c ping 127.0.0.1 & del" wide ascii
        $str2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $str3 = "AppData\\Roaming\\" wide ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        ((any of ($s*) and 2 of ($cfg*)) or (2 of ($cfg*) and 2 of ($str*)))
}

rule Trojan_Trickbot {
    meta:
        description = "Detects TrickBot trojan"
        author = "Amaru Project"
        reference = "https://www.mandiant.com/resources/trickbot-banking-trojan"
        confidence = "high"
        severity = "high"
    
    strings:
        $s1 = "TrickBot" nocase wide ascii
        $s2 = "trick" nocase wide ascii
        
        $mod1 = "systeminfo" wide ascii
        $mod2 = "injectDll" wide ascii
        $mod3 = "mailsearcher" wide ascii
        $mod4 = "worming" wide ascii
        $mod5 = "shareDll" wide ascii
        
        $cfg1 = "<srv>" wide ascii
        $cfg2 = "<group>" wide ascii
        $cfg3 = "<gtag>" wide ascii
        $cfg4 = "<mcconf>" wide ascii
        
        $pdb = ".pdb" wide ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        ((2 of ($mod*) and any of ($s*)) or
         (3 of ($cfg*)) or
         (any of ($s*) and 2 of ($cfg*) and any of ($mod*)))
} 
rule Updated_trojans_20250319_64804 {
    meta:
        description = "Updated rule for trojans"
        author = "Amaru Team"
        severity = "medium"
        date = "2025-03-19"
    strings:
        $s1 = "new_malicious_pattern" nocase
    condition:
        any of them
}
