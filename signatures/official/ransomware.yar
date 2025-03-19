/*
 * Amaru Official Ransomware Detection Rules
 * Description: Rules for detecting common ransomware families
 * Author: Amaru Contributors
 * License: GPL-2.0
 */

rule Ransomware_WannaCry {
    meta:
        description = "Detects WannaCry ransomware"
        author = "Amaru Project"
        reference = "https://www.cisa.gov/news-events/ics-advisories/icsa-17-143-01"
        confidence = "high"
        severity = "critical"
    
    strings:
        $s1 = "WannaCry" nocase wide ascii
        $s2 = "WANACRY!" nocase wide ascii
        $s3 = "wcry@" nocase wide ascii
        $s4 = "msg/m_" wide ascii
        $s5 = "tasksche.exe" nocase wide ascii
        $s6 = "taskdl.exe" nocase wide ascii
        $s7 = "@WanaDecryptor@" wide ascii
        $s8 = "Bitcoin" wide ascii
        
        $mutex = "Global\\MsWinZonesCacheCounterMutexA" wide ascii
        
        $ransom_msg1 = "Ooops, your files have been encrypted!" wide ascii
        $ransom_msg2 = "Wana Decrypt0r" wide ascii
        $ransom_msg3 = "wanacrypt0r" wide ascii
        
        $domain = ".onion" wide ascii
        $domain2 = "gx7ekbenv2riucmf.onion" wide ascii
        
    condition:
        uint16(0) == 0x5A4D and 
        filesize < 5MB and 
        ((3 of ($s*)) or (2 of ($ransom_msg*)) or ($mutex) or (any of ($domain*) and 2 of ($s*)))
}

rule Ransomware_Locky {
    meta:
        description = "Detects Locky ransomware"
        author = "Amaru Project"
        reference = "https://www.cyber.gov.au/acsc/view-all-content/alerts/locky-ransomware-targeting-organisations-through-phishing-emails"
        confidence = "high"
        severity = "critical"
    
    strings:
        $s1 = "locky" nocase wide ascii
        $s2 = "_LOCKY_" nocase wide ascii
        $s3 = ".locky" nocase wide ascii
        $s4 = ".zepto" nocase wide ascii
        $s5 = ".odin" nocase wide ascii
        $s6 = ".aesir" nocase wide ascii
        $s7 = ".thor" nocase wide ascii
        $s8 = ".osiris" nocase wide ascii
        
        $instruction1 = "LOCKY-DECRYPT.txt" wide ascii
        $instruction2 = "_Locky_recover_instructions.txt" wide ascii
        $instruction3 = "_HELP_instructions.html" wide ascii
        
        $encryption = { 83 C4 04 84 C0 74 ?? BE ?? ?? ?? ?? 89 74 24 ?? FF 15 }
        
    condition:
        uint16(0) == 0x5A4D and 
        filesize < 2MB and 
        ((2 of ($s*)) or (any of ($instruction*)) or $encryption)
}

rule Ransomware_Ryuk {
    meta:
        description = "Detects Ryuk ransomware"
        author = "Amaru Project"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-302a"
        confidence = "high"
        severity = "critical"
    
    strings:
        $s1 = "RyukReadMe.txt" wide ascii
        $s2 = "ryuk" nocase wide ascii
        $s3 = "UNIQUE_ID_DO_NOT_REMOVE" wide ascii
        $s4 = "-ryuk" wide ascii
        $s5 = "RyukMasterKey" wide ascii
        
        $code1 = { 8B 55 FC 83 C2 01 89 55 FC 8B 45 FC 3B 45 F4 7C ?? }
        $code2 = { 68 E8 03 00 00 FF 15 ?? ?? ?? ?? 33 C0 5E 5B 83 C4 18 }
        
        $ransom_note = "Balance of Shadow Universe" wide ascii
        
    condition:
        uint16(0) == 0x5A4D and 
        filesize < 5MB and 
        ((2 of ($s*)) or (all of ($code*)) or ($ransom_note and any of ($s*)))
} 
rule Updated_ransomware_20250319_23001 {
    meta:
        description = "Updated rule for ransomware"
        author = "Amaru Team"
        severity = "medium"
        date = "2025-03-19"
    strings:
        $s1 = "new_malicious_pattern" nocase
    condition:
        any of them
}
