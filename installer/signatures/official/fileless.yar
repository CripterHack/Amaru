// Fileless malware detection rules will be placed here
rule Updated_fileless_20250319_39803 {
    meta:
        description = "Updated rule for fileless"
        author = "Amaru Team"
        severity = "medium"
        date = "2025-03-19"
    strings:
        $s1 = "new_malicious_pattern" nocase
    condition:
        any of them
}
