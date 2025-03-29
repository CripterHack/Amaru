// Backdoor detection rules will be placed here
rule Updated_backdoors_20250319_34874 {
    meta:
        description = "Updated rule for backdoors"
        author = "Amaru Team"
        severity = "medium"
        date = "2025-03-19"
    strings:
        $s1 = "new_malicious_pattern" nocase
    condition:
        any of them
}
