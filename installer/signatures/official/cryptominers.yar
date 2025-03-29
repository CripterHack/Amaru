// Cryptominer detection rules will be placed here
rule Updated_cryptominers_20250319_59396 {
    meta:
        description = "Updated rule for cryptominers"
        author = "Amaru Team"
        severity = "medium"
        date = "2025-03-19"
    strings:
        $s1 = "new_malicious_pattern" nocase
    condition:
        any of them
}
