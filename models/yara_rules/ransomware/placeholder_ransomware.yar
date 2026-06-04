rule NovaSentinel_Placeholder_Ransomware
{
    meta:
        author = "NovaSentinel"
        description = "Placeholder ransomware YARA rule for community rule directory structure."
        reference = "https://novasentinel.io"
    strings:
        $placeholder_text = "NovaSentinel-Ransomware-Placeholder-Rule-2026"
    condition:
        $placeholder_text
}
