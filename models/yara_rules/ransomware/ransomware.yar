rule Ransomware_Common_Strings {
    meta:
        description = "Detects common ransomware strings and behaviors"
        author = "NovaSentinel"
        severity = "high"

    strings:
        $s1 = "Your files have been encrypted" nocase
        $s2 = "decrypt your files" nocase
        $s3 = "private key" nocase
        $s4 = "bitcoins" nocase
        $s5 = ".encrypted" nocase
        $s6 = "README_FOR_DECRYPT" nocase
        $s7 = "vssadmin.exe delete shadows" nocase
        $s8 = "bcdedit /set {default} recoveryenabled no" nocase
        $s9 = "cryptovariable" nocase

    condition:
        2 of them
}

rule Generic_Ransomware_API {
    meta:
        description = "Detects APIs commonly used by ransomware for encryption and shadow copy deletion"
    
    strings:
        $a1 = "CryptEncrypt"
        $a2 = "CryptGenKey"
        $a3 = "CryptExportKey"
        $a4 = "DeviceIoControl"
        $a5 = "ShellExecute"
        $a6 = "CreateProcess"

    condition:
        all of ($a1, $a2, $a3) and (1 of ($a4, $a5, $a6))
}
