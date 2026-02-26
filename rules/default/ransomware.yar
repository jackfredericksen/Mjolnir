rule Ransomware_Generic_CryptoAPI : critical
{
    meta:
        description = "Detects ransomware-like cryptographic API usage patterns"
        severity = "critical"
        author = "Mjolnir"

    strings:
        $crypto1 = "CryptEncrypt" ascii wide
        $crypto2 = "CryptGenKey" ascii wide
        $crypto3 = "CryptImportKey" ascii wide
        $crypto4 = "BCryptEncrypt" ascii wide
        $file1 = "FindFirstFile" ascii wide
        $file2 = "FindNextFile" ascii wide
        $ransom1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $ransom2 = "bitcoin" ascii wide nocase
        $ransom3 = ".onion" ascii wide
        $ransom4 = "decrypt" ascii wide nocase
        $ext1 = ".encrypted" ascii wide
        $ext2 = ".locked" ascii wide
        $ext3 = ".crypto" ascii wide

    condition:
        (2 of ($crypto*)) and (any of ($file*)) and (any of ($ransom*) or any of ($ext*))
}

rule Ransomware_ShadowCopy_Delete : critical
{
    meta:
        description = "Detects Volume Shadow Copy deletion (common in ransomware)"
        severity = "critical"
        author = "Mjolnir"

    strings:
        $cmd1 = "vssadmin delete shadows" ascii wide nocase
        $cmd2 = "wmic shadowcopy delete" ascii wide nocase
        $cmd3 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $cmd4 = "wbadmin delete catalog" ascii wide nocase

    condition:
        any of them
}
