rule Trojan_Generic_ProcessInjection : high
{
    meta:
        description = "Detects process injection patterns"
        severity = "high"
        author = "Mjolnir"

    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtCreateThreadEx" ascii wide
        $api5 = "RtlCreateUserThread" ascii wide

    condition:
        ($api1 and $api2 and ($api3 or $api4 or $api5))
}

rule Trojan_Generic_Shellcode : high
{
    meta:
        description = "Detects common shellcode patterns"
        severity = "high"
        author = "Mjolnir"

    strings:
        $shellcode1 = { FC E8 ?? ?? ?? ?? }  // call $+5 pattern
        $shellcode2 = { 31 C9 64 8B 41 30 }  // xor ecx; mov eax, fs:[ecx+0x30] (PEB access)
        $shellcode3 = { 64 A1 30 00 00 00 }  // mov eax, fs:[0x30] (PEB access x86)
        $shellcode4 = { 65 48 8B 04 25 60 00 00 00 } // mov rax, gs:[0x60] (PEB access x64)

    condition:
        any of them
}
