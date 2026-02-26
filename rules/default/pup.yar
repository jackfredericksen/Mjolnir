rule PUP_KeyLogger : medium
{
    meta:
        description = "Detects potential keylogger behavior"
        severity = "medium"
        author = "Mjolnir"

    strings:
        $api1 = "SetWindowsHookEx" ascii wide
        $api2 = "GetAsyncKeyState" ascii wide
        $api3 = "GetKeyState" ascii wide
        $api4 = "GetKeyboardState" ascii wide
        $api5 = "RegisterRawInputDevices" ascii wide
        $log1 = "keylog" ascii wide nocase
        $log2 = "keystroke" ascii wide nocase

    condition:
        (2 of ($api*)) or (any of ($api*) and any of ($log*))
}

rule PUP_ScreenCapture : low
{
    meta:
        description = "Detects screen capture capabilities"
        severity = "low"
        author = "Mjolnir"

    strings:
        $api1 = "BitBlt" ascii wide
        $api2 = "GetDesktopWindow" ascii wide
        $api3 = "GetWindowDC" ascii wide
        $api4 = "CreateCompatibleBitmap" ascii wide
        $save = "screenshot" ascii wide nocase

    condition:
        (3 of ($api*)) or (2 of ($api*) and $save)
}

rule EICAR_Test_File : low
{
    meta:
        description = "EICAR antivirus test file"
        severity = "low"
        author = "EICAR"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii

    condition:
        $eicar
}
