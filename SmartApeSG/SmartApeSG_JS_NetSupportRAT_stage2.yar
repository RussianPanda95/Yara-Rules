rule SmartApeSG_JS_NetSupportRAT_stage2 {
    meta:
        author = "RussianPanda"
        description = "Detects SmartApeSG JavaScript Stage 2 retrieving NetSupportRAT"
        date = "1/11/2024"
    strings:
        $s1 = "HKCU:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
        $s2 = "client32.exe"
        $s3 = ".zip"
        $s4 = "Get-Random -Minimum -1000 -Maximum 1000"
        $s5 = "FromBase64String"
    condition:
         all of ($s*) and filesize < 1MB 
}


