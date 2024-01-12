rule SmartApeSG_JS_NetSupportRAT_stage2 {
    meta:
        author = "RussianPanda"
        description = "Detects SmartApeSG JavaScript Stage 2 retrieving NetSupportRAT"
        date = "1/11/2024"
        modified = "1/12/2024"
        hash = "67d8f84b37732cf85e05b327ad6b6a9f"
    strings:
        $x1 = "powershell.exe -Ex Bypass -NoP -C $"
        $x2 = "Get-Random -Minimum -1000 -Maximum 1000"

        $s1 = "HKCU:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
        $s2 = "=new ActiveXObject('W"
        $s3 = "System.Net.WebClient).DownloadString($"
        $s4 = "FromBase64String"
        $s5 = "Start-Process -FilePath $"
    condition:
        filesize < 1MB 
        and (
            ( 1 of ($x*) and 3 of them )
            or 5 of them
        )
}
