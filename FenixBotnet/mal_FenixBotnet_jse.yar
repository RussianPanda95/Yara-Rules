rule mal_FenixBotnet_jse {
    meta:
        description = "Detects Fenix Botnet JSE downloader"
        author = "RussianPanda"
        date = "2024-01-18"

    strings:
        $s1 = {76 61 72 20 [0-30] 3D 20 22 66 22}
        $s2 = {76 61 72 20 [0-30] 3D 20 22 75 22}
        $s3 = {76 61 72 20 [0-30] 3D 20 22 6E 22}
        $s4 = {6E 65 77 20 46 75 6E 63 74 69 6F 6E 28 64 65 63 6F 64 65 55 52 49 43 6F 6D 70 6F 6E 65 6E 74 28 [0-30] 29 29 2E 63 61 6C 6C 28 29}
        
    condition:
        all of ($s*) and filesize < 500KB
}
