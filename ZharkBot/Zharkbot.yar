rule ZharkBot {
    meta:
        description = "Detects ZharkBot, version 1.2.5"
        author = "RussianPanda"
        date = "2024-09-02"
        reference = "https://research.openanalysis.net/zharkbot/triage/x64dbg/2024/09/02/zharkbot-config.html"
        hash = "1aa0622a744ec4d28a561bac60ec5e907476587efbadfde546d2b145be4b8109"
      
    strings:
        $s1 = "^[a-z]{8}$"
        $s2 = "^d{6}$"

    condition:
        uint16(0) == 0x5A4D and all of them and filesize < 500KB
}

