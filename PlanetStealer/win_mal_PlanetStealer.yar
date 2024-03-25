rule win_mal_PlanetStealer {
    meta:
        author = "RussianPanda"
        description = "Detects PlanetStealer"
        date = "3/4/2024"
    strings:
        $s1 = {48 8D 15 ?? ?? ?? 00 0F B6 34 10 0F B6 BC 04 ?? ?? 00 00 ?? ?? 40 88 ?? 04 ?? ?? 00 00 48 FF C0}
        $s2 = {48 83 F8 ?? 7C DA}
        $s3 = {72 75 6E 74 69 6D 65 2E 67 6F 62 75 66}
        $s4 = {74 6F 74 61 6C 5F 77 61 6C 6C 65 74 73}
        $s5 = {74 6F 74 61 6C 5F 63 6F 6F 6B 69 65 73}
    condition:
        uint16(0) == 0x5A4D and all of them and #s2 > 100 and #s1 > 100 and filesize < 20MB
}

