rule win_mal_StealC_v2 {
    meta:
        author = "RussianPanda"
        description = "Detects StealC v2"
        hash = "bc7e489815352f360b6f0c0064e1d305db9150976c4861b19b614be0a5115f97"
        date = "4/10/2025"
    strings:
        $s1 = {48 8d ?? ?? ?? ??  00 48 8d}
        $s2 = {0F B7 C8 81 E9 19 04 00 00 74 14 83 E9 09 74 0F 83 E9 01 74 0A 83 E9 1C 74 05 83 F9 04 75 08}
    condition:
        uint16(0) == 0x5A4D and #s1 > 500 and all of them and filesize < 900KB
}
