rule win_mal_Zloader {
    meta:
        author = "RussianPanda"
        description = "Detects Zloader and possibly other Zloader modules that employ the same encryption"
        date = "3/10/2024"
    strings:
        $s1 = {8B 45 ?? 89 45 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C1 8B 45 ?? 99 F7 F9 8B 45 ?? 48 63 D2 48 8D 0D ?? ?? ?? 00 0F BE 0C 11 31 C8 88 C2 48 8B 45 F0 48 63 4D}
        $s2 = {48 63 C9 44 0F B6 04 08 48 8B 45 E8 8B 4D D4 0F B6 14 08 44 31 C2 88 14 08 8B 45 D4}
        $s3 = {B9 11 00 00 00 99 F7 F9 8B [0-20] 31 C8 88 C2}
    condition:
        uint16(0) == 0x5A4D and any of them
}

