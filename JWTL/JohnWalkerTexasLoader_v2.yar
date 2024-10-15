rule JohnWalkerTexasLoader_v2 {

    meta:
        description = "Detects JohnWalkerTexasLoader (JWTL)"
        author = "RussianPanda"
        date = "2024-10-15"
        hash = "9f6bf0473f5541d84faad4c33a0bc5b1928fceb5938f2d6a7e6e02b7f0980341"

    strings:
        $s1 = {61 00 48 00 52 00 30 00 63 00 48 00 4D 00 36 00 4C 00 79 00 39}
        $s2 = {73 65 6E 64 6F 70 65 6E 31}
        $s3 = {73 65 6E 64 6F 70 65 6E 32}

    condition:
        uint16(0) == 0x5A4D and all of them
}
