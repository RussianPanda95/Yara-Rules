rule mal_nitrogen {
    meta:
        author = "RussianPanda"
        description = "Detects Nitrogen campaign"
        date = "2/4/2024"
    strings:
        $s1 = {63 7C 77 7B F2 6B 6F C5}
        $s2 = {52 09 6A D5 30 36 A5 38}
        $s3 = {6F 72 69 67 69 6E 61 6C 5F 69 6E 73 74 61 6C 6C}
        $s4 = {43 3A 5C 55 73 65 72 73 5C 50 75 62 6C 69 63 5C 44 6F 77 6E 6C 6F 61 64}
        $s5 = {25 00 43 00 55 00 52 00 52 00 45 00 4E 00 54 00 5F 00 44 00 45 00 52 00 45 00 43 00 54 00 4F 00 52 00 59 00 25}
    condition:
        uint16(0) == 0x5A4D and all of them
}
