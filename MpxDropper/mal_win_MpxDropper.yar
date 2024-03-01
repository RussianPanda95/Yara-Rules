rule win_mal_MpxDropper {
    meta:
        author = "RussianPanda"
        description = "Detects MpxDropper"
        date = "3/1/2024"
        hash = "3a44a45afbfe5fc7cdeb3723e05c4e892b079abdb7d1e8d6fc70496ef0a14d5d"
    strings:
        $s1 = {43 3a 5c 55 73 65 72 73 5c 6d 70 78 31 36 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73}
    condition:
        uint16(0) == 0x5A4D and all of them
}

