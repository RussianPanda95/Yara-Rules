rule win_mal_XWorm {
    meta:
        author = "RussianPanda"
        description = "Detects XWorm RAT"
        date = "3/11/2024"
        hash = "fc422800144383ef6e2e0eee37e7d6ba"
    strings:
        $s1 = {4D 00 6F 00 64 00 69 00 66 00 69 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6C 00 6C 00 79 00 21}
        $s2 = {50 00 6C 00 75 00 67 00 69 00 6E 00 73 00 20 00 52 00 65 00 6D 00 6F 00 76 00 65 00 64 00 21}
        $s3 = {73 00 65 00 6E 00 64 00 50 00 6C 00 75 00 67 00 69 00 6E}
        $s4 = {4D 00 6F 00 64 00 69 00 66 00 69 00 65 00 64 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6C 00 6C 00 79 00 21}
        $s5 = "_CorExeMain"
    condition:
        uint16(0) == 0x5A4D and all of them
}

