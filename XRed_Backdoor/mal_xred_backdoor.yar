rule mal_xred_backdoor {
    meta:
        description = "Detects XRed backdoor"
        author = "RussianPanda"
        date = "2024-02-09"
        hash = "9e1fbae3a659899dde8db18a32daa46a"

    strings:
        $s1 = {4B 65 79 62 6F 61 72 64 20 48 6F 6F 6B 20 2D 3E 20 41 63 74 69 76 65}
        $s2 = {54 43 50 20 43 6C 69 65 6E 74 20 2D 3E 20 41 6B 74 69 66}
        $s3 = {55 53 42 20 48 6F 6F 6B 73 20 2D 3E 20 41 63 74 69 76 65}
        $s4 = {45 58 45 55 52 4C 31}
        $s5 = {49 4E 49 55 52 4C 33}
        $s6 = {58 52 65 64 35 37}

    condition:
        uint16(0) == 0x5A4D and 3 of them
}

