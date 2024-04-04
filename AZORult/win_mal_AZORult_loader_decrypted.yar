rule win_mal_AZORult_loader_decrypted {
    meta:
        author = "RussianPanda"
        description = "Detects decrypted AZORult Loader"
        date = "4/4/2024"
        hash = "1901593e0299930d46b963866f33a93b"
    strings:
        $s1 = {73 00 64 00 32 00 2E 00 70 00 73 00 31 00}
        $s2 = {25 00 74 00 65 00 6D 00 70 00 25 00 5C 00 25 00 70 00 61 00 74 00 68 00 73 00 25}
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}

