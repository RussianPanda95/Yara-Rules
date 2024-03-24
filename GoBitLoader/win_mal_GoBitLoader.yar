rule win_mal_GoBitLoader {
    meta:
        author = "RussianPanda"
        description = "Detects GoBitLoader"
        reference = "https://www.malwarebytes.com/blog/threat-intelligence/2024/03/new-go-loader-pushes-rhadamanthys"
        date = "3/24/2024"
    strings:
        $s1 = {6D 61 69 6E 2E 52 65 64 69 72 65 63 74 54 6F 50 61 79 6C 6F 61 64}
        $s2 = {6D 61 69 6E 2E 48 6F 6C 6C 6F 77 50 72 6F 63 65 73 73}
        $s3 = {6D 61 69 6E 2E 41 65 73 44 65 63 6F 64 65 2E 66 75 6E 63 31}
    condition:
        uint16(0) == 0x5A4D and all of them
}

