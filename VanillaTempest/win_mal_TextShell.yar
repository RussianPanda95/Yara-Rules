rule TextShell {
    meta:
        description = "Detects TextShell Obfsucator"
        author = "RussianPanda"
        date = "2025-10-31"
        hash = "cf44aa11a17b3dad61cae715f4ea27c0cbf80732a1a7a1c530a5c9d3d183482a"
    strings:
        $s1 = {41 8B 04 84 48 03 ?? EB}
        $s2 = {41 3B ?? 74 ?? FF C3 3B 5D 18 72}
        $s3 = {FF 15 ?? ?? ?? ?? 48 8B}
    condition:
        uint16(0) == 0x5A4D and all of them and #s3 > 1000
}
