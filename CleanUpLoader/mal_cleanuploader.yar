rule mal_cleanuploader {
    meta:
        description = "Detects CleanUpLoader"
        author = "RussianPanda"
        date = "2024-02-14"
        reference = "https://x.com/AnFam17/status/1757871703282077857?s=20"
        hash = "2b62dd154b431d8309002d5b4a35de07"
    strings:
        $s1 = {0F B6 80 30 82 42 00 88}
        $s2 = {44 69 73 6B 43 6C 72}
        $s3 = {49 00 6E 00 73 00 74 00 61 00 6C 00 6C 00 20 00 45 00 64 00 67 00 65}
    condition:
        uint16(0) == 0x5A4D and all of them and #s1 > 15
}
