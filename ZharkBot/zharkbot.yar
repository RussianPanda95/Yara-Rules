rule ZharkBot {
    meta:
        description = "Detects ZharkBot"
        author = "RussianPanda"
        date = "2024-01-21"
        reference = "https://x.com/ViriBack/status/1749184882822029564?s=20"
        hash = "d53ce8c0a8a89c2e3eb080849da8b1c47eaac614248fc55d03706dd5b4e10bdd"

    strings:
        $s1 = {F7 EA C1 FA 04 8B C2 C1 E8 1F 03 C2 8B 55 ?? 0F BE C0 8A CA 6B C0 ?? 2A C8 80 C1}
        $s2 = {F7 E2 C1 EA 04 0F BE C2 8B 55 ?? 8A CA 6B C0 ?? 2A C8 80 C1 ?? 30 8C 15}

    condition:
        uint16(0) == 0x5A4D and #s1 > 10 and #s2 > 10 and filesize < 500KB
}
