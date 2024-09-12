rule LummaC2 {
    meta:
        description = "Detects LummaC2 Stealer"
        author = "RussianPanda"
        date = "2024-09-12"
        hash = "988f54f9694dd1ae701bacec3b83c752"

    strings:
        $s1 = {0F B6 [2-6] 83 ?? 1F} // Decrypting the C2s
        $s2 = {F3 A5 8B 74 24 F8 8B 7C 24 F4 8D 54 24 04 FF 54 24 FC C3} // Heaven's Gate

    condition:
        uint16(0) == 0x5A4D and all of them
}

