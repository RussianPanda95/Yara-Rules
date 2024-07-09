rule GhostGambit {
    meta:
        description = "Detects GhostGambit dropper"
        author = "RussianPanda"
        date = "2024-07-09"
        hash = "2b16c68d9bafbd2ecf3634d991d7c794"
    strings:
        $s1 = "/code32" ascii wide
        $s2 = "/reg32" ascii wide
        $s3 = "ZhuDongFangYu.exe" ascii wide
        $s4 = "/c ping -n 4 127.0.0.1 > nul && del" ascii wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
