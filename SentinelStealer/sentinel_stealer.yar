rule sentinel_stealer {
    meta:
        description = "Detects Sentinel Stealer"
        author = "RussianPanda"
        date = "2024-01-19"
        hash = "3a540a8a81c5a5b452f154d7875423a3"
    
    strings:
        $s1 = "Sentinel.SmallerEncryptedIcon" wide
        $s2 = "SentinelSteals" wide
        $s4 = "_CorExeMain"
    condition:
        all of them
}
