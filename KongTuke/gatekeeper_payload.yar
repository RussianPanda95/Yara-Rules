rule GateKeeperPayload {
    meta:
        author = "RussianPanda"
        description = "Detects GateKeeper payload used by KongTuke"
        date = "01/16/2026"
        hash = "f1f3cf076f8a6f3f5bac6a2a05d4883cc02919fbaf88a6826c86761a1d49f6e1"
    strings:
        $s1 = {68 00 00 00 79 00 00 00 70 00 00 00 65 00 00 00 72 00 00 00 64 00 00 00 62 00 00 00 67 00 00 00}
        $s2 = {64 00 00 00 6E 00 00 00 73 00 00 00 70 00 00 00 79 00 00 00}
        $s3 = "GetProcesses" ascii wide
        $s4 = "MainWindowTitle" ascii wide
        $s5 = "mscoree.dll"
    condition:
        all of ($s*) and filesize < 5MB
}
