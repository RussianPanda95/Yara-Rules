rule win_mal_mmgrabber {
    meta:
        description = "Detects mmgrabber Plugin"
        author = "RussianPanda"
        date = "2024-2-13"
        hash = "40ebd719aa66a88e261633887ed4e2c144bd11fbcc6f7793f9b32652cc5bf2d3"
    strings:
        $s1 = "GrabDesktopWallets"
        $s2 = "GrabChromeExtensions"
        $s3 = "FindExodusFolder"
        $s4 = "mscoree.dll"
    condition:
        uint16(0) == 0x5A4D and all of them
}
