rule win_mal_PreGrabber {
    meta:
        description = "Detects Pregrabber Plugin"
        author = "RussianPanda"
        date = "2024-2-13"
        hash = "f39319312a567fa771921d11ece66f3ce8996ba45f90d6fc89031b621535eb7e"
    strings:
        $s1 = "msgPack"
        $s2 = "HandlePreGrabber"
        $s3 = "bdos"
        $s4 = "uniqueid"
        $s5 = "mtx"
        $s6 = "install"
        $s7 = "mscoree.dll"
    condition:
        uint16(0) == 0x5A4D and all of them
}
