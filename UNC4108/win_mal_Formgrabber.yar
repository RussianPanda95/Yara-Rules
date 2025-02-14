rule win_mal_Formgrabber {
    meta:
        description = "Detects Formgrabber Plugin"
        author = "RussianPanda"
        date = "2024-2-13"
        hash = "33ea72b46af7bb2ecc0775f7536d3259f34bd7a13e298cac66649ee694097c2e"
    strings:
        $s1 = "frmgrb"
        $s2 = "WebfakeRecords"
        $s3 = "urlblocklist"
        $s4 = "mscoree.dll"
    condition:
        uint16(0) == 0x5A4D and all of them
}
