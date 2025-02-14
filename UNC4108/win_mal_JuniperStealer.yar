rule win_mal_JuniperStealer {
    meta:
        description = "Detects Juniper Stealer"
        author = "RussianPanda"
        date = "2025-2-13"
        hash = "44dc2777ee8dd6d5cd8ebb10e71caf73b330940131417b5fca2b174a264e19e3"
    strings:
        $s1 = "OutlookDecryptPwd" 
        $s2 = "CookiesNew"
        $s3 = "Cookies128"
        $s4 = "mscoree.dll"
    condition:
        uint16(0) == 0x5A4D and all of them
}
