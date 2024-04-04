rule win_mal_AZORult_loader {
    meta:
        author = "RussianPanda"
        description = "Detects AZORult Loader"
        date = "4/4/2024"
        hash = "47e208687c2fb40bdbaa17e368aaa1bd"
    strings:
        $s1 = {27 11 68 05}
        $s2 = {15 B1 B3 09}
        $s3 = {B5 96 AA 0D}
        $s4 = {74 [0-10] C1 E9 18}
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}
