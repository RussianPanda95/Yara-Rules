rule win_mal_Matanbuchus_loader {
    meta:
        author = "RussianPanda"
        description = "Detects Matanbuchus 3.0 Loader component"
        date = "2/15/2025"
		    hash = "ec29bcda7d42d812aebd2ee5be6e43256bcf6095b9fc36f92eec5d6475dd5e1f"
    strings:
        $s1 = {FF E0 F5 05 EB 0F}
		    $s2 = {65 78 70 61}
		    $s3 = {6E 64 20 33}
		    $s4 = {66 89 ?? ?? ?? ?? 00 00 00 66 89 ?? ?? ?? ?? 00 00 00 66 89}
		    $s5 = {E8 00 00 00 00 83 04 24 05 CB}  
    condition:
        uint16(0) == 0x5A4D and 4 of them and filesize < 250KB
}
