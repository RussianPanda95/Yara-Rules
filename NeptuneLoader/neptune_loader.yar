rule neptune_loader {
    meta:
        description = "Detects Neptune Loader"
        author = "RussianPanda"
        date = "2024-01-17"

    strings:
        $s1 = {8B C6 E8 F4 FB FF FF}
        $s2 = {66 33 D1 66 89 54 58 FE}
        $s3 = {7C 53 74 61 72 74 75 70 46 6F 6C 64 65 72 7C}
        $s4 = {44 65 6C 70 68 69}
        $t1 = {C7 [3] 0B 40 40 00 [6] A1 ?? 61 40 00}
        $t2 = {C7 ?? 24 00 40 40 00 A1 ?? 61 40 00}
        $t3 = {8B ?? ?? FF D0 B8}

    condition:
        3 of ($s*) or 2 of ($t*) and filesize < 6MB
}
