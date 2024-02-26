rule win_mal_D3Fack_Loader {
    meta:
        author = "RussianPanda"
        description = "Detects D3F@ck Loader"
        date = "2/25/2024"
    strings:
        $s1 = {64 61 74 61 2F [1-15] 2F [1-15] 2E 65 78 65}
        $s2 = {65 78 65 63 75 74 65 50 6F 77 65 72 53 68 65 6C 6C 43 6F 6D 6D 61 6E 64}
        $s3 = {64 6F 77 6E 6C 6F 61 64 41 6E 64 52 75 6E 46 69 6C 65}
    condition:
        all of them
}

