rule win_mal_KoiStealer_PS {
    meta:
        author = "RussianPanda"
        description = "Detects KoiStealer PowerShell script"
        date = "4/4/2024"
        hash = "4f55be0b55ec67dfda42b88e9c743a2a"
    strings:
        $s1 = "index.php?id=$guid&subid="
        $s2 = "$config"
    condition:
        all of ($s*)
}

