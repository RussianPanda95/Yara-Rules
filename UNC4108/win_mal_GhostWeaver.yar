rule win_mal_GhostWeaver {
    meta:
        description = "Detects GhostWeaver backdoor"
        author = "RussianPanda"
        date = "2025-2-15"
        hash = "5051f0aa11da67e16797daa51992467ad45c5bf18dcd2e252e8aa63d3fce31bc"
    strings:
        $s1 = "$global:keystr"
        $s2 = "stub"
        $s3 = "ForEach-Object"
    condition:
        all of them and filesize < 1MB and @s3 > 100
}
