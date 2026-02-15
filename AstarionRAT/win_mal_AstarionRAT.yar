rule win_mal_AstarionRAT {
    meta:
        author = "RussianPanda"
        description = "Detects AstarionRAT"
        date = "2/14/2025"
		hash = "a508d0bb583dc6e5f97b6094f8f910b5b6f2b9d5528c04e4dee62c343fce6f4b"
    strings:
        $s1 = "s5://%s:%s@%s:%d"
        $s2 = "Failed to connect to the server"
		$s3 = "Impersonated"
    condition:
        uint16(0) == 0x5A4D and all of them
}
