rule MetaStealer_NET_Reactor_packer {
    meta:
        author = "RussianPanda"
        description = "Detects NET_Reactor_packer 12-2023 used in MetaStealer"
        date = "12/29/2023"

    strings:
        $s1 = {C7 84 24 80 02 00 00 24 02 00 00 C6 44 24}
		$s2 = "mscoree.dll" wide
		$s3 = {43 61 76 69 6c 73 20 43 6f 72 70 2e 20 32 30 31 30}
		$s4 = {80 F1 E7 80 F2 44 [16] 80 F1 4B 80 F2 23}

    condition:
        3 of ($s*) and filesize < 600KB
		
}
