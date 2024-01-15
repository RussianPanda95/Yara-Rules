rule DarkVNC {
	meta:
		author = "RussianPanda"
		description = "Detects DarkVNC"
		date = "1/15/2024"
		hash = "3c74dccd06605bcf527ffc27b3122959"
	strings:
		$s1 = {66 89 84 24 ?? 00 00 00 B8 ?? 00 00 00}
		$s2 = {66 31 14 41 48}
		$s3 = "VncStopServer"
		$s4 = "VncStartServer"
	condition:
		uint16(0) == 0x5A4D and
		3 of them and filesize < 700KB
}
