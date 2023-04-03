rule PSWSTEALER {
	meta:
		author = "RUPanda"
		description = "PSWSTEALER" 
		date = "4/2/2023"
	strings:
		$obf = {09 20 FF [3] 5F 06 25 17 58 0A 61 1E 62 09 1E 63 06 25 17 58 0A 61 D2 60 D1 9D}
		$obf1 = {09 06 08 59 61 D2 13 04 09 1E 63 08 61 D2 13 05 07 08 11 05 1E 62 11 04 60 D1 9D 08 17 58 0C}
		$enc = {73 ?? 00 00 0A 73 ?? 00 00 0A}
		$s = {73 ?? 00 00 0A 0C 08 6F ?? 00 00 0A}

	condition:
		all of them and filesize < 200KB
}
