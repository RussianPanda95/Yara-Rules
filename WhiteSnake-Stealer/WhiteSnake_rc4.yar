rule WhiteSnakeStealer {

	meta:
		author = "RussianPanda"
		reference = "https://russianpanda.com/2023/07/04/WhiteSnake-Stealer-Malware-Analysis/"
		description = "WhiteSnake Stealer" 
		date = "7/4/2023"

	strings:
		$s1 = {73 68 69 74 2e 6a 70 67}
		$s2 = {FE 0C ?? 00 20 00 01 00 00 3F ?? FF FF FF 20 00 00 00 00 FE 0E ?? 00 38 ?? 00 00 00 FE 0C}
		$s3 = "qemu" wide
		$s4 = "vbox" wide
	condition:
		all of ($s*) and filesize < 300KB

}

