rule WhiteSnakeStealer {

	meta:
		author = "RussianPanda"
		reference = "https://russianpanda.com/2023/07/04/WhiteSnake-Stealer-Malware-Analysis/"
		description = "Detects WhiteSnake Stealer XOR samples " 
		date = "7/4/2023"

	strings:
		$s1 = {FE 0C 00 00 FE 09 00 00 FE 0C 02 00 6F ?? 00 00 0A FE 0C 03 00 61 D1 FE 0E 04 00 FE}
		$s2 = {61 6e 61 6c 2e 6a 70 67}
	condition:
		all of ($s*) and filesize < 600KB

}

