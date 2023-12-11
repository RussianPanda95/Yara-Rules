rule MeduzaStealer {

	meta:
		author = "RussianPanda"
		reference = "https://russianpanda.com/2023/06/28/Meduza-Stealer-or-The-Return-of-The-Infamous-Aurora-Stealer/"
		description = "Detects MeduzaStealer" 
		date = "6/27/2023"

	strings:
		$s1 = {74 69 6D 65 7A 6F 6E 65}
		$s2 = {75 73 65 72 5F 6E 61 6D 65}
		$s3 = {67 70 75}
		$s4 = {63 75 72 72 65 6E 74 5F 70 61 74 68 28 29}
		$s5 = {C5 FD EF}
		$s6 = {66 0F EF}

	condition:
		all of them and filesize < 700KB
}

