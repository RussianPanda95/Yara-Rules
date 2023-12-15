import "pe"

rule WorkersDevBackdoor {

	meta:
		author = "RussianPanda"
		decription = "Detects WorkersDevBackdoor"
		date = "12/15/2023"

	strings:
		$s1 = {72 03 00 00 70 06 28 0B 00 00 0A 28 0C 00 00 0A 0B}
		$s2 = {72 C3 00 00 70 7E 05 00 00 04 28 17 00 00 06 28 14 00 00 0A 0C}
		$s3 = {43 00 4F 00 4D 00 50 00 55 00 54 00 45 00 52 00 4E 00 41 00 4D 00 45}
		$s4 = {55 00 53 00 45 00 52 00 44 00 4F 00 4D 00 41 00 49 00 4E}
		
	condition:
		all of ($s*)
		and pe.imports("mscoree.dll")
}
