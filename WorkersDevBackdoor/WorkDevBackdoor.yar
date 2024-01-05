import "pe"

rule WorkersDevBackdoor {

	meta:
		author = "RussianPanda"
		decription = "Detects WorkersDevBackdoor"
		date = "12/15/2023"

	strings:
		$s1 = {72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 20 00 7B 00 30 00 7D 00 20 00 7B 00 31 00 7D}
		$s2 = {72 FB 00 00 70 72 13 01 00 70 28 20 00 00 0A 72 2D 01 00 70}
		$s3 = {55 00 53 00 45 00 52 00 44 00 4F 00 4D 00 41 00 49 00 4E}
		$s4 = {43 00 4F 00 4D 00 50 00 55 00 54 00 45 00 52 00 4E 00 41 00 4D 00 45}
		
	condition:
		3 of ($s*)
		and pe.imports("mscoree.dll") 
		and filesize < 2MB
}
