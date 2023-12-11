import "pe"

rule AndeLoader {

	meta:
		author = "RussianPanda"
		decription = "Detects Ande Loader"
		date = "12/11/2023"

	strings:
		$s1 = {59 61 6E 6F 41 74 74 72 69 62 75 74 65} 
		$s2 = "CreateShortcut" wide
		$s3 = ".vbs" wide
		
	condition:
		3 of ($s*)
		and pe.imports("mscoree.dll")
}
