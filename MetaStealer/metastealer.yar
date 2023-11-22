import "pe"
rule MetaStealer {

	meta:
		author = "RussianPanda"
    decription = "Detects MetaStealer"
		date = "11/16/2023"

	strings:
		$s1 = "FileScannerRule"
		$s2 = "MSObject"
		$s3 = "MSValue"
		$s4 = "GetBrowsers"
		$s5 = "Biohazard"
		
	condition:
		4 of ($s*) 
		and pe.imports("mscoree.dll")
}
