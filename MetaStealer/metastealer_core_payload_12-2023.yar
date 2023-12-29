import "pe"
rule MetaStealer_core_payload {

	meta:
		author = "RussianPanda"
		decription = "Detects MetaStealer Core Payload"
		date = "12/29/2023"

	strings:
		$s1 = "FileScannerRule"
		$s2 = "TreeObject"
		$s3 = "Schema"
		$s4 = "StringDecrypt"
		$s5 = "AccountDetails"
			
	condition:
		4 of ($s*) 
		and pe.imports("mscoree.dll")
}