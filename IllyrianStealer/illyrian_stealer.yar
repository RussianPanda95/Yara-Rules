import "pe"
rule IllyrianStealer {

	meta:
		author = "RussianPanda"
		decription = "Detects Illyrian Stealer"
		date = "1/8/2024"
		hash = "fae0aed6173804e8c22027cbb0c121eedd927f16ea7e2b23662dbe6e016980e8"
	strings:
	        $s1 = "get_TotalPhysicalMemory"
	        $s2 = "\\b(bitcoincash)[a-zA-HJ-NP-Z0-9]{36,54}\\b" wide
	        $s3 = "[Crypto]" wide
	        $s4 = "|Black|" wide
 	condition:
		all of ($s*)
		and filesize < 50KB
    		and pe.imports("mscoree.dll") 
}
