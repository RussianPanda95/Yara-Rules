import "pe"
rule IllyrianStealer {

	meta:
		author = "RussianPanda"
		decription = "Detects Illyrian Stealer"
		date = "1/8/2024"

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
