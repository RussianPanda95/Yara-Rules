import "pe"

rule SwaetRAT {

	meta:
		author = "RussianPanda"
		decription = "Detects SwaetRAT"
    		date = "11/27/2023"

	strings:
		$s2 = "Pong"
		$s3 = "ReadData"
		$s4 = "DeskDrop" wide
		$s5 = "OfflineGet" wide
		
	condition:
		all of ($s*)
		and pe.imports("mscoree.dll")
}
