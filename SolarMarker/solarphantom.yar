rule SolarPhantom {

	meta:
		author = "RussianPanda"
		reference = "https://www.esentire.com/blog/solarmarker-to-jupyter-and-back"
		description = "SolarPhantom Backdoor Detection"

	strings:
		$p1 = {B8 94 E3 46 00 E8 C6 EB FA FF 8B 45 F8}
		$p2 = {68 E8 EF 46 00 FF 75 E4}
		$p3 = {62 72 76 70 72 66 5f 62 6b 70}
	condition:
		uint16(0) == 0x5A4D and 1 of ($p*)
		and filesize < 600KB
		
}

 
