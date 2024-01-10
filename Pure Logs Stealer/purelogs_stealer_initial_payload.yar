rule purelogs_stealer_initial_dropper {
	meta:
	        author = "RussianPanda"
	        decription = "Detects PureLogs Stealer"
	        reference = ""
	        date = "1/9/2024"

	strings:
	        $s1 = {73 ?? 00 00 06 28 ?? 00 00 ?? 2A}
	        $s2 = {28 ?? 00 00 06 74 ?? 00 00 1B 28 ?? 00 00 0A 2A}
	        $s3 = {28 ?? 00 00 ?? 75 ?? 00 00 01 72 ?? 00 00 70 6F ?? 00 00 0A 2A}
	        $s4 = {28 ?? 00 00 ?? 75 ?? 00 00 01 72 ?? 00 00 ?? 20 00 01 00 00 14 14 14 6F ?? 00 00 ?? 26}
	        $s5 = {28 ?? 00 00 ?? 73 ?? 00 00 [29] 73 15 00 00 0A [22] 28 01 00 00 2B 28 02 00 00 2B}
       

 	condition:
		all of ($s*)
        	and uint16(0) == 0x5A4D and filesize < 900KB
		
}
