rule prysmax_stealer {
	meta:
	        author = "RussianPanda"
	        decription = "Detects Prysmax Stealer"
	        reference = "https://www.cyfirma.com/outofband/new-maas-prysmax-launches-fully-undetectable-infostealer/"
	        date = "1/9/2024"
        
	strings:
	        $a1 = {23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23 23}
	        $s2 = {73 70 72 79 73 6D 61 78}
	        $s3 = {56 43 52 55 4E 54 49 4D 45 31 34 30 2E 64 6C 6C}
	        $s4 = {56 43 52 55 4E 54 49 4D 45 31 34 30 5F 31 2E 64 6C 6C}
	        $s5 = {4D 53 56 43 50 31 34 30 2E 64 6C 6C}
	        $s6 = {50 79 49 6E 73 74 61 6C 6C 65 72}
	        
 	condition:
		all of ($s*)
	        and uint16(0) == 0x5A4D and $a1 in (9600000..filesize) and #a1 > 600
	        and filesize > 60MB and filesize < 200MB
			
