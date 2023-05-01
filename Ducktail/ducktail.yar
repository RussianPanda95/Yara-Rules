rule Ducktail {
	meta:
		author = "RUPanda"
		description = "Ducktail Infostealer" 
		date = "4/25/2023"
	strings:
		$s = {65 5f 73 71 6c 69 74 65 33 2e 64 6c 6c}
		$s1 = {54 65 6c 65 67 72 61 6d 2e 42 6f 74 2e 64 6c 6c}
		$s2 = {4e 65 77 74 6f 6e 73 6f 66 74 2e 4a 73 6f 6e 2e 64 6c 6c}
		$s3 = {42 6f 75 6e 63 79 43 61 73 74 6c 65 2e 43 72 79 70 74 6f 2e 64 6c 6c}
		$s4 = {53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 53 6f 63 6b 65 74 73 2e 43 6c 69 65 6e 74 2e 64 6c 6c}
		$s5 = {53 79 73 74 65 6d 2e 4e 65 74 2e 4d 61 69 6c 2e 64 6c 6c}
	condition:
		all of them and filesize > 60MB

}
