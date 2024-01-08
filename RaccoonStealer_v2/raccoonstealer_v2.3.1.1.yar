rule RaccoonStealer {

	meta:
		author = "RussianPanda"
		decription = "Detects Raccoon Stealer v2.3.1.1"
        	reference = "https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-raccoon-stealer-v2-0"
		date = "1/8/2024"
	strings:
	        $s1 = {8B 0D [2] 41 00 A3 [3] 00}
	        $s2 = "MachineGuid"
	        $s3 = "SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards"
	        $s4 = "SELECT service, encrypted_token FROM token_service"
	        $s5 = "&configId="
	        $s6 = "machineId="
 	condition:
		all of ($s*) and #s1 > 10
        	and uint16(0) == 0x5A4D
		and filesize < 5MB
}
