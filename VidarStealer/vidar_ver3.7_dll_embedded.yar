rule Vidar_DLL_embedded {

	meta:
		author = "RUPanda"
		description = "Vidar Stealer with embedded DLL dependencies" 
		date = "5/2/2023"

	strings:
		$s = {50 4B 03 04 14 00 00 00 08 00 24 56 25 55 2B 6D 5C 08 39 7C 05}
		$a1 = "https://t.me/mastersbots"
		$a2 = "https://steamcommunity.com/profiles/76561199501059503"
		$a3 = "%s\\%s\\Local Storage\\leveldb"
		$a4 = "\\Autofill\\%s_%s.txt"
		$a5 = "\\Downloads\\%s_%s.txt"
		$a6 = "\\CC\\%s_%s.txt"
		$a7 = "Exodus\\exodus.wallet"

	condition:
		$s and 5 of ($a*) 

}
