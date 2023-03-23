rule  AuroraStealer_March_2023 {

	meta:
		author = "RUPanda"
		description = "Detects the Build/Group IDs if present / detects an obfuscated AuroraStealer March update binary" 
		date = "3/23/2023"

	strings:
		$b1 = { 48 8D 0D ?? ?? 05 00 E8 ?? ?? EF FF }
		$ftp = "FOUND FTP"  
			
	condition:
		all of them

}