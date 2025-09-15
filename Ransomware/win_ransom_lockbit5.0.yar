rule win_ransom_Lockbit5 {
	meta:
		author = "RussianPanda"
		description = "Detects LockBit 5.0" 
		date = "9/15/2025"
    hash = "7ea5afbc166c4e23498aa9747be81ceaf8dad90b8daa07a6e4644dc7c2277b82"
	strings:
		$s1 = {C6 41 0F 00 0F B6 ?? 33 ?? 89}
		$s2 = {0F B6 ?? 0F C1 ?? 18 31} 
		$s3 = {83 ?? 02 83 ?? 0F D0 84 ?? ?? 00 00 00}
		
	condition:
		all of ($s*) 
		and uint16(0) == 0x5A4D and filesize < 1MB
}
