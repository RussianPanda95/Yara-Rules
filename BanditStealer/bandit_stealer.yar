import "pe"

rule Bandit_Stealer {

	meta:
		author = "RussianPanda"
		description = "Detects the latest build of Bandit Stealer" 
		date = "5/5/2023"
    
	strings:
		$s1 = {48 8D 35 ?? ?? B6 FF 48 8D BE DB ?? ?? FF 48 8D 87 AC ?? ?? 00 FF 30 C7 00 ?? ?? ?? ?? 50 57 31 DB 31 C9}
		$s2 = {48 FF C0 88 17 83 E9 01 8A 10 48 8D 7F 01 75 F0} 
		
	condition:
		all of ($s*) 
		and (uint16(0) == 0x5A4D or uint32(0) == 0x4464c457f)
		and pe.sections[0].name contains "UPX0" 
		and pe.sections[1].name contains "UPX1"
		and pe.sections[0].characteristics & pe.SECTION_MEM_EXECUTE and pe.sections[0].characteristics & pe.SECTION_MEM_WRITE
		and pe.sections[1].characteristics & pe.SECTION_MEM_EXECUTE and pe.sections[1].characteristics & pe.SECTION_MEM_WRITE
}
