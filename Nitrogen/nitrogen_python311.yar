import "pe"

rule nitrogen_python311_rule {

    meta:
    	author = "RussianPanda"
	reference = "https://www.esentire.com/blog/persistent-connection-established-nitrogen-campaign-leverages-dll-side-loading-technique-for-c2-communication"
    	description = "Detects side-loaded Python311 DLL for the new Nitrogen campaign 10-23-2023"
    	date = "10/24/2023"

    strings:
    	$s1 = { 68 62 6F 6B 62 69 30 2F }
    	$s2 = { 48 B8 ?? ?? ?? ?? ?? ?? ?? 00 48 89 44 24 5C }
    	$s3 = { 48 8B 05 ?? ?? 09 00}

    condition:
	all of($s *) and
	uint16(0) == 0x5A4D and
	pe.exports("nop")

}
