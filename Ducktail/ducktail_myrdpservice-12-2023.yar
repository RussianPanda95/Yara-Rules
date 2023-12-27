import "pe"

rule Ducktail_myRdpService_bot {

	meta:
		author = "RussianPanda"
		decription = "Detects Ducktail myRdpService bot"
		date = "12/24/2023"

	strings:
		$s1 = {43 00 3A 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 54 00 65 00 6D 00 70 00 5C 00 64 00 65 00 76 00 69 00 63 00 65 00 49 00 64 00 2E 00 74 00 78 00 74} 
		$s2 = {6C 00 6F 00 67 00 5F 00 72 00 64 00 70 00 2A}
		$s3 = {00 43 00 6F 00 6E 00 6E 00 65 00 63 00 74 00 65 00 64 00}
	condition:
		all of ($s*) and filesize < 12MB
		and pe.exports("DotNetRuntimeDebugHeader")
}
