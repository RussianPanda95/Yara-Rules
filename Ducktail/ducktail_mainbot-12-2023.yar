import "pe"

rule Ducktail_mainbot {

	meta:
		author = "RussianPanda"
		decription = "Detects Ducktail mainbot"
		date = "12/24/2023"

	strings:
		$s1 = {2F 00 61 00 70 00 69 00 2F 00 63 00 68 00 65 00 63 00 6B}
		$s2 = {62 00 65 00 67 00 69 00 6E 00 20 00 63 00 6F 00 6E 00 6E 00 65 00 63 00 74}
		$s3 = {62 00 65 00 67 00 69 00 6E 00 20 00 66 00 6C 00 75 00 73 00 68 00 20 00 64 00 6E 00 73}
		$s4 = {62 00 65 00 67 00 69 00 6E 00 20 00 73 00 65 00 6E 00 64 00 69 00 6E 00 67}
		
	condition:
		all of ($s*) and filesize < 12MB
		and pe.exports("DotNetRuntimeDebugHeader")
}
