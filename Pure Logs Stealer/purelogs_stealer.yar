import "pe"

rule PureLogs_Stealer {
    meta:
        author = "RussianPanda"
        description = "Detects Pure Logs Stealer"
        date = "12/26/2023"

    strings:
        $s1 = {7E 58 00 00 0A [15] 28 20 00 00 0A 18 6F 0A 02 00 0A 0B}
        $s2 = {50 6C 67 43 6F 72 65}
        $s3 = {7E 64 01 00 0A 28 65 01 00 0A}

    condition:
        all of ($s*) and filesize < 5MB
        and pe.imports("mscoree.dll")
		
}
