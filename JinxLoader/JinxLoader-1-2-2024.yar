rule JinxLoader {
    meta:
        author = "RussianPanda"
        description = "Detects JinxLoader Golang version"
        date = "1/2/2024"
        hash = "6bd7ff5d764214f239af2bb58b368308c2d04f1147678c2f638f37a893995f71"


    strings:
        $s1 = {72 75 6E 74 69 6D 65 2E 67 6F 70 61 6E 69 63}
    	$s2 = {48 8D 05 4D 6E 07 00 BB 0A 00 00 00}
    	$s3 = {73 65 6C 66 5F 64 65 73 74 72 75 63 74 2E 62 61 74}
    	$s4 = {48 8D 1D B7 24 08 00 [25] E8 EF FC E4 FF}
    condition:
    	uint16(0) == 0x5A4D 
        and all of ($s*) and filesize < 9MB
}
