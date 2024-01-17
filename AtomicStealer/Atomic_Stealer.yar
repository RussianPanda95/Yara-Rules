rule Atomic_Stealer {
    meta:
        author = "RussianPanda"
        description = "Detects Atomic Stealer targering MacOS"
        date = "1/13/2024"
        reference = "https://www.malwarebytes.com/blog/threat-intelligence/2024/01/atomic-stealer-rings-in-the-new-year-with-updated-version/amp"
        hash = "dd8aa38c7f06cb1c12a4d2c0927b6107"
    strings:
        $s1 = {8B 09 83 C1 (01|02|04|05|03) 39 C8 0F 85 38 00 00 00 48 8B 85}
        $s2 = {C7 40 04 00 00 00 00 C6 40 08 00 C6 40 09 00}
        $t1 = {0F 57 1D 97 0D 01 00 0F 29 5D C0 80 75 D0 1E 80 75 D1 1F 80 75 D2 20 80 75 D3 21 80 75 D4 22 80 75 D5 23 80 75 D6 24 80 75 D7 25 80 75 D8 26 80 75 D9 27 80 75 DA 28 80 75 DB 29 80 75 DC 2A 80 75 DD 2B 80 75 DE 2C C6 45 DF 00}
        $t2 = {0F 28 85 C0 FA FF FF 0F 28 8D D0 FA FF FF 0F 28 95 E0 FA FF FF 0F 28 9D F0 FA FF FF 0F 57 05 BD 1B 01 00}
        $t3 = {8A 06 34 DE 88 07 8A 46 01 34 DF 88 47 01}
        $c1 = {28 ?? 40 39}
        $c2 = {64 65 73 6B 77 61 6C 6C 65 74 73}
    condition:	
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
        and all of ($s*) and #s1 > 60 and #s2 > 100 or all of ($t*) or (#c1 > 200 and $c2)
}

