rule Atomic_Stealer {
    meta:
        author = "RussianPanda"
        description = "Detects Atomic Stealer targering MacOS"
        date = "1/13/2024"
        reference1 = "https://www.malwarebytes.com/blog/threat-intelligence/2024/01/atomic-stealer-rings-in-the-new-year-with-updated-version/amp"
	reference2 = "https://www.bleepingcomputer.com/news/security/macos-info-stealers-quickly-evolve-to-evade-xprotect-detection/"
        hash = "dd8aa38c7f06cb1c12a4d2c0927b6107"
    strings:
        $s1 = {8B 09 83 C1 (01|02|04|05|03) 39 C8 0F 85 38 00 00 00 48 8B 85}
        $s2 = {C7 40 04 00 00 00 00 C6 40 08 00 C6 40 09 00}
        $t1 = {80 75 D?}
        $t2 = {0F 57 05 ?? 1B 01 00}
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
        and all of ($s*) and #s1 > 60 and #s2 > 100 or (all of ($t*) and #t1 > 10 and #t2 > 5) or (#c1 > 200 and $c2)
}

