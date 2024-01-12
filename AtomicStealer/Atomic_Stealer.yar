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
    condition:	
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
        and all of ($s*) and #s1 > 60 and #s2 > 100
}

