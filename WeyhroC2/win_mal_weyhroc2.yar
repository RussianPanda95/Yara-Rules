rule WeyhroC2 {
    meta:
        description = "Detects Weyhro C2"
        author = "RussianPanda"
        date = "2025-12-4"
        reference = "https://x.com/RussianPanda9xx/status/1996258417476837746?s=20"
        hash = "ec4ab4e4d700c9e5fdda59eb879a2bf18d0eefd825539d64677144d43a744cee"
    strings:
        $s1 = "AMSI patch skipped"
		    $s2 = "AMSI patched successfully"
		    $s3 = "IAT unhook successful"
		    $s4 = "Inline unhook successful"
    condition:
        uint16(0) == 0x5A4D and all of them
}
