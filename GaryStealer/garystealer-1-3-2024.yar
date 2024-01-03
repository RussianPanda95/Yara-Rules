rule GaryStealer {
    meta:
        author = "RussianPanda"
        description = "Detects GaryStealer 1-3-2024"
	reference = "https://cybersecurity.att.com/blogs/labs-research/behind-the-scenes-jaskagos-coordinated-strike-on-macos-and-windows"
        date = "01/03/2024"
        hash = "6efa29a0f9d112cfbb982f7d9c0ddfe395b0b0edb885c2d5409b33ad60ce1435"

    strings:
        $s1 = {72 75 6e 74 69 6d 65 2e 67 6f 70 61 6e 69 63}
        $s2 = {4c 6f 63 61 6c 20 49 50 20 41 64 64 72 65 73 73 65 73 3a 5b 70 69 63 6b 2d 66 69 72 73 74 2d 6c 62 20 25 70 5d}
        $s3 = {70 65 72 73 69 73 74 61 6E 63 65 20 63 72 65 61 74 65 64}
        $s4 = {C7 40 28 ?? 00 00 00}

    condition:
        uint16(0) == 0x5A4D
        and 3 of ($s*) and filesize < 17MB
        and #s4 > 2
		
}
