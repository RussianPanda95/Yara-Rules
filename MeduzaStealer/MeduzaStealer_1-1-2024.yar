rule MeduzaStealer {
    meta:
        author = "RussianPanda"
        description = "Detects MeduzaStealer 1-2024"
		reference = "https://russianpanda.com/2023/06/28/Meduza-Stealer-or-The-Return-of-The-Infamous-Aurora-Stealer/"
        date = "01/01/2024"

    strings:
        $s1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 57 69 6e 55 70 64 61 74 65 2e 65 78 65}
		$s2 = {0f 57 ?? ?? ?? 00 00 66 0f 7f 85 ?? ?? 00 00}
		$s3 = {48 8d 15 ?? ?? 05 00 49 8b cf}
		$s4 = {48 8d 0d ?? ?? 06 00 ff 15 ?? ?? 06 00}

    condition:
        3 of ($s*) and filesize < 1MB
		
}
