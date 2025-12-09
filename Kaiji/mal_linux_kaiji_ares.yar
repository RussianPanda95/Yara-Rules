rule Kaiji_Ares {
    meta:
        description = "Detects a Variant of Kaiji (Ares) observed during React2Shell exploitation"
        author = "RussianPanda"
        date = "2025-12-8"
        hash = "c79fcb6c433d8a613f25b9b4c81c1c2514ac97e9aaae7c7c84a432b2476b5e4e"
    strings:
        $s1 = "C:/src/client/linux/ares_tcp.go"
		$s2 = {E5 BC BA E5 88 B6 55 64 70}
		$s3 = {B0 81 E5 8C 85}
    condition:
        uint32(0) == 0x464c457f and 2 of them
}
