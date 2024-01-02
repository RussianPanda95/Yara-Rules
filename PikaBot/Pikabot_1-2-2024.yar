rule PikaBot {
    meta:
        author = "RussianPanda"
        reference = "https://research.openanalysis.net/pikabot/debugging/string%20decryption/2023/11/12/new-pikabot.html"
        description = "Detects PikaBot"
        date = "1/2/2024"

    strings:
        $s1 = {8A 04 11 30 02 42 83 EE 01 75 F5 5E C3}
    	$s2 = {C0 E9 02 C0 E0 04 [13] C0 E2 06 02 D0}
    	$s3 = {8D 53 BF 80 FA 19 0F B6 C3}
    condition:
        uint16(0) == 0x5A4D
        and 2 of ($s*) and filesize < 500KB
}
