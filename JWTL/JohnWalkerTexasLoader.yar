rule JohnWalkerTexasLoader {

    meta:
        description = "Detects JohnWalkerTexasLoader (JWTL)"
        author = "RussianPanda"
        date = "2024-10-10"
        hash = "3784fc39dc5c0dec08ad0a49bbbb990359e313a9fa87e6842fd67ed7cc1c0baa"

    strings:
        $s1 = "?status=1&wallets=" ascii wide
        $s2 = "/api.php" ascii wide
        $s3 = "/api-debug.php" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and all of them
}
