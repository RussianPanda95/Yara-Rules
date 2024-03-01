rule win_mal_RustyDropper {
    meta:
        author = "RussianPanda"
        description = "Detects RustyDropper"
        date = "3/1/2024"
        hash = "a3a5e7011335a2284e2d4f73fd464ff129f0c9276878a054c1932bc50608584b"
    strings:
        $s1 = {47 3a 5c 52 55 53 54 5f 44 52 4f 50 50 45 52 5f 45 58 45 5f 50 41 59 4c 4f 41 44 5c 44 52 4f 50 50 45 52 5f 4d 41 49 4e 5c}
        $s2 = {46 45 41 54 55 52 45 5f 42 52 4f 57 53 45 52 5f 45 4d 55 4c 41 54 49 4f 4e}
    condition:
        uint16(0) == 0x5A4D and all of them
}

