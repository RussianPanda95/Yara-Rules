rule win_mal_Chromium_app_bound_encryption_Decrypter {
    meta:
        description = "Detects Potential Chromium app_bound_encryption key Decrypter"
        author = "RussianPanda"
        date = "2025-2-13"
        hash = "0f4dcfd8c9ada67a9b41033fc715d370399fd74ca94dbb8a1ea45b3785c88d02"
    strings:
        $op_chr_1 = {E0 60 88 70 41 F6 11 46}
        $op_chr_2 = {88 95 7D 86 7D D3 67 5B}
        $op_chr_3 = {CF BE 3A 46 0D 41 7F 40}
        $op_chr_4 = {8A F5 0D F3 5A 00 5C C8}
        $op_br_1 = {AF 31 6B 57 69 63 6B 4B}
        $op_br_2 = {85 60 E4 B2 03 A9 7A 8B}
        $op_br_3 = {1E 86 96 F3 8E 0C 71 4C}
        $op_br_4 = {82 56 2F AE 6D 75 9C E9}
        $op_edg_1 = {6C E9 CB 1F 97 16 AF 43}
        $op_edg_2 = {91 40 28 97 C7 C6 97 67}
        $op_edg_3 = {07 B8 C2 C9 31 77 34 4F}
        $op_edg_4 = {81 B7 44 FF 77 79 52 2B}
        $riid1 = {CF BE 3A 46 0D 41 7F 40 8A F5 0D F3 5A 00 5C C8}
        $riid2 = {1E 86 96 F3 8E 0C 71 4C 82 56 2F AE 6D 75 9C E9}
        $dll1 = "CoCreateInstance"
        $dll2 = "CoInitializeEx"
    condition:
        uint16(0) == 0x5A4D and all of ($dll*) and all of ($riid*) and 8 of ($op_*)
}
