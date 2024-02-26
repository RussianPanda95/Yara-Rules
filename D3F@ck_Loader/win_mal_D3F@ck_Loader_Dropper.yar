rule win_mal_D3Fack_Loader_Dropper {
    meta:
        author = "RussianPanda"
        description = "Detects D3F@ck Loader Dropper"
        date = "2/26/2024"
        hash = "01f950baec5b92a851a1b573b7e9891d80bcf8e8688daf7a57563648cae8d26c"
    strings:
        $s1 = {6C 69 62 5C 2A}
        $s2 = {6F 72 67 2E 64 65 76 65 6C 6E 65 78 74 2E 6A 70 68 70 2E 65 78 74 2E 6A 61 76 61 66 78 2E 46 58 4C 61 75 6E 63 68 65 72}
        $s3 = {62 69 6E 5C 6A 61 76 61 2E 65 78 65 00 62 69 6E 5C 6A 61 76 61 77 2E 65 78 65}
    condition:
        uint16(0) == 0x5A4D and all of them
}

