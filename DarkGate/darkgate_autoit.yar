rule darkgate_AutoIT {
    meta:
        description = "Detects DarkGate AutoIT script"
        author = "RussianPanda"
        date = "2024-01-26"
        reference = "https://yara.readthedocs.io/en/stable/writingrules.html?highlight=xor"
        hash = "e1803b01e3f187355dbeb87a0c91b76c"

    strings:
        $h = "AU3!EA06"
        $s1 = "just_test.txt" xor(0x01-0xff)
        $s2 = "c:\\temp\\data.txt" xor(0x01-0xff)
        $s3 = "test.txt" xor(0x01-0xff)
        $s4 = "cc.txt" xor(0x01-0xff)
        $s5 = "c:\\temp\\data.txt" xor(0x01-0xff)
        $s6 = "uu.txt" xor(0x01-0xff)
    condition:
        3 of ($s*) and $h
}

