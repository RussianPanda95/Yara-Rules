rule MAESTRO {
    meta:
        author = "RussianPanda"
        description = "Detects MAESTRO payload"
        hash = "37972a232ac6d8c402ac4531430967c1fd458b74a52d6d1990688d88956791a7"
        date = "12/31/2025"
    strings:
        $s1 = "devcon.exe disable \"PCI\\VEN_15AD&DEV_0740\""
        $s2 = "devcon.exe disable \"ROOT\\VMWVMCIHOSTDEV\""
        $s3 = "Open SymbolicLink Failed" wide
        $s4 = "Done!!!" ascii wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
