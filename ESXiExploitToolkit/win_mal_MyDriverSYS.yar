rule MyDriverSys {
    meta:
        author = "RussianPanda"
        description = "Detects the malicious driver - MyDriver.sys"
        hash = "c3f8da7599468c11782c2332497b9e5013d98a1030034243dfed0cf072469c89"
        date = "12/31/2025"
    strings:
        $s1 = "SetGuestInfo  7 11111111"
        $s2 = "found ESXi%d.%d build-%d"
        $s3 = "current build is not surpported"
    condition:
        uint16(0) == 0x5A4D and all of them
}
