rule mal_NarniaRAT {
    meta:
        author = "RussianPanda"
        description = "Detects NarniaRAT from BotnetFenix campaign"
        date = "2/2/2024"
        hash = "43f6c3f92a025d12de4c4f14afa5d098"
    strings:
        $s1 = "client-remote desktop"
        $s2 = "SendDataToServer"
        $s3 = "SendRunningApps"
        $s4 = "SendDataToServer"
        $s5 = "SendKeys"
        $s6 = "_CorExeMain"
    condition:
        uint16(0) == 0x5A4D and 5 of them
}
