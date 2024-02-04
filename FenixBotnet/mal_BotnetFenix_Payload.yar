rule mal_BotnetFenix_Payload {
    meta:
        author = "RussianPanda"
        description = "Detects BotnetFenix payload"
        date = "2/2/2024"
        hash = "65a9575c50a96d04a3f649fe0f6b8ccd"
    strings:
        $s1 = "tasks_register"
        $s2 = "actionget_action"
        $s3 = "Post Success"
        $s4 = "Success Stealer"
        $s5 = "Download and Execute task id"
        $a = "_CorExeMain"
    condition:
        uint16(0) == 0x5A4D and 4 of ($s*) and $a
}
