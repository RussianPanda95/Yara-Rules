rule Gh0stRAT {
    meta:
        description = "Detects Gh0stRAT"
        author = "RussianPanda"
        date = "2024-07-09"
        hash = "678b06ecdbc9b186788cf960332566f9"
    strings:
        $s1 = "SAM\\SAM\\Domains\\Account\\Users\\Names\\%s"
        $s2 = "GetMP privilege::debug sekurlsa::logonpasswords exit" 
        $s3 = "Http/1.1 403 Forbidden"
        $s4 = "WinSta0\\Default"
    condition:
        uint16(0) == 0x5A4D and all of them
}
