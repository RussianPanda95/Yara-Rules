rule PeerBlight {
    meta:
        description = "Detects PeerBlight backdoor"
        author = "RussianPanda"
        date = "2025-12-7"
        hash = "a605a70d031577c83c093803d11ec7c1e29d2ad530f8e95d9a729c3818c7050d"
    strings:
        $s1 = "/bin/systemd-daemon"
		    $s2 = "/lib/systemd/system/systemd-agent.service"
        $s3 = "group"
        $s4 = "tag"
        $s5 = "arch"
        $s6 = "srvk"
    condition:
        uint32(0) == 0x464c457f and all of them
}
