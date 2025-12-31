rule VSOCKpuppet {
    meta:
        author = "RussianPanda"
        description = "Detects VSOCKpuppet payload"
        hash = "c3f8da7599468c11782c2332497b9e5013d98a1030034243dfed0cf072469c89"
        date = "12/31/2025"
    strings:
        $s1 = "received command:%s"
        $s2 = "MCISock_GetAFValue failed"
        $s3 = "recv_response failed"
        $s4 = "send_msg_len failed"
    condition:
        uint32(0) == 0x464C457F and all of them
}
