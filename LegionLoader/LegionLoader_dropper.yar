rule LegionLoader_dropper {

    meta:
        description = "Detects malicious LegionLoader DLL dropper"
        author = "RussianPanda"
        date = "2024-09-23"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.satacom"
        hash = "ef5b961ebc6167e728f9bf40e726ac71"

    strings:
        $s1 = {48 03 CA [0-50] 33 D2 33 C9 FF 15 ?? ?? ?? ?? 33 D2 33 C9 FF 15}
        $s2 = {44 30 3B 48 FF C3}
        $s3 = {8B ?? 8B ?? 83 ?? 01 D1 ?? F7 ?? 81 ?? 20 83 B8 ED 8B}

    condition:
        uint16(0) == 0x5A4D and all of them and filesize < 1MB
}

