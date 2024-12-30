rule LegionLoader {

    meta:
        description = "Detects LegionLoader core payload"
        author = "RussianPanda"
        date = "2024-10-05"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.satacom"
        hash = "3b630367b2942bd765f8a35bca47ea6b"

    strings:
        $s1 = "crypto_domain"
        $s2 = "postback_url"
        $s3 = "last_win_error"
        
    condition:
        uint16(0) == 0x5A4D and all of them and filesize < 500KB
}
