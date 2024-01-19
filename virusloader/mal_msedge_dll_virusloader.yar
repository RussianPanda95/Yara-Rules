rule mal_msedge_dll_virusloader {
    meta:
        description = "Detects trojanized msedge.dll file"
        author = "RussianPanda"
        reference = "https://blog.phylum.io/npm-package-found-delivering-sophisticated-rat/"
        date = "2024-01-19"
        hash = "ab2e3b07170ef1516af3af0d03388868"
    
    strings:
        $s1 = {C6 85 ?? FE FF FF ?? C6}
        $s2 = {C7 85 ?? FD FF FF}
        $s3 = {BF 60 01 00 00 [18] 30 04 39 41}
  
    condition:
        uint16(0) == 0x5A4D and all of ($s*) and #s1 > 30 and #s2 > 30 and filesize < 300KB
}
