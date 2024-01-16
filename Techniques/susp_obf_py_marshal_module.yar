
rule susp_obf_py_marshal_module {
    meta:
        description = "Detects Obfuscated Code Using Marshal Module"
        author = "RussianPanda"
        date = "2024-01-16"
        reference = "https://www.trendmicro.com/fr_fr/research/23/j/infection-techniques-across-supply-chains-and-codebases.html"

    strings:
        $s1 = "import marshal"
        $s2 = "exec(marshal.loads(zlib.decompress(b'x\\x9c"
        $t2 = "gzip"
        $t3 = "lzma"
        $t4 = "bz2"
        $t5 = "binascii"
      
    condition:
        all of ($s*) and any of ($t*) and filesize < 2MB
}
