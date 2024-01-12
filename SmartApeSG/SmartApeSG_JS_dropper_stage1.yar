rule SmartApeSG_JS_dropper_stage1 {
    meta:
        author = "RussianPanda"
        description = "Detects SmartApeSG initial JavaScript file"
        date = "1/11/2024"
        reference = "https://medium.com/walmartglobaltech/smartapesg-4605157a5b80"
        hash = "8769d9ebcf14b24a657532cd96f9520f54aa0e799399d840285311dfebe3fb15"
    strings:
        $a1 = "'GE'+'T'"
        $a2 = "'GE','T'"
        $s1 = "pt.Creat"
        $s2 = "L2.ServerX"
        $s3 = "ponseText"
        $s4 = "MLHTTP.6.0"
        $s5 = /\/news\.php\?([0-9]|[1-9][0-9]|100)/
    condition:
         all of ($s*) and filesize < 1MB and any of ($a*)
}


