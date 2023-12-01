rule FakeBat_PowerShell {
    meta:
        description = "Detects FakeBat PowerShell scripts"
        author = "RussianPanda"
        date = "2023-12-01"

    strings:
        $s1 = "$LoadDomen/?status=start&av=" nocase
        $s2 = "$xxx.gpg" nocase

    condition:
        all of ($s*)
}
