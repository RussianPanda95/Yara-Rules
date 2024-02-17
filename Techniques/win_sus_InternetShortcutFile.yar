rule win_sus_InternetShortcutFile {
    meta:
        description = "Detects suspicious Internet Shortcut Files that are often used to retrieve malware"
        author = "RussianPanda"
        date = "2024-02-17"

    strings:
        $s1 = "[InternetShortcut]"
        $s2 = {55 52 4C 3D 66 69 6C 65 3A 2F 2F}
        $a1 = ".exe"
        $a2 = ".dll"
        $a3 = ".js"
        $a4 = ".msi"
        $a5 = ".msix"
        $a6 = ".bat"
        $a7 = ".cmd"
    condition:
        all of ($s*) and any of ($a*)
}
