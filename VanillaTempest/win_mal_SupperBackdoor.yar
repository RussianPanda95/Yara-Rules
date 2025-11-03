rule SupperBackdoor {
    meta:
        description = "Detects Supper backdoor"
        author = "RussianPanda"
        date = "2025-10-31"
        hash = "bf2ba1f30ef8ca6f9946f6ec21118eff3c3442590bbedea150e2d670e78ab986"
    strings:
        $s1 = "[DEBUG MAIN SOCKS] Starting Init SOCKS"
		$s2 = "fail send data to target"
		$s3 = "serv disconnect"
		$s4 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000"
    condition:
        all of them
}
