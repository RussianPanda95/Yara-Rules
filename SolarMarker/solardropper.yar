rule SolarDropper
{
	meta:
		author = "RussianPanda"
		reference = "https://www.esentire.com/blog/solarmarker-to-jupyter-and-back"
		description = "SolarMarker first stage detection"
		
    strings:
        $p1 = {2d 00 71 00 71 00 78 00 74 00 72 00 61 00 63 00 74 00 3a 00 22 00 3c 00 66 00 69 00 6c 00 71 00 71 00 6e 00 61 00 6d 00 71 00 71 00 3e 00 22 00}
	$p2 = "deimos.exe"
	$p3 = {5e 00 2d 00 28 00 5b 00 5e 00 3a 00 20 00 5d 00 2b 00 29 00 5b 00 20 00 3a 00 5d 00 3f 00 28 00 5b 00 5e 00 3a 00 5d 00 2a 00 29 00 24 00}

    condition:
        all of ($p*)
}
