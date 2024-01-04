rule SolarMarker_loader_PS2EXE {
    meta:
        author = "RussianPanda"
        description = "Detects SolarMarker loader using PS2EXE"
	reference = "https://www.esentire.com/blog/solarmarker-to-jupyter-and-back"
        date = "01/04/2024"
        hash = "b45c31679c2516b38c7ff8c395f1d11d"

    strings:
        $s1 = {72 7B 02 00 70 72 89 02 00 70 72 91 02 00 70 [22] 72 97 02 00 70 72 AB 02 00 70 72 B5 02 00 70}  
        $s2 = {13 0D 72 [3] 70} 
        $s3 = {72 C1 02 00 70 72 B2 03 00 70 72 B8 03 00 70}
    condition: 
        all of ($s*)
        and filesize > 200MB
        
}

