import "pe"

rule SolarMarker_loader {
    meta:
        author = "RussianPanda"
        description = "Detects SolarMarker loader 1-4-2024"
	reference = "https://www.esentire.com/blog/solarmarker-to-jupyter-and-back"
        date = "01/04/2024"
        hash = "8eeefe0df0b057fc866b8d35625156de"

    strings:
        $s1 = {06 [0-7] 58 D1 8C [3] 01 28 [3] 0A 0A}  
    condition: 
        all of ($s*)
        and #s1 > 5
        and filesize < 7MB
        and pe.imports("mscoree.dll")
        
}


