rule AMOS_Stealer
{
    meta:
        description = "Detects AMOS Stealer"
        author = "RussianPanda"
        date = "2025-04-11"
        hash = "55663778a8c593b77a82ea1be072c73dd6a1d7a9567bbfbfad7d3dec9f672996"
        
    strings:
        $op1 = {E8 ?? ?? ?? ?? EB 00 48 8D}
        $op2 = {48 8D BD ?? ?? FF FF E8 ?? ?? 00 00 48 8D BD}
        
    condition:
        (
            uint32(0) == 0xfeedface or
            uint32(0) == 0xcefaedfe or 
            uint32(0) == 0xfeedfacf or 
            uint32(0) == 0xcffaedfe or 
            uint32(0) == 0xcafebabe or 
            uint32(0) == 0xbebafeca or
            uint32(0) == 0xcafebabf or
            uint32(0) == 0xbfbafeca
        ) and (#op1 > 50000 and #op2 > 4)
}
