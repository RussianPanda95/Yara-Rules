import "vt"

rule D3fackLoader {
  meta:
    author = "RussianPanda"
    target_entity = "file"
  condition:
    for any vt_behaviour_files_opened in vt.behaviour.files_opened: (
      vt_behaviour_files_opened == "ds.txt"
    )
    and for any vt_behaviour_processes_created in vt.behaviour.processes_created: (
      vt_behaviour_processes_created == "C:\\Windows\\SysWOW64\\findstr.exe FINDSTR  /I \"Virtual VBOX VMware\""
    )
    and vt.metadata.analysis_stats.malicious > 1

}


