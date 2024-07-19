import "vt"

rule D3fackLoader {
  meta:
    author = "RussianPanda"
    target_entity = "file"
  condition:
    for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: (
      vt_behaviour_system_property_lookups == "IWbemServices::ExecQuery - root\\CIMV2 : SELECT Name FROM Win32_Process Where Name=&quot;VBoxService.exe&quot;"
    )
    and vt.metadata.exiftool["Comments"] == "This installation was built with Inno Setup."
    and for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: (
      vt_behaviour_system_property_lookups == "IWbemServices::ExecQuery - root\\CIMV2 : SELECT Name FROM Win32_Process Where Name=&quot;Vmwareuser.exe&quot;"
    )
    and for any vt_behaviour_system_property_lookups in vt.behaviour.system_property_lookups: (
      vt_behaviour_system_property_lookups == "IWbemServices::ExecQuery - root\\CIMV2 : SELECT Name FROM Win32_Process Where Name=&quot;Vmtoolsd.exe&quot;"
    )
    and vt.metadata.analysis_stats.malicious > 2
}

