import "dotnet"

rule MAL_EXE_GlobalShadow_Backdoor_September_12 { 
  meta:
    description = "This rule detects new GlobalShadow Backdoor EXE"
    author      = "Tolga"
    date        = "2024-09-12"
    sharing     = "TLP:AMBER"
    tags        = "windows,backdoor,exe,dotnet"
    sample      = "a23adcce96b743d1ecc5a0410fdb6326ae7fff2e78917f51cc70497320dbe750"
    reference   = "https://app.threat.zone/submission/406a7483-59e5-4f28-9d7d-98f58fe07cf9"
    os          = "windows"
    category    = "Malware"
  strings:
   $s1 = "palotxt" fullword ascii
   $s2 = "EmmaCL2.Properties.Resources.resources" fullword ascii
   $s3 = "DesktoProcessId" fullword ascii
   $s4 = "ApProcessId.conf" fullword wide
   $s5 = "RTime.conf" fullword wide

   $ioc1 = "tdyfbwxngpmixjiqtjjote3k9qwc31dsx.oast.fun" fullword wide
   $ioc2 = "http://94.131.108.78:7118/B/" fullword wide

   condition: 
   	uint16(0) == 0x5A4D and
	dotnet.version == "v4.0.30319" and 
	all of them
}
