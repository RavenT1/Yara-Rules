import "pe"
import "math"
import "hash"

rule MAL_EXE_Zharkbot_August_12 { 
  meta:
    description = "This rule detects new rust-packed Zharkbot EXE"
    author      = "Tolga / Malwation"
    date        = "2024-08-12"
    sharing     = "TLP:AMBER"
    tags        = "windows,rust,packed,exe,"
    sample      = "068ef78225ab94c3f9c228d6248911986c23317d269f0bb5d0a46bd15cd93e80"
    reference   = "https://app.threat.zone/"
    os          = "windows"
    category    = "Malware"
  
  strings:
   $s1 = "hollows_hunter32VGAuthService.exe" fullword ascii 
   $s2 = "GlobalPoolAlreadyInitializedCurrentThreadAlreadyInPoolIOError" fullword ascii
   $s3 = "exeNUL\\cmd.exefallback RNG broken: " fullword ascii  

   condition: 
   	uint16(0) == 0x5A4D and 
	all of them and
   	for any i in (0..pe.number_of_sections - 1): (
		math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7.8 and
		pe.sections[i].name == ".rdata" )
}