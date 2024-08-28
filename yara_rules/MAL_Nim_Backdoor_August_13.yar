import "pe"
import "elf"

rule MAL_Nim_Backdoor_August_13 { 
  meta:
    description = "This rule detects new Nim Backdoor EXE and ELF samples"
    author      = "Tolga / Malwation"
    date        = "2024-08-13"
    sharing     = "TLP:AMBER"
    tags        = "backdoor,nim,exe,elf"
    sample1     = "3decf04da202def2ff7a8c10e6b807fd6a1d01f7c9a6ea75f40763bcf464bace"
    sample2     = "addce962f24ddea9bd5768ceee4fc229fd0a5d94fedbac73130b93e8bb177e5b"
    reference   = "https://app.threat.zone/submission/d92a196a-40dc-4f6b-b9d6-9d858f4fe552"
    os          = "windows,linux"
    category    = "Malware"
  strings:
   $mw1= "@mprogram.nim.c" fullword ascii
   $mw2 = "@\nExiting Program..." fullword ascii 
   $mw3 = "`x.a <= x.b` " fullword ascii  
   $mw4 = "userRequestedExit__program_u13" fullword ascii 

   $ip_regex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/		// target_ip		 	
   $hex_pattern = { 64 65 6C 61 79 5F 5F 70 72 6F 67 72 61 6D 5F 75 ?? ?? }	// delay__program_u??
 
   condition: 
   all of them and 
	(filesize < 250KB and filesize > 140KB) and 
	(pe.number_of_sections > 15 or elf.number_of_sections > 31)
	
	
}