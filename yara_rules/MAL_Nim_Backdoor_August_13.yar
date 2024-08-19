rule MAL_Nim_Backdoor_August_13 { 
  meta:
    description = "This rule detects new Nim Backdoor EXE and ELF samples"
    author      = "Tolga / Malwation"
    date        = "2024-08-13"
    sharing     = "TLP:AMBER"
    tags        = "backdoor,nim,exe,elf"
    sample1     = "3decf04da202def2ff7a8c10e6b807fd6a1d01f7c9a6ea75f40763bcf464bace"
    sample2     = "addce962f24ddea9bd5768ceee4fc229fd0a5d94fedbac73130b93e8bb177e5b"
    reference   = "https://app.threat.zone/submission/bdf1a6c7-be2a-4d65-b733-c4c7681bd6e8"
    os          = "windows,linux"
    category    = "Malware"
  strings:
   $mw1= "@mprogram.nim.c" fullword ascii
   $mw2 = "@\nExiting Program..." fullword ascii 
   $mw3 = "`x.a <= x.b` " fullword ascii  
   $mw4 = "delay__program_u" ascii 
 
   condition: 
   all of them and filesize < 265KB
}