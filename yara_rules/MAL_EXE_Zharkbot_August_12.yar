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

   $mw1 = "C:\\Users\\Magnu\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\antilysis-0.1.2\\src\\lib.rs" ascii
   $mw2 = "C:\\Users\\Magnu\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\hex-0.4.3\\src\\lib.rs" ascii
   $mw3 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-1cd66030c949c28d\\hashbrown-0.14.0\\src\\raw\\mod.rs" fullword ascii    
   $mw4 = "hollows_hunter32VGAuthService.exe" fullword ascii
   $s1 = "library\\alloc\\src\\sync.rs" fullword ascii
   $s2 = "library\\core\\src\\unicode\\printable.rs" fullword ascii 
   $s3 = "library\\std\\src\\sys\\windows\\mod.rs" fullword ascii  
   $s4 = "exeNUL\\cmd.exefallback RNG broken: " fullword ascii  

   condition: 
   uint16(0) == 0x5a4d and 3 of ($mw*) and 4 of them
}