rule MAL_EXE_OriginLogger_Ransomware_August_15 { 
  meta:
    description = "This rule detects new OriginLogger Ransomware EXE"
    author      = "Tolga / Malwation"
    date        = "2024-08-15"
    sharing     = "TLP:AMBER"
    tags        = "windows,ransomware,exe,originlogger"
    sample      = "059333e2583e32c5c5cbf8f6d87be71764127ca70e30146ff440a7ea6ee5c5e0"
    reference   = "https://app.threat.zone/"
    os          = "windows"
    category    = "Malware"
  strings:
   $s1= "Data Source=../../databases/dbKanji.sqlite;Version=" fullword wide
   $s2 = "XwiU.exe" fullword ascii 
   $s3 = "3.1.2.3" fullword ascii
   $s4 = "16.0.0.0" fullword ascii   
   $s5 = "config.txt" fullword wide
   $s6 = "L3t.g!R" fullword ascii 
   $s7 =  "JapaneseTrainer.strings" fullword ascii 
   $s8 = "DC54CY4WPCRYGAFC85GZIF" fullword wide

   condition: 
   5 of ($s*)
}