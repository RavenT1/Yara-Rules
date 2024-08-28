import "pe"
import "math"
import "dotnet"

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
   $s2 = "DC54CY4WPCRYGAFC85GZIF" fullword wide
   $s3 = "Database updated - ID:" fullword wide

   condition: 
   	uint16(0) == 0x5A4D and
	for any i in (0..pe.number_of_sections - 1): (
		math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7.95 and
		pe.sections[i].name == ".text" ) and
	dotnet.version == "v4.0.30319" and 
	all of them
}