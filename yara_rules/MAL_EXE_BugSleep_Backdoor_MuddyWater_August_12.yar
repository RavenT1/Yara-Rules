import "pe"

rule MAL_EXE_BugSleep_Backdoor_MuddyWater_August_12 { 
  meta:
    description = "This rule detects new MuddyWater's backdoor BugSleep malware samples"
    author      = "Tolga / Malwation"
    date        = "2024-08-12"
    sharing     = "TLP:AMBER"
    tags        = "windows,backdoor,muddywater,exe,"
    sample1     = "94278fa01900fdbfb58d2e373895c045c69c01915edc5349cd6f3e5b7130c472"
    sample2     = "73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e"
    sample3     = "5df724c220aed7b4878a2a557502a5cefee736406e25ca48ca11a70608f3a1c0"
    sample4     = "960d4c9e79e751be6cad470e4f8e1d3a2b11f76f47597df8619ae41c96ba5809"
    reference   = "https://app.threat.zone/"
    os          = "windows"
    category    = "Malware"
  strings:
   $mw1 = "i@bvxumxgsjgz" ascii
   $mw2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
   $mw3 = "Zv5b651goo" fullword ascii

   $s1 = "DocumentsManagerReporter" fullword wide
   $s2 = "DocumentUpdater" fullword wide 
   $s3 = "PackageManager" fullword wide
   $s4 = "start /min cmd /c del" fullword ascii    
   $s5 = "sample comment" fullword wide 
   $s6 = "RunTimeBroker.exe" fullword wide
   $s7 = "anydesk.exe" nocase wide
   $s8 = "Onedrive.exe" nocase wide

   condition: 
     	uint16(0) == 0x5A4D and ( 2 of ($mw*) and 2 of ($s*) ) and
	pe.number_of_sections >= 7
	 
}