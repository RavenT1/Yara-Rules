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
    reference   = "https://app.threat.zone/6a6f37dd-8075-4805-99de-37cfdc1d2850"
    os          = "windows"
    category    = "Malware"
  strings:

   $mw1 = "DocumentsManagerReporter" fullword wide
   $mw2 = "DocumentUpdater" fullword wide 
   $mw3 = "PackageManager" fullword wide
   $mw4 = "vxumxgsjgzg" ascii
   $s1 = "start /min cmd /c del" fullword ascii    
   $s2 = "sample comment" fullword wide 
   $s3 = "RunTimeBroker.exe" fullword wide
   $s4 = "anydesk.exe" nocase wide
   $s5 = "Onedrive.exe" nocase wide

   condition: 
       uint16(0) == 0x5a4d and 2 of ($mw*) and 5 of them 
}