import "pe"

rule MAL_EXE_Voldemort_September_10{
   meta:
     description = "This rule detects new Voldemort malware samples"
     author    	 = "Tolga / Malwation"
     date 	 = "2024-09-08"
     sharing 	 = "TLP:AMBER"
     tags   	 = "windows,dll,exe"
     sample 	 = "fa383eac2bf9ad3ef889e6118a28aa57a8a8e6b5224ecdf78dcffc5225ee4e1f"
     reference   = "https://app.threat.zone/submission/6ec11a5a-af6c-4b2a-b718-0b77bf58b2ee"
     os          = "windows"
     category    = "Malware"     
   strings:
     $s1 = "iscqCollabHost." fullword ascii 
     $s2 = "bHwst.exeC" fullword ascii 
     $s3 = "Host.exeCiscoColla" fullword ascii 
     $s4 = ">nlafHost.exjCiscoCoLlabHost/exeAisclbnllabHost.exeCiN" fullword ascii 
     $s5 = "abHost.exe" fullword ascii 
     $s6 = "coGomlabHosT.exe" fullword ascii 

     $s7 = "/v4/spreadsheets/%s/values/%s!R%dC1"  wide 
     $s8 = "/v4/spreadsheets/%s:batchUpdate" fullword wide 
     $s9 = "cbHort.eyeCi" fullword ascii 

 
     condition:	
	uint16(0) == 0x5a4d and 
      	( pe.exports("SparkEntryPoint") or all of ($s*) )
}

