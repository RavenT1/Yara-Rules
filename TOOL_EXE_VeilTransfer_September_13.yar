import "pe"

rule TOOL_EXE_VeilTransfer_September_13 {
   meta:
     description = "This rule detects VeilTransfer hacktool EXE"
     author    	 = "Tolga"
     date 	 = "2024-09-13"
     sharing 	 = "TLP:AMBER"
     tags   	 = "windows,hacktool,exe"
     sample 	 = "1f8ebf4c58bf5922b2de348464364a04fa257415a91f7bae9c8a1d4a3d2bef7f"
     reference   = "https://app.threat.zone/submission/71a5e6fc-1cbc-4ca1-91c1-ee0acfa44cbe"
     os          = "windows"
     category    = "Hacktool"     
   strings:

     $s1 = "Upload via VeilTransfer" ascii 
     $s2 = "sftp, ftp, webdav, mega, webhook, pastebin, github, telegram[!] Warning: File %s exceeds the split size, putting it in its own zip part." fullword ascii
     $s3 = "veilman" fullword ascii
     $s4 = "github.com/brianvoe/gofakeit/v6.addDateTimeLookup.func16" fullword ascii

     $hex1 = { 56 65 69 6C 54 72 61 6E 73 66 65 72 [6-17] 57 61 6C 6B 41 6E 64 55 70 6C 6F 61 64 }   // WalkAndUpload function

     condition:	
	uint16(0) == 0x5a4d and 
	filesize < 16500KB and filesize > 12500KB and
	pe.number_of_sections == 15 and
	all of them
      	
}

