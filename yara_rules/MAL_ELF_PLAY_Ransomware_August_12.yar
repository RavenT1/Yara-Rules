import "elf"

rule MAL_ELF_LNX_Play_August_15 : PLAY RANSOMWARE LINUX ELF {
    meta:
        description = "This rule detects new Play Ransomware samples."
        author      = "Tolga / Malwation"
        date        = "2024-08-15"
        sharing     = "TLP:AMBER"
        tags        = "play,linux,ransomware,elf"
        sample      = "7a55c8391fda90a5d4653fdebe2d685edb662859937e14b6756f45e29b76901d"
        reference   = "https://app.threat.zone/submission/ba839fe6-5385-4b55-af54-dba3cb93ce43"
        os          = "linux"
        category    = "Malware"
    strings:
        $vm1 = "vim-cmd vmsvc/getallvms > machines" ascii fullword
        $vm2 = "vim-cmd vmsvc/power.off" ascii fullword
        $vm3 = "esxcli storage filesystem list > storage" ascii fullword
        $s1 = "Y9EwRW2orYPPTkHVfL67TBYF1WCYAJVpI" ascii fullword
        $s2 = ".PLAY" ascii fullword
	$s3 = "zenity --error --no-markup --title='" ascii fullword
	$s4 = "First step is done." ascii fullword 

    condition:
        uint16(0)==0x457f and  
	(elf.number_of_segments >= 13 and elf.number_of_sections == 0) and
	6 of them
	
}