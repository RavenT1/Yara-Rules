rule MAL_ELF_LNX_Play_August_15 : PLAY RANSOMWARE LINUX ELF {
    meta:
        description = "This rule detects new Play Ransomware samples."
        author      = "Tolga / Malwation"
        date        = "2024-08-15"
        sharing     = "TLP:AMBER"
        tags        = "play,linux,ransomware,elf"
        sample      = "7a55c8391fda90a5d4653fdebe2d685edb662859937e14b6756f45e29b76901d"
        reference   = "https://app.threat.zone/"
        os          = "linux"
        category    = "Malware"
    strings:
        $vm1 = "vim-cmd vmsvc/getallvms > machines" ascii fullword
        $vm2 = "vim-cmd vmsvc/power.off" ascii fullword
        $m1 = ".PLAY" ascii fullword
        $m2 = "Y9EwRW2orYPPTkHVfL67TBYF1WCYAJVpI" ascii fullword
        $m3 = "esxcli storage filesystem list > storage" ascii fullword
	$m4 = "First step is done." ascii fullword

    condition:
        uint16(0)==0x457f and 4 of them
}