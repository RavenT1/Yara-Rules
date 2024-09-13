import "elf"

rule MAL_ELF_Sedexp_September_10 {
    meta:
        description = "This rule detects new Sedexp linux malware samples."
        author      = "Tolga / Malwation"
        date        = "2024-09-10"
        sharing     = "TLP:AMBER"
        tags        = "sedexp,linux,ransomware,elf"
        sample1     = "94ef35124a5ce923818d01b2d47b872abd5840c4f4f2178f50f918855e0e5ca2"
	sample2     = "43f72f4cdab8ed40b2f913be4a55b17e7fd8a7946a636adb4452f685c1ffea02"
	sample3     = "b981948d51e344972d920722385f2370caf1e4fac0781d508bc1f088f477b648"
        reference   = "https://app.threat.zone/submission/78b080e5-660b-4373-a043-5558bfad460d"
        os          = "linux"
        category    = "Malware"
    strings:
        $mw1 = "ACTION==\"add\", ENV{MAJOR}==\"1\", ENV{MINOR}==\"8\", RUN+=\"%s %s:+\"" fullword ascii
        $s1 = "cp -f %s %s && sync" fullword ascii
	$s2 = "%s/pkill -%d %s" fullword ascii
	$s3 = "retpolin" fullword ascii 
	$s4 = "per_execH" fullword ascii
	$s5 = "sedexp" fullword ascii 
	$s6 = "/etc/udev/rules.d/99-%s.rules" fullword ascii

    condition:
        uint16(0)==0x457f and 
	filesize < 240KB and filesize > 190KB and 
	($mw1 and 5 of them)
			
}