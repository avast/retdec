/*
 * YARA rules for ARM Mach-O compiler detection.
 * Copyright (c) 2017 Avast Software, licensed under the MIT license
 */

import "macho"

rule xcode_ios_sdk_01
{
	meta:
		tool = "C"
		name = "XCode"
		extra = "with WatchOS or iOS SDK"
		source = "Made by RetDec Team"
		pattern = "00009DE504108DE2014080E2042181E007D0CDE30230A0E1044093E4000054E3FCFFFF1A"
	strings:
		$1 = { 00 00 9D E5 04 10 8D E2 01 40 80 E2 04 21 81 E0 07 D0 CD E3 02 30 A0 E1 04 40 93 E4 00 00 54 E3 FC FF FF 1A }
	condition:
		$1 at macho.entry_point or $1 at macho.ep_for_arch(macho.CPU_TYPE_ARM)
}

rule xcode_ios_sdk_02 {
	meta:
		tool = "C"
		name = "XCode"
		extra = "with WatchOS or iOS SDK"
		source = "Made by RetDec Team"
		pattern = "00009DE504108DE2014080E2042181E007D0CDE30230A0E1044093E4000054E3FCFFFF1A18C09FE50CC08FE000C09CE53CFF2FE10CC09FE50CC08FE000C09CE51CFF2FE1"
	strings:
		$1 = { 00 00 9D E5 04 10 8D E2 01 40 80 E2 04 21 81 E0 07 D0 CD E3 02 30 A0 E1 04 40 93 E4 00 00 54 E3 FC FF FF 1A 18 C0 9F E5 0C C0 8F E0 00 C0 9C E5 3C FF 2F E1 0C C0 9F E5 0C C0 8F E0 00 C0 9C E5 1C FF 2F E1 }
	condition:
		$1 at macho.entry_point or $1 at macho.ep_for_arch(macho.CPU_TYPE_ARM)
}
