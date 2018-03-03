/*
 * YARA rules for 64-bit PowerPC Mach-O compiler detection.
 * Copyright (c) 2017 Avast Software, licensed under the MIT license
 */

import "macho"

rule xcode_osx_sdk_01 {
	meta:
		tool = "C"
		name = "XCode"
		extra = "with OS X SDK v10.4 or higher"
		source = "Made by RetDec Team"
		pattern = "7C3A0B783821FFF8782106A438000000F8010000F821FF81807A0000389A00083B6300017B7B1F247CA4DA14????????7FE00008"
	strings:
		$1 = { 7C 3A 0B 78 38 21 FF F8 78 21 06 A4 38 00 00 00 F8 01 00 00 F8 21 FF 81 80 7A 00 00 38 9A 00 08 3B 63 00 01 7B 7B 1F 24 7C A4 DA 14 ?? ?? ?? ?? 7F E0 00 08 }
	condition:
		$1 at macho.entry_point or $1 at macho.ep_for_arch(macho.CPU_TYPE_POWERPC64)
}

rule xcode_osx_sdk_02 {
	meta:
		tool = "C"
		name = "XCode"
		extra = "with OS X SDK v10.5 or higher"
		source = "Made by RetDec Team"
		pattern = "7C3A0B783821FFF8782106A438000000F8010000F821FF81807A0000389A00083B6300017B7B1F247CA4DA147CA62B78E806000038C600082C2000004082FFF4"
	strings:
		$1 = { 7C 3A 0B 78 38 21 FF F8 78 21 06 A4 38 00 00 00 F8 01 00 00 F8 21 FF 81 80 7A 00 00 38 9A 00 08 3B 63 00 01 7B 7B 1F 24 7C A4 DA 14 7C A6 2B 78 E8 06 00 00 38 C6 00 08 2C 20 00 00 40 82 FF F4 }
	condition:
		$1 at macho.entry_point or $1 at macho.ep_for_arch(macho.CPU_TYPE_POWERPC64)
}
