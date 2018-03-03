/*
 * YARA rules for PowerPC Mach-O compiler detection.
 * Copyright (c) 2017 Avast Software, licensed under the MIT license
 */

import "macho"

rule xcode_osx_sdk_01 {
	meta:
		tool = "C"
		name = "XCode"
		extra = "with OS X SDK"
		source = "Made by RetDec Team"
		pattern = "7C3A0B783821FFFC5421003438000000900100009421FFC0807A0000389A00043B630001577B103A7CA4DA14"
	strings:
		$1 = { 7C 3A 0B 78 38 21 FF FC 54 21 00 34 38 00 00 00 90 01 00 00 94 21 FF C0 80 7A 00 00 38 9A 00 04 3B 63 00 01 57 7B 10 3A 7C A4 DA 14 }
	condition:
		$1 at macho.entry_point or $1 at macho.ep_for_arch(macho.CPU_TYPE_POWERPC)
}

rule xcode_osx_sdk_02 {
	meta:
		tool = "C"
		name = "XCode"
		extra = "with OS X SDK v10.1 or higher"
		source = "Made by RetDec Team"
		pattern = "7C3A0B783821FFFC5421003438000000900100009421FFC0807A0000389A00043B630001577B103A7CA4DA14????????7FE00008"
	strings:
		$1 = { 7C 3A 0B 78 38 21 FF FC 54 21 00 34 38 00 00 00 90 01 00 00 94 21 FF C0 80 7A 00 00 38 9A 00 04 3B 63 00 01 57 7B 10 3A 7C A4 DA 14 ?? ?? ?? ?? 7F E0 00 08 }
	condition:
		$1 at macho.entry_point or $1 at macho.ep_for_arch(macho.CPU_TYPE_POWERPC)
}

rule xcode_osx_sdk_03 {
	meta:
		tool = "C"
		name = "XCode"
		extra = "with OS X SDK v10.5 or higher"
		source = "Made by RetDec Team"
		pattern = "7C3A0B783821FFFC5421003438000000900100009421FFC0807A0000389A00043B630001577B103A7CA4DA147CA62B788006000038C600042C0000004082FFF4"
	strings:
		$1 = { 7C 3A 0B 78 38 21 FF FC 54 21 00 34 38 00 00 00 90 01 00 00 94 21 FF C0 80 7A 00 00 38 9A 00 04 3B 63 00 01 57 7B 10 3A 7C A4 DA 14 7C A6 2B 78 80 06 00 00 38 C6 00 04 2C 00 00 00 40 82 FF F4 }
	condition:
		$1 at macho.entry_point or $1 at macho.ep_for_arch(macho.CPU_TYPE_POWERPC)
}
