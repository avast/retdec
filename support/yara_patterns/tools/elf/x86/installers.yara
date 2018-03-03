/*
 * YARA rules for x86 ELF installer detection.
 * Copyright (c) 2017 Avast Software, licensed under the MIT license
 */

import "elf"

rule p7zip_904
{
	meta:
		tool = "I"
		name = "p7zip SFX"
		source = "Made by RetDec Team"
		pattern = "31ED5E89E183E4F050545268?0??090868????0408515668????0?08E8??FDFFFFF489F65589E583EC1453E8000000005B81C3????0?008B83??02000085C07402FFD05BC9C389F690909090909090905589E583EC08833D?C??0?0800753EEB12A1?8"
	strings:
		$1 = { 31 ED 5E 89 E1 83 E4 F0 50 54 52 68 ?0 ?? 09 08 68 ?? ?? 04 08 51 56 68 ?? ?? 0? 08 E8 ?? FD FF FF F4 89 F6 55 89 E5 83 EC 14 53 E8 00 00 00 00 5B 81 C3 ?? ?? 0? 00 8B 83 ?? 02 00 00 85 C0 74 02 FF D0 5B C9 C3 89 F6 90 90 90 90 90 90 90 90 55 89 E5 83 EC 08 83 3D ?C ?? 0? 08 00 75 3E EB 12 A1 ?8 }
	condition:
		$1 at elf.entry_point
}
