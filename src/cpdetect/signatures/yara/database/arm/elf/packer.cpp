/**
 * @file src/cpdetect/signatures/yara/database/arm/elf/packer.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *armElfPacker =
R"arm_elf_packer(rule rule_1_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [LZMA]"
		source = "Made by Retdec Team"
		pattern = "00000000F04F2DE930D04DE200308DE50030D0E50250D0E501E0D0E500C09DE514308DE55C309DE50040A0E300408CE5004083E514C09DE50130D0E503308CE0"
		start = 380
	strings:
		$1 = { 00 00 00 00 F0 4F 2D E9 30 D0 4D E2 00 30 8D E5 00 30 D0 E5 02 50 D0 E5 01 E0 D0 E5 00 C0 9D E5 14 30 8D E5 5C 30 9D E5 00 40 A0 E3 00 40 8C E5 00 40 83 E5 14 C0 9D E5 01 30 D0 E5 03 30 8C E0 }
	condition:
		for any of them : ( $ at elf.entry_point + 380 )
}
rule rule_2_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "044094E00EF0A0110140D0E40440A4E0044CB0E10EF0A0E10110A0E30EC0A0E1F6FFFFEB0110B1E0F4FFFFEBFBFFFF3A"
		start = 276
	strings:
		$1 = { 04 40 94 E0 0E F0 A0 11 01 40 D0 E4 04 40 A4 E0 04 4C B0 E1 0E F0 A0 E1 01 10 A0 E3 0E C0 A0 E1 F6 FF FF EB 01 10 B1 E0 F4 FF FF EB FB FF FF 3A }
	condition:
		for any of them : ( $ at elf.entry_point + 276 )
}
rule rule_3_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2D]"
		source = "Made by Retdec Team"
		pattern = "0140D0E40440A4E0044CB0E10EF0A0E10130D0E40130C2E4044094E0F7FFFF0BFAFFFF2A0110A0E3030000EA011041E2044094E0F1FFFF0B0110B1E0"
		start = 276
	strings:
		$1 = { 01 40 D0 E4 04 40 A4 E0 04 4C B0 E1 0E F0 A0 E1 01 30 D0 E4 01 30 C2 E4 04 40 94 E0 F7 FF FF 0B FA FF FF 2A 01 10 A0 E3 03 00 00 EA 01 10 41 E2 04 40 94 E0 F1 FF FF 0B 01 10 B1 E0 }
	condition:
		for any of them : ( $ at elf.entry_point + 276 )
}
rule rule_4_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2E]"
		source = "Made by Retdec Team"
		pattern = "0140D0E40440A4E0044CB0E10EF0A0E10130D0E40130C2E4044094E0F7FFFF0BFAFFFF2A0110A0E3030000EA011041E2044094E0F1FFFF0B0110A1E0"
		start = 276
	strings:
		$1 = { 01 40 D0 E4 04 40 A4 E0 04 4C B0 E1 0E F0 A0 E1 01 30 D0 E4 01 30 C2 E4 04 40 94 E0 F7 FF FF 0B FA FF FF 2A 01 10 A0 E3 03 00 00 EA 01 10 41 E2 04 40 94 E0 F1 FF FF 0B 01 10 A1 E0 }
	condition:
		for any of them : ( $ at elf.entry_point + 276 )
})arm_elf_packer";
