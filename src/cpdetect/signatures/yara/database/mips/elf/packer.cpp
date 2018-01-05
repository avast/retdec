/**
 * @file src/cpdetect/signatures/yara/database/mips/elf/packer.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *mipsElfPacker =
R"mips_elf_packer(rule rule_1_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.03"
		pattern = "????11040000F7272028A4000000E6AC????0D3C2148A00101000B24C2770900????A9154048090000008998030089880400"
	strings:
		$1 = { ?? ?? 11 04 00 00 F7 27 20 28 A4 00 00 00 E6 AC ?? ?? 0D 3C 21 48 A0 01 01 00 0B 24 C2 77 09 00 ?? ?? A9 15 40 48 09 00 00 00 89 98 03 00 89 88 04 00 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_2_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.04"
		pattern = "??0011040000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A0011400001001000B240300899002008E90004A090025482E0101008E90004A090025482E0100008E90004A090025482E0104008424C2770900404809000800E00301002925"
	strings:
		$1 = { ?? 00 11 04 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 14 00 00 10 01 00 0B 24 03 00 89 90 02 00 8E 90 00 4A 09 00 25 48 2E 01 01 00 8E 90 00 4A 09 00 25 48 2E 01 00 00 8E 90 00 4A 09 00 25 48 2E 01 04 00 84 24 C2 77 09 00 40 48 09 00 08 00 E0 03 01 00 29 25 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_3_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.09"
		pattern = "??0011040000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B244?00110401000F240500C01100008E90010084240100C624F9FF0010FFFFCEA0??00110440780F00??0011042178EE01????C01??????E2???00"
	strings:
		$1 = { ?? 00 11 04 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 4? 00 11 04 01 00 0F 24 05 00 C0 11 00 00 8E 90 01 00 84 24 01 00 C6 24 F9 FF 00 10 FF FF CE A0 ?? 00 11 04 40 78 0F 00 ?? 00 11 04 21 78 EE 01 ?? ?? C0 1? ?? ?? ?E 2? ?? 00 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_4_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [LZMA]"
		source = "Made by Retdec Team"
		pattern = "????11040000F7270000999000FA01240100989007002233C2C8190004082103"
	strings:
		$1 = { ?? ?? 11 04 00 00 F7 27 00 00 99 90 00 FA 01 24 01 00 98 90 07 00 22 33 C2 C8 19 00 04 08 21 03 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_5_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "????11040000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B24????110401000F240500C01100008E90010084240100C624F9FF0010FFFFCEA0????110440780F00????11042178EE01FBFFC011"
	strings:
		$1 = { ?? ?? 11 04 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 ?? ?? 11 04 01 00 0F 24 05 00 C0 11 00 00 8E 90 01 00 84 24 01 00 C6 24 F9 FF 00 10 FF FF CE A0 ?? ?? 11 04 40 78 0F 00 ?? ?? 11 04 21 78 EE 01 FB FF C0 11 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_6_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2D]"
		source = "Made by Retdec Team"
		pattern = "????11040000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B24????110401000F240500C01100008E90010084240100C624F9FF0010FFFFCEA0????110440780F00????11042178EE010500C015FEFFEE25????11042178CF01"
	strings:
		$1 = { ?? ?? 11 04 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 ?? ?? 11 04 01 00 0F 24 05 00 C0 11 00 00 8E 90 01 00 84 24 01 00 C6 24 F9 FF 00 10 FF FF CE A0 ?? ?? 11 04 40 78 0F 00 ?? ?? 11 04 21 78 EE 01 05 00 C0 15 FE FF EE 25 ?? ?? 11 04 21 78 CF 01 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_7_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2E]"
		source = "Made by Retdec Team"
		pattern = "????11040000F727FCFFBD270000BFAF2028A4000000E6AC00800D3C2148A00101000B24????110401000F240500C01100008E90010084240100C624F9FF0010FFFFCEA0????110440780F00????11042178EE010500C015FEFFEE25????11042178EE01"
	strings:
		$1 = { ?? ?? 11 04 00 00 F7 27 FC FF BD 27 00 00 BF AF 20 28 A4 00 00 00 E6 AC 00 80 0D 3C 21 48 A0 01 01 00 0B 24 ?? ?? 11 04 01 00 0F 24 05 00 C0 11 00 00 8E 90 01 00 84 24 01 00 C6 24 F9 FF 00 10 FF FF CE A0 ?? ?? 11 04 40 78 0F 00 ?? ?? 11 04 21 78 EE 01 05 00 C0 15 FE FF EE 25 ?? ?? 11 04 21 78 EE 01 }
	condition:
		for any of them : ( $ at elf.entry_point )
})mips_elf_packer";
