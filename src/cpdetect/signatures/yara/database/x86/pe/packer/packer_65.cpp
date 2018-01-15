/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_65.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_65 =
R"x86_pe_packer(
rule rule_7ZipSFX_313_console
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "3.13"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF6878F8410068607C410064A100000000506489250000000083EC105356578965E8FF1510F1410033D28AD489152C7E42008BC881E1FF000000890D287E4200C1E10803CA890D247E4200C1E810A3207E42006A01E8FD1300005985C075086A"
	strings:
		$1 = { 55 8B EC 6A FF 68 78 F8 41 00 68 60 7C 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 10 53 56 57 89 65 E8 FF 15 10 F1 41 00 33 D2 8A D4 89 15 2C 7E 42 00 8B C8 81 E1 FF 00 00 00 89 0D 28 7E 42 00 C1 E1 08 03 CA 89 0D 24 7E 42 00 C1 E8 10 A3 20 7E 42 00 6A 01 E8 FD 13 00 00 59 85 C0 75 08 6A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_7ZipSFX_42x_console
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "4.2x"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF68202C420068?0CD410064A100000000506489250000000083EC105356578965E8FF150021420033D28AD489158CBF42008BC881E1FF000000890D88BF4200C1E10803CA890D84BF4200C1E810A380BF42006A01E89F1C00005985C075086A"
	strings:
		$1 = { 55 8B EC 6A FF 68 20 2C 42 00 68 ?0 CD 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 10 53 56 57 89 65 E8 FF 15 00 21 42 00 33 D2 8A D4 89 15 8C BF 42 00 8B C8 81 E1 FF 00 00 00 89 0D 88 BF 42 00 C1 E1 08 03 CA 89 0D 84 BF 42 00 C1 E8 10 A3 80 BF 42 00 6A 01 E8 9F 1C 00 00 59 85 C0 75 08 6A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_7ZipSFX_16xx_console
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "4.3x - 16.xx"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF68????4?0068????4?0064A100000000506489250000000083EC205356578965E88365FC006A01FF15???04?0059830D????4200FF830D????4200FFFF15???04?008B0D????42008908FF15???04?008B0D????42008908A1???04?008B00"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? 4? 00 68 ?? ?? 4? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 20 53 56 57 89 65 E8 83 65 FC 00 6A 01 FF 15 ?? ?0 4? 00 59 83 0D ?? ?? 42 00 FF 83 0D ?? ?? 42 00 FF FF 15 ?? ?0 4? 00 8B 0D ?? ?? 42 00 89 08 FF 15 ?? ?0 4? 00 8B 0D ?? ?? 42 00 89 08 A1 ?? ?0 4? 00 8B 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_7ZipSFX_17xx_console
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "17.xx"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF68C076420068?C2?420064A100000000506489250000000083EC205356578965E88365FC006A01FF15DC50420059830D34064300FF830D38064300FFFF15E05042008B0DFCE542008908FF15E45042008B0DF8E542008908A1E85042008B00"
	strings:
		$1 = { 55 8B EC 6A FF 68 C0 76 42 00 68 ?C 2? 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 20 53 56 57 89 65 E8 83 65 FC 00 6A 01 FF 15 DC 50 42 00 59 83 0D 34 06 43 00 FF 83 0D 38 06 43 00 FF FF 15 E0 50 42 00 8B 0D FC E5 42 00 89 08 FF 15 E4 50 42 00 8B 0D F8 E5 42 00 89 08 A1 E8 50 42 00 8B 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
})x86_pe_packer";
