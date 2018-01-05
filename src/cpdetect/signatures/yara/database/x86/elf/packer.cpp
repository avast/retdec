/**
 * @file src/cpdetect/signatures/yara/database/x86/elf/packer.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86ElfPacker =
R"x86_elf_packer(rule rule_1_ELFCrypt
{
	meta:
		tool = "P"
		name = "ELFCrypt"
		version = "1.0"
		source = "from Detect It Easy signatures"
		pattern = "EB0206C6609CBE"
	strings:
		$1 = { EB 02 06 C6 60 9C BE }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_2_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.09"
		pattern = "E8????????608B7424248B7C242C83CDFFEB0F90909090908A064688074701DB75078B1E83EEFC11DB8A0772EBB80100000001DB75078B1E83EEFC11DB11C001DB"
	strings:
		$1 = { E8 ?? ?? ?? ?? 60 8B 74 24 24 8B 7C 24 2C 83 CD FF EB 0F 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_3_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.09"
		pattern = "E8????????EB0E5A585997608A542420E9????????608B7424248B7C242C83CDFFEB0F90909090908A064688074701DB75078B1E83EEFC11DB8A0772EBB80100000001DB75078B1E83EEFC11DB11C001DB"
	strings:
		$1 = { E8 ?? ?? ?? ?? EB 0E 5A 58 59 97 60 8A 54 24 20 E9 ?? ?? ?? ?? 60 8B 74 24 24 8B 7C 24 2C 83 CD FF EB 0F 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_4_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.xx"
		source = "from Detect It Easy signatures"
		pattern = "E8????????EB0E5A585997608A542420E9????????60"
	strings:
		$1 = { E8 ?? ?? ?? ?? EB 0E 5A 58 59 97 60 8A 54 24 20 E9 ?? ?? ?? ?? 60 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_5_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [LZMA]"
		source = "Made by Retdec Team"
		pattern = "E8????????EB0E5A585997608A542420E9180B0000608B7424248B7C242C83CDFF89E58B5528AC4A88C12407C0E903BB00FDFFFFD3E38DA45C90F1FFFF83E4E06A006A0089E35383C3048B4D30FF31575383C304884302AC4A88C1240F8803C0E904884B015256535090909090909090"
	strings:
		$1 = { E8 ?? ?? ?? ?? EB 0E 5A 58 59 97 60 8A 54 24 20 E9 18 0B 00 00 60 8B 74 24 24 8B 7C 24 2C 83 CD FF 89 E5 8B 55 28 AC 4A 88 C1 24 07 C0 E9 03 BB 00 FD FF FF D3 E3 8D A4 5C 90 F1 FF FF 83 E4 E0 6A 00 6A 00 89 E3 53 83 C3 04 8B 4D 30 FF 31 57 53 83 C3 04 88 43 02 AC 4A 88 C1 24 0F 88 03 C0 E9 04 88 4B 01 52 56 53 50 90 90 90 90 90 90 90 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_6_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "E8????????EB0E5A585997608A542420E9EE000000608B7424248B7C242C83CDFFEB0F90909090908A064688074701DB75078B1E83EEFC11DB8A0772EBB80100000001DB75078B1E83EEFC11DB11C001DB73EF75098B1E83EEFC11DB73E431C9"
	strings:
		$1 = { E8 ?? ?? ?? ?? EB 0E 5A 58 59 97 60 8A 54 24 20 E9 EE 00 00 00 60 8B 74 24 24 8B 7C 24 2C 83 CD FF EB 0F 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_7_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "E8????????608B7424248B7C242C83CDFFEB0F90909090908A064688074701DB75078B1E83EEFC11DB8A0772EBB80100000001DB75078B1E83EEFC11DB11C001DB73EF7509"
	strings:
		$1 = { E8 ?? ?? ?? ?? 60 8B 74 24 24 8B 7C 24 2C 83 CD FF EB 0F 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_8_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2D]"
		source = "Made by Retdec Team"
		pattern = "E8????????EB0E5A585997608A542420E902010000608B7424248B7C242C83CDFFEB0F90909090908A064688074701DB75078B1E83EEFC11DB8A0772EBB80100000001DB75078B1E83EEFC11DB11C001DB730B75198B1E83EEFC11DB72104801DB"
	strings:
		$1 = { E8 ?? ?? ?? ?? EB 0E 5A 58 59 97 60 8A 54 24 20 E9 02 01 00 00 60 8B 74 24 24 8B 7C 24 2C 83 CD FF EB 0F 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 48 01 DB }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_9_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2D]"
		source = "Made by Retdec Team"
		pattern = "E8????????608B7424248B7C242C83CDFFEB0F90909090908A064688074701DB75078B1E83EEFC11DB8A0772EBB80100000001DB75078B1E83EEFC11DB11C001DB730B7519"
	strings:
		$1 = { E8 ?? ?? ?? ?? 60 8B 74 24 24 8B 7C 24 2C 83 CD FF EB 0F 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_10_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2E]"
		source = "Made by Retdec Team"
		pattern = "E8????????EB0E5A585997608A542420E912010000608B7424248B7C242C83CDFFEB0F90909090908A064688074701DB75078B1E83EEFC11DB8A0772EBB80100000001DB75078B1E83EEFC11DB11C001DB730B75288B1E83EEFC11DB721F4801DB"
	strings:
		$1 = { E8 ?? ?? ?? ?? EB 0E 5A 58 59 97 60 8A 54 24 20 E9 12 01 00 00 60 8B 74 24 24 8B 7C 24 2C 83 CD FF EB 0F 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 28 8B 1E 83 EE FC 11 DB 72 1F 48 01 DB }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_11_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2E]"
		source = "Made by Retdec Team"
		pattern = "E8????????608B7424248B7C242C83CDFFEB0F90909090908A064688074701DB75078B1E83EEFC11DB8A0772EBB80100000001DB75078B1E83EEFC11DB11C001DB730B7528"
	strings:
		$1 = { E8 ?? ?? ?? ?? 60 8B 74 24 24 8B 7C 24 2C 83 CD FF EB 0F 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 28 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_12_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [LZMA]"
		source = "Made by Retdec Team"
		pattern = "E8????????555351524801FE564180F80E0F856C0A0000554889E5448B094989D04889F2488D7702568A07FFCA88C1"
	strings:
		$1 = { E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 41 80 F8 0E 0F 85 6C 0A 00 00 55 48 89 E5 44 8B 09 49 89 D0 48 89 F2 48 8D 77 02 56 8A 07 FF CA 88 C1 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_13_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "FC415B4180F802740DE9????????48FFC6881748FFC78A1601DB750A8B1E4883EEFC11DB8A1672E68D410141FFD3"
		start = 112
	strings:
		$1 = { FC 41 5B 41 80 F8 02 74 0D E9 ?? ?? ?? ?? 48 FF C6 88 17 48 FF C7 8A 16 01 DB 75 0A 8B 1E 48 83 EE FC 11 DB 8A 16 72 E6 8D 41 01 41 FF D3 }
	condition:
		for any of them : ( $ at elf.entry_point + 112 )
}
rule rule_14_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2D]"
		source = "Made by Retdec Team"
		pattern = "FC415B4180F805740DE9????????48FFC6881748FFC78A1601DB750A8B1E4883EEFC11DB8A1672E68D4101EB07FFC841FFD3"
		start = 112
	strings:
		$1 = { FC 41 5B 41 80 F8 05 74 0D E9 ?? ?? ?? ?? 48 FF C6 88 17 48 FF C7 8A 16 01 DB 75 0A 8B 1E 48 83 EE FC 11 DB 8A 16 72 E6 8D 41 01 EB 07 FF C8 41 FF D3 }
	condition:
		for any of them : ( $ at elf.entry_point + 112 )
}
rule rule_15_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2E]"
		source = "Made by Retdec Team"
		pattern = "FC415B4180F808740DE9????????48FFC6881748FFC78A1601DB750A8B1E4883EEFC11DB8A1672E68D4101EB07FFC841FFD3"
		start = 112
	strings:
		$1 = { FC 41 5B 41 80 F8 08 74 0D E9 ?? ?? ?? ?? 48 FF C6 88 17 48 FF C7 8A 16 01 DB 75 0A 8B 1E 48 83 EE FC 11 DB 8A 16 72 E6 8D 41 01 EB 07 FF C8 41 FF D3 }
	condition:
		for any of them : ( $ at elf.entry_point + 112 )
})x86_elf_packer";
