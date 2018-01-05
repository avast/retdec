/**
 * @file src/cpdetect/signatures/yara/database/x86/macho/packer.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86MachOPacker =
R"x86_macho_packer(rule rule_1_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [LZMA]"
		source = "Made by Retdec Team"
		pattern = "E8????????608B7424248B7C242C83CDFF89E58B5528AC4A88C12407C0E903"
	strings:
		$1 = { E8 ?? ?? ?? ?? 60 8B 74 24 24 8B 7C 24 2C 83 CD FF 89 E5 8B 55 28 AC 4A 88 C1 24 07 C0 E9 03 }
	condition:
		for any of them : ( $ at macho.entry_point )
}
rule rule_2_UPX
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
		for any of them : ( $ at macho.entry_point )
}
rule rule_3_UPX
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
		for any of them : ( $ at macho.entry_point )
}
rule rule_4_UPX
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
		for any of them : ( $ at macho.entry_point )
}
rule rule_5_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [LZMA]"
		source = "Made by Retdec Team"
		pattern = "E8????????555351524801FE564180F80E0F856C0A0000554889E5448B094989D0"
	strings:
		$1 = { E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 41 80 F8 0E 0F 85 6C 0A 00 00 55 48 89 E5 44 8B 09 49 89 D0 }
	condition:
		for any of them : ( $ at macho.entry_point )
}
rule rule_6_UPX
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
		for any of them : ( $ at macho.entry_point + 112 )
}
rule rule_7_UPX
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
		for any of them : ( $ at macho.entry_point + 112 )
}
rule rule_8_UPX
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
		for any of them : ( $ at macho.entry_point + 112 )
})x86_macho_packer";
