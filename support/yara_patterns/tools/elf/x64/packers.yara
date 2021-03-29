/*
 * YARA rules for x64 ELF packer detection.
 * Copyright (c) 2017 Avast Software, licensed under the MIT license
 */

import "elf"

rule upx_39x_lzma
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [LZMA]"
		source = "Made by Retdec Team"
		pattern = "E8????????555351524801FE564180F80E0F856C0A0000554889E5448B094989D04889F2488D7702568A07FFCA88C1"
	strings:
		$1 = { E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 41 80 F8 0E 0F 85 6C 0A 00 00 55 48 89 E5 44 8B 09 49 89 D0 48 89 F2 48 8D 77 02 56 8A 07 FF CA 88 C1 }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2b
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "FC415B4180F802740DE9????????48FFC6881748FFC78A1601DB750A8B1E4883EEFC11DB8A1672E68D410141FFD3"
		start = 112
	strings:
		$1 = { FC 41 5B 41 80 F8 02 74 0D E9 ?? ?? ?? ?? 48 FF C6 88 17 48 FF C7 8A 16 01 DB 75 0A 8B 1E 48 83 EE FC 11 DB 8A 16 72 E6 8D 41 01 41 FF D3 }
	condition:
		$1 at elf.entry_point + 112
}

rule upx_39x_nrv2d
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2D]"
		source = "Made by Retdec Team"
		pattern = "FC415B4180F805740DE9????????48FFC6881748FFC78A1601DB750A8B1E4883EEFC11DB8A1672E68D4101EB07FFC841FFD3"
		start = 112
	strings:
		$1 = { FC 41 5B 41 80 F8 05 74 0D E9 ?? ?? ?? ?? 48 FF C6 88 17 48 FF C7 8A 16 01 DB 75 0A 8B 1E 48 83 EE FC 11 DB 8A 16 72 E6 8D 41 01 EB 07 FF C8 41 FF D3 }
	condition:
		$1 at elf.entry_point + 112
}

rule upx_39x_nrv2e
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2E]"
		source = "Made by Retdec Team"
		pattern = "FC415B4180F808740DE9????????48FFC6881748FFC78A1601DB750A8B1E4883EEFC11DB8A1672E68D4101EB07FFC841FFD3"
		start = 112
	strings:
		$1 = { FC 41 5B 41 80 F8 08 74 0D E9 ?? ?? ?? ?? 48 FF C6 88 17 48 FF C7 8A 16 01 DB 75 0A 8B 1E 48 83 EE FC 11 DB 8A 16 72 E6 8D 41 01 EB 07 FF C8 41 FF D3 }
	condition:
		$1 at elf.entry_point + 112
}

rule upx_394_lzma
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.94 [LZMA]"
		source = "Made by Retdec Team"
		pattern = "E8????????EB0E5A585997608A542420E9110B0000608B7424248B7C242C83CDFF89E58B5528AC4A88C12407C0E903BB00FDFFFFD3E38DA45C90F1FFFF83E4E06A006A"
	strings:
		$1 = { E8 ?? ?? ?? ?? EB 0E 5A 58 59 97 60 8A 54 24 20 E9 11 0B 00 00 60 8B 74 24 24 8B 7C 24 2C 83 CD FF 89 E5 8B 55 28 AC 4A 88 C1 24 07 C0 E9 03 BB 00 FD FF FF D3 E3 8D A4 5C 90 F1 FF FF 83 E4 E0 6A 00 6A }
	condition:
		$1 at elf.entry_point
}

rule upx_394_lzma_2
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [LZMA]"
		source = "Made by Retdec Team"
		pattern = "E8????????555351524801FE564180F80E0F85650A0000554889E5448B094989D04889F2488D7702568A07FFCA88C12407C0E90348C7C300FDFFFF48D3E388C1488D9C5C88"
	strings:
		$1 = { E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 41 80 F8 0E 0F 85 65 0A 00 00 55 48 89 E5 44 8B 09 49 89 D0 48 89 F2 48 8D 77 02 56 8A 07 FF CA 88 C1 24 07 C0 E9 03 48 C7 C3 00 FD FF FF 48 D3 E3 88 C1 48 8D 9C 5C 88 }
	condition:
		$1 at elf.entry_point
}

rule x64_lzma_v393
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.93 [LZMA]"
		source = "Made by Jan Neduchal"
		pattern = "E8????????555351524801FE5641??????0F85????????554889E5448B094989D04889F2488D7702568A07FFCA88C12407"
	strings:
		$h00 = { E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 41 ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 48 89 E5 44 8B 09 49 89 D0 48 89 F2 48 8D 77 02 56 8A 07 FF CA 88 C1 24 07 }
	condition:
		$h00 at elf.entry_point
}


rule x64_nrv2x_v393
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.93 [NRV2x]"
		source = "Made by Jan Neduchal"
		pattern = "E8????????555351524801FE564889FE4889D731DB31C94883CDFFE8????????01DB74??F3C38B1E4883EEFC11DB8A16F3"
	strings:
		$h00 = { E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 48 89 FE 48 89 D7 31 DB 31 C9 48 83 CD FF E8 ?? ?? ?? ?? 01 DB 74 ?? F3 C3 8B 1E 48 83 EE FC 11 DB 8A 16 F3 }
	condition:
		$h00 at elf.entry_point
}


rule x64_lzma_v395
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.95 [LZMA]"
		source = "Made by Jan Neduchal"
		pattern = "5052E8????????555351524801FE5641??????0F85????????554889E5448B094989D04889F2488D7702568A07FFCA88C1"
	strings:
		$h00 = { 50 52 E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 41 ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 48 89 E5 44 8B 09 49 89 D0 48 89 F2 48 8D 77 02 56 8A 07 FF CA 88 C1 }
	condition:
		$h00 at elf.entry_point
}


rule x64_nrv2x_v395
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.95 [NRV2x]"
		source = "Made by Jan Neduchal"
		pattern = "5052E8????????555351524801FE564889FE4889D731DB31C94883CDFFE8????????01DB74??F3C38B1E4883EEFC11DB8A"
	strings:
		$h00 = { 50 52 E8 ?? ?? ?? ?? 55 53 51 52 48 01 FE 56 48 89 FE 48 89 D7 31 DB 31 C9 48 83 CD FF E8 ?? ?? ?? ?? 01 DB 74 ?? F3 C3 8B 1E 48 83 EE FC 11 DB 8A }
	condition:
		$h00 at elf.entry_point
}

