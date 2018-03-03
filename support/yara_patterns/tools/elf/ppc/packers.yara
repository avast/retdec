/*
 * YARA rules for PowerPC ELF packer detection.
 * Copyright (c) 2017 Avast Software, licensed under the MIT license
 */

import "elf"

rule upx_39x_lzma_le
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [LZMA]"
		source = "Made by Retdec Team"
		pattern = "??????4?0E000728????8240A602087C7833C97C00000681782BA77CFEFFA438020083380800019000000388FEE80B547E070254"
	strings:
		$1 = { ?? ?? ?? 4? 0E 00 07 28 ?? ?? 82 40 A6 02 08 7C 78 33 C9 7C 00 00 06 81 78 2B A7 7C FE FF A4 38 02 00 83 38 08 00 01 90 00 00 03 88 FE E8 0B 54 7E 07 02 54 }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2b_le
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2B]"
		pattern = "??????4?EC29007CA602A87D02000728????82400000A690141A847C0080003C0080203DFFFF6338FFFFA538FFFF4039??????4?"
	strings:
		$1 = { ?? ?? ?? 4? EC 29 00 7C A6 02 A8 7D 02 00 07 28 ?? ?? 82 40 00 00 A6 90 14 1A 84 7C 00 80 00 3C 00 80 20 3D FF FF 63 38 FF FF A5 38 FF FF 40 39 ?? ?? ?? 4? }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2d_le
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2D]"
		pattern = "??????4?EC29007CA602A87D05000728????82400000A690141A847C0080003C0080203DFFFF6338FFFFA538FFFF4039??????4?"
	strings:
		$1 = { ?? ?? ?? 4? EC 29 00 7C A6 02 A8 7D 05 00 07 28 ?? ?? 82 40 00 00 A6 90 14 1A 84 7C 00 80 00 3C 00 80 20 3D FF FF 63 38 FF FF A5 38 FF FF 40 39 ?? ?? ?? 4? }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2e_le
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2E]"
		pattern = "??????4?EC29007CA602A87D08000728????82400000A690141A847C0080003C0080203DFFFF6338FFFFA538FFFF4039??????4?"
	strings:
		$1 = { ?? ?? ?? 4? EC 29 00 7C A6 02 A8 7D 08 00 07 28 ?? ?? 82 40 00 00 A6 90 14 1A 84 7C 00 80 00 3C 00 80 20 3D FF FF 63 38 FF FF A5 38 FF FF 40 39 ?? ?? ?? 4? }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_lzma_be
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [LZMA]"
		source = "Made by Retdec Team"
		pattern = "4???????2807000E4082????7C0802A67CC93378810600007CA72B7838A4FFFE388300029001000888030000540BE8FE5402077E"
	strings:
		$1 = { 4? ?? ?? ?? 28 07 00 0E 40 82 ?? ?? 7C 08 02 A6 7C C9 33 78 81 06 00 00 7C A7 2B 78 38 A4 FF FE 38 83 00 02 90 01 00 08 88 03 00 00 54 0B E8 FE 54 02 07 7E }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2b_be
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2B]"
		pattern = "4???????7C0029EC7DA802A6280700024082????90A600007C841A143C0080003D2080003863FFFF38A5FFFF3940FFFF4?"
	strings:
		$1 = { 4? ?? ?? ?? 7C 00 29 EC 7D A8 02 A6 28 07 00 02 40 82 ?? ?? 90 A6 00 00 7C 84 1A 14 3C 00 80 00 3D 20 80 00 38 63 FF FF 38 A5 FF FF 39 40 FF FF 4? }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2d_be
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2D]"
		pattern = "4???????7C0029EC7DA802A6280700054082????90A600007C841A143C0080003D2080003863FFFF38A5FFFF3940FFFF4?"
	strings:
		$1 = { 4? ?? ?? ?? 7C 00 29 EC 7D A8 02 A6 28 07 00 05 40 82 ?? ?? 90 A6 00 00 7C 84 1A 14 3C 00 80 00 3D 20 80 00 38 63 FF FF 38 A5 FF FF 39 40 FF FF 4? }
	condition:
		$1 at elf.entry_point
}

rule upx_39x_nrv2e_be
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2E]"
		pattern = "4???????7C0029EC7DA802A6280700084082????90A600007C841A143C0080003D2080003863FFFF38A5FFFF3940FFFF4?"
	strings:
		$1 = { 4? ?? ?? ?? 7C 00 29 EC 7D A8 02 A6 28 07 00 08 40 82 ?? ?? 90 A6 00 00 7C 84 1A 14 3C 00 80 00 3D 20 80 00 38 63 FF FF 38 A5 FF FF 39 40 FF FF 4? }
	condition:
		$1 at elf.entry_point
}

rule upx_394_lzma_be
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.94 [LZMA]"
		source = "Made by Retdec Team"
		pattern = "4???????2807000E4082????9421FFE87C0802A67CC93378810600007CA72B7838A4FFFE388300029001000888030000540BE8FE5402077E"
	strings:
		$1 = { 4? ?? ?? ?? 28 07 00 0E 40 82 ?? ?? 94 21 FF E8 7C 08 02 A6 7C C9 33 78 81 06 00 00 7C A7 2B 78 38 A4 FF FE 38 83 00 02 90 01 00 08 88 03 00 00 54 0B E8 FE 54 02 07 7E }
	condition:
		$1 at elf.entry_point
}
