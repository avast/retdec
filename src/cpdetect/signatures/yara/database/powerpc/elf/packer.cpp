/**
 * @file src/cpdetect/signatures/yara/database/powerpc/elf/packer.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *powerpcElfPacker =
R"powerpc_elf_pack(rule rule_1_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [LZMA]"
		source = "Made by Retdec Team"
		pattern = "?1????480E000728?0??8240A602087C7833C97C00000681782BA77CFEFFA438020083380800019000000388FEE80B547E070254"
	strings:
		$1 = { ( ?1 | ?3 | ?5 | ?7 | ?9 | ?B | ?D | ?F ) ?? ?? ( 48 | 49 | 4A | 4B | 4C | 4D | 4E | 4F ) 0E 00 07 28 ( ?0 | ?2 | ?4 | ?6 | ?8 | ?A | ?C | ?E ) ?? 82 40 A6 02 08 7C 78 33 C9 7C 00 00 06 81 78 2B A7 7C FE FF A4 38 02 00 83 38 08 00 01 90 00 00 03 88 FE E8 0B 54 7E 07 02 54 }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_2_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2B]"
		pattern = "?1????48EC29007CA602A87D02000728?0??82400000A690141A847C0080003C0080203DFFFF6338FFFFA538FFFF4039?0????48"
	strings:
		$1 = { ( ?1 | ?3 | ?5 | ?7 | ?9 | ?B | ?D | ?F ) ?? ?? ( 48 | 49 | 4A | 4B | 4C | 4D | 4E | 4F ) EC 29 00 7C A6 02 A8 7D 02 00 07 28 ( ?0 | ?2 | ?4 | ?6 | ?8 | ?A | ?C | ?E ) ?? 82 40 00 00 A6 90 14 1A 84 7C 00 80 00 3C 00 80 20 3D FF FF 63 38 FF FF A5 38 FF FF 40 39 ( ?0 | ?2 | ?4 | ?6 | ?8 | ?A | ?C | ?E ) ?? ?? ( 48 | 49 | 4A | 4B | 4C | 4D | 4E | 4F ) }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_3_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2D]"
		pattern = "?1????48EC29007CA602A87D05000728?0??82400000A690141A847C0080003C0080203DFFFF6338FFFFA538FFFF4039?0????48"
	strings:
		$1 = { ( ?1 | ?3 | ?5 | ?7 | ?9 | ?B | ?D | ?F ) ?? ?? ( 48 | 49 | 4A | 4B | 4C | 4D | 4E | 4F ) EC 29 00 7C A6 02 A8 7D 05 00 07 28 ( ?0 | ?2 | ?4 | ?6 | ?8 | ?A | ?C | ?E ) ?? 82 40 00 00 A6 90 14 1A 84 7C 00 80 00 3C 00 80 20 3D FF FF 63 38 FF FF A5 38 FF FF 40 39 ( ?0 | ?2 | ?4 | ?6 | ?8 | ?A | ?C | ?E ) ?? ?? ( 48 | 49 | 4A | 4B | 4C | 4D | 4E | 4F ) }
	condition:
		for any of them : ( $ at elf.entry_point )
}
rule rule_4_UPX
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2E]"
		pattern = "?1????48EC29007CA602A87D08000728?0??82400000A690141A847C0080003C0080203DFFFF6338FFFFA538FFFF4039?0????48"
	strings:
		$1 = { ( ?1 | ?3 | ?5 | ?7 | ?9 | ?B | ?D | ?F ) ?? ?? ( 48 | 49 | 4A | 4B | 4C | 4D | 4E | 4F ) EC 29 00 7C A6 02 A8 7D 08 00 07 28 ( ?0 | ?2 | ?4 | ?6 | ?8 | ?A | ?C | ?E ) ?? 82 40 00 00 A6 90 14 1A 84 7C 00 80 00 3C 00 80 20 3D FF FF 63 38 FF FF A5 38 FF FF 40 39 ( ?0 | ?2 | ?4 | ?6 | ?8 | ?A | ?C | ?E ) ?? ?? ( 48 | 49 | 4A | 4B | 4C | 4D | 4E | 4F ) }
	condition:
		for any of them : ( $ at elf.entry_point )
})powerpc_elf_pack";
