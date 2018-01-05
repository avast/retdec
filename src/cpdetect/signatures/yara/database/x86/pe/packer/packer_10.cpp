/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_10.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_10 =
R"x86_pe_packer(
rule rule_256_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.02a"
		pattern = "60E8????????5D81ED3ED943??B838??????03C52B850BDE43??898517DE43??80BD01DE43????7515FE8501DE43??E81D??????E87902????E81203????8B8503DE43??038517DE43??8944241C61FF"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_257_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.02b"
		pattern = "60E8????????5D81ED967843??B8907843??03C52B857D7C43??8985897C43??80BD747C43"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_258_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.02b"
		pattern = "60E8000000005D81ED96784300B89078430003C5"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_259_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.03b"
		pattern = "60E8????????5D81EDAE9843??B8A89843??03C52B85189D43??8985249D43??80BD0E9D43"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_260_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.04b"
		pattern = "60E8????????5D81ED????????B8????????03C52B85??129D??89851E9D????80BD089D"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? ?? 80 BD 08 9D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_261_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.05b"
		pattern = "60E8????????5D81EDCE3A44??B8C83A44??03C52B85B53E44??8985C13E44??80BDAC3E44"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_262_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.05b"
		pattern = "7500E9"
	strings:
		$1 = { 75 00 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_263_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.06b1"
		pattern = "60E8????????5D81EDEAA843??B8E4A843??03C52B8578AD43??898584AD43??80BD6EAD43"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_264_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.06b"
		pattern = "9090907500E9"
	strings:
		$1 = { 90 90 90 75 00 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_265_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.07b DLL"
		pattern = "60E8000000005D????????????B8????????03C5"
	strings:
		$1 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_266_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.07b"
		pattern = "60E8????????5D81ED????????B8????????03C52B85??0BDE??898517DE????80BD01DE"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE ?? ?? 80 BD 01 DE }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_267_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08"
		pattern = "909090750190E9"
	strings:
		$1 = { 90 90 90 75 01 90 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_268_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08"
		pattern = "9090907501FFE9"
	strings:
		$1 = { 90 90 90 75 01 FF E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_269_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08.01 - 1.08.02"
		pattern = "60EB0A5DEB02FF2545FFE5E8E9E8F1FFFFFFE981??????44??BB10??44??03DD2B9D"
	strings:
		$1 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_270_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08.03"
		pattern = "60E8000000005D????????????BB????????03DD2B9DB150440083BDAC50440000899DBB4E"
	strings:
		$1 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_271_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08.04"
		pattern = "60E841060000EB41"
	strings:
		$1 = { 60 E8 41 06 00 00 EB 41 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_272_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08.x"
		pattern = "60EB035DFFE5E8F8FFFFFF81ED1B6A4400BB106A440003DD2B9D2A"
	strings:
		$1 = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_273_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.000"
		pattern = "60E870050000EB4C"
	strings:
		$1 = { 60 E8 70 05 00 00 EB 4C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_274_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.001"
		pattern = "60E872050000EB4C"
	strings:
		$1 = { 60 E8 72 05 00 00 EB 4C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_275_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.1"
		pattern = "60E872050000EB3387DB9000"
	strings:
		$1 = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_276_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.11b"
		pattern = "60E802000000EB095D5581ED39394400C3E93D040000"
	strings:
		$1 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_277_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.11c"
		pattern = "60E802000000EB095D5581ED39394400C3E959040000"
	strings:
		$1 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_278_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.11d"
		pattern = "60E802000000EB095D5581ED39394400C36?"
	strings:
		$1 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 6? }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_279_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.12"
		extra = "or ASProtect (2.x)"
		pattern = "60E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB"
	strings:
		$1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_280_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.12"
		source = "Generated based on AVG tests"
		pattern = "60E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00?0??0083BD2204000000899D220400000F85650300008D852E04000050FF954D0F00008985260400008BF88D5D5E5350FF95490F000089854D0500008D5D6B5357FF95490F00"
	strings:
		$1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?0 ?? 00 83 BD 22 04 00 00 00 89 9D 22 04 00 00 0F 85 65 03 00 00 8D 85 2E 04 00 00 50 FF 95 4D 0F 00 00 89 85 26 04 00 00 8B F8 8D 5D 5E 53 50 FF 95 49 0F 00 00 89 85 4D 05 00 00 8D 5D 6B 53 57 FF 95 49 0F 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_281_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.20"
		source = "Generated based on AVG tests"
		pattern = "60E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00?0??0083BD7D04000000899D7D0400000F85C00300008D858904000050FF95090F00008985810400008BF08D7D515756FF95050F0000ABB000AE75FD380775EE8D457AFFE056"
	strings:
		$1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?0 ?? 00 83 BD 7D 04 00 00 00 89 9D 7D 04 00 00 0F 85 C0 03 00 00 8D 85 89 04 00 00 50 FF 95 09 0F 00 00 89 85 81 04 00 00 8B F0 8D 7D 51 57 56 FF 95 05 0F 00 00 AB B0 00 AE 75 FD 38 07 75 EE 8D 45 7A FF E0 56 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_282_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.24 or 2.28"
		source = "Generated based on AVG tests"
		pattern = "60E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00?0??0083BD8804000000899D880400000F85CB0300008D859404000050FF95A90F000089858C0400008BF08D7D515756FF95A50F0000ABB000AE75FD380775EE8D457AFFE056"
	strings:
		$1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?0 ?? 00 83 BD 88 04 00 00 00 89 9D 88 04 00 00 0F 85 CB 03 00 00 8D 85 94 04 00 00 50 FF 95 A9 0F 00 00 89 85 8C 04 00 00 8B F0 8D 7D 51 57 56 FF 95 A5 0F 00 00 AB B0 00 AE 75 FD 38 07 75 EE 8D 45 7A FF E0 56 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_283_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.xx"
		pattern = "A803????617508B801??????C20C??68????????C38B852604????8D8D3B04????5150FF95"
	strings:
		$1 = { A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_284_ASPack_ASPROTECT {
	meta:
		tool = "P"
		name = "ASPack-ASPROTECT"
		pattern = "60E9D5040000F7100F0F0F9F6C90FCDB8C540FCACF8C540F12EC3AAC2795540F92CC0F94540F0F98AC0F94540F1E9458120F0FD694D28C540F0F0F0F0F9C9417"
	strings:
		$1 = { 60 E9 D5 04 00 00 F7 10 0F 0F 0F 9F 6C 90 FC DB 8C 54 0F CA CF 8C 54 0F 12 EC 3A AC 27 95 54 0F 92 CC 0F 94 54 0F 0F 98 AC 0F 94 54 0F 1E 94 58 12 0F 0F D6 94 D2 8C 54 0F 0F 0F 0F 0F 9C 94 17 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_285_ASPack_ASPROTECT {
	meta:
		tool = "P"
		name = "ASPack-ASPROTECT"
		pattern = "60E9DB05000047605F5F5FEFBCE04CA715A45F1A9B15A45F623C8AFCE01DA45FE21CD71CA45F5FE8FCD71CA45F6EE4A8625F5F26E49E15A45F5F5F5F5FECE4DF"
	strings:
		$1 = { 60 E9 DB 05 00 00 47 60 5F 5F 5F EF BC E0 4C A7 15 A4 5F 1A 9B 15 A4 5F 62 3C 8A FC E0 1D A4 5F E2 1C D7 1C A4 5F 5F E8 FC D7 1C A4 5F 6E E4 A8 62 5F 5F 26 E4 9E 15 A4 5F 5F 5F 5F 5F EC E4 DF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_286_ASPack_ASPROTECT {
	meta:
		tool = "P"
		name = "ASPack-ASPROTECT"
		pattern = "60E9DC050000C19EB7BBD92C153DC6E56D01D957F4711E9DBA98043A397A1E9D3A79515AFDBBD925553496E2B7CA5EE6BABBD9633DFB8FE2B7BBD99CB7485E1D"
	strings:
		$1 = { 60 E9 DC 05 00 00 C1 9E B7 BB D9 2C 15 3D C6 E5 6D 01 D9 57 F4 71 1E 9D BA 98 04 3A 39 7A 1E 9D 3A 79 51 5A FD BB D9 25 55 34 96 E2 B7 CA 5E E6 BA BB D9 63 3D FB 8F E2 B7 BB D9 9C B7 48 5E 1D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_287_ASPack_ASPROTECT {
	meta:
		tool = "P"
		name = "ASPack-ASPROTECT"
		pattern = "60E9F305000067A022E78F317F6662E994A28F1A1E51CAA1213AA43CA359CAA1A15AF71C67E78F28BF9F32E422E80AE821E78F66A7D839E422E78FA1226A0A21"
	strings:
		$1 = { 60 E9 F3 05 00 00 67 A0 22 E7 8F 31 7F 66 62 E9 94 A2 8F 1A 1E 51 CA A1 21 3A A4 3C A3 59 CA A1 A1 5A F7 1C 67 E7 8F 28 BF 9F 32 E4 22 E8 0A E8 21 E7 8F 66 A7 D8 39 E4 22 E7 8F A1 22 6A 0A 21 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_288_ASPack_ASPROTECT {
	meta:
		tool = "P"
		name = "ASPack-ASPROTECT"
		pattern = "E801000000EB5DBB??FFFFFF03DD81EB008A0F00EB02EB39C645100033C08B733CFF7433580FB75433064A4A8DBC33F80000008B770C8B4F100BC9740703F3"
	strings:
		$1 = { E8 01 00 00 00 EB 5D BB ?? FF FF FF 03 DD 81 EB 00 8A 0F 00 EB 02 EB 39 C6 45 10 00 33 C0 8B 73 3C FF 74 33 58 0F B7 54 33 06 4A 4A 8D BC 33 F8 00 00 00 8B 77 0C 8B 4F 10 0B C9 74 07 03 F3 }
	condition:
		for any of them : ( $ in (pe.entry_point .. pe.entry_point + 1) )
}
rule rule_289_ASPR_Stripper {
	meta:
		tool = "P"
		name = "ASPR Stripper"
		version = "2.x"
		pattern = "BB????????E9????????609CFCBF????????B9????????F3AA9D61C3558BEC"
	strings:
		$1 = { BB ?? ?? ?? ?? E9 ?? ?? ?? ?? 60 9C FC BF ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 AA 9D 61 C3 55 8B EC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_290_ASProtect_SKE {
	meta:
		tool = "P"
		name = "ASProtect SKE"
		version = "2.1, 2.2, 2.1x EXE"
		pattern = "9060E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00??????807D4D01750C8B74242883FE01895D4E75318D45535053FFB5ED0900008D453550E98200000000000000000000000000000000"
	strings:
		$1 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_291_ASProtect {
	meta:
		tool = "P"
		name = "ASProtect"
		pattern = "????????????????????????????????????????????????????????????????????????????????????????????????????????2B95CD3C400081EA2C00000080BD083D40000074188B85ED3C40000385F73C40003B??7401"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2B 95 CD 3C 40 00 81 EA 2C 00 00 00 80 BD 08 3D 40 00 00 74 18 8B 85 ED 3C 40 00 03 85 F7 3C 40 00 3B ?? 74 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_292_ASProtect {
	meta:
		tool = "P"
		name = "ASProtect"
		pattern = "60??????????905D??????????????????????03DD"
	strings:
		$1 = { 60 ?? ?? ?? ?? ?? 90 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 DD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_293_ASProtect {
	meta:
		tool = "P"
		name = "ASProtect"
		pattern = "68????????E8????0000C3C3"
	strings:
		$1 = { 68 ?? ?? ?? ?? E8 ?? ?? 00 00 C3 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_294_ASProtect {
	meta:
		tool = "P"
		name = "ASProtect"
		pattern = "9060E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00????00807D4D01750C8B74242883FE01895D4E75318D45535053FFB5DD0900008D453550E98200000000000000000000000000000000"
	strings:
		$1 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_295_ASProtect {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.0"
		pattern = "60E801??????905D81ED????????BB????????03DD2B9D"
	strings:
		$1 = { 60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_296_ASProtect {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.1 BRS"
		pattern = "60E9??05"
	strings:
		$1 = { 60 E9 ?? 05 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_297_ASProtect {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.1 MTE"
		pattern = "60E9????????9178797979E9"
	strings:
		$1 = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_298_ASProtect {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.1"
		pattern = "60E9??04????E9??????????????EE"
	strings:
		$1 = { 60 E9 ?? 04 ?? ?? E9 ?? ?? ?? ?? ?? ?? ?? EE }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_299_ASProtect {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.1b"
		pattern = "9060E9??04"
	strings:
		$1 = { 90 60 E9 ?? 04 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_300_ASProtect {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.1c"
		pattern = "9060E81B??????E9FC"
	strings:
		$1 = { 90 60 E8 1B ?? ?? ?? E9 FC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
