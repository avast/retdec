/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_42.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_42 =
R"x86_pe_packer(
rule rule_1164_PolyCrypt_PE {
	meta:
		tool = "P"
		name = "PolyCrypt PE"
		version = "2.1.4b, 2.1.5"
		pattern = "506F6C7943727970742050452028632920323030342D323030352C204A4C6162536F6674776172652E0050004300500045"
	strings:
		$1 = { 50 6F 6C 79 43 72 79 70 74 20 50 45 20 28 63 29 20 32 30 30 34 2D 32 30 30 35 2C 20 4A 4C 61 62 53 6F 66 74 77 61 72 65 2E 00 50 00 43 00 50 00 45 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1165_PolyCrypt_PE {
	meta:
		tool = "P"
		name = "PolyCrypt PE"
		version = "2.1.4b, 2.1.5"

		pattern = "918BF4ADFEC9803408??E2FAC360E8EDFFFFFFEB"
	strings:
		$1 = { 91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1166_PolyCryptor {
	meta:
		tool = "P"
		name = "PolyCryptor"
		pattern = "EB??28506F6C7953637279707420??????20627920534D5429"
	strings:
		$1 = { EB ?? 28 50 6F 6C 79 53 63 72 79 70 74 20 ?? ?? ?? 20 62 79 20 53 4D 54 29 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1167_PolyEnE {
	meta:
		tool = "P"
		name = "PolyEnE"
		version = "0.01+"
		pattern = "506F6C79456E45004D657373616765426F7841005553455233322E646C6C"
	strings:
		$1 = { 50 6F 6C 79 45 6E 45 00 4D 65 73 73 61 67 65 42 6F 78 41 00 55 53 45 52 33 32 2E 64 6C 6C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1168_PolyEnE {
	meta:
		tool = "P"
		name = "PolyEnE"
		version = "0.01+"
		pattern = "600000E0????????????????????????????????????????????????????????????????????????600000E0"
	strings:
		$1 = { 60 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 00 00 E0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1169_PoPa {
	meta:
		tool = "P"
		name = "PoPa"
		version = "0.01"
		pattern = "558BEC83C4EC53565733C08945ECB8A43E0010E830F6FFFF33C05568BE400010????????89206A0068800000006A036A006A0168000000808D55EC33C0E862E7FFFF8B45ECE832F2FFFF50E8B4F6FFFFA36466001033D255689340001064FF32648922833D64660010FF0F843A0100006A006A006A00A16466001050E89BF6FFFF83E81050A16466001050E8BCF6FFFF6A0068806600106A106868660010A16466001050E88BF6FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 A4 3E 00 10 E8 30 F6 FF FF 33 C0 55 68 BE 40 00 10 ?? ?? ?? ?? 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 62 E7 FF FF 8B 45 EC E8 32 F2 FF FF 50 E8 B4 F6 FF FF A3 64 66 00 10 33 D2 55 68 93 40 00 10 64 FF 32 64 89 22 83 3D 64 66 00 10 FF 0F 84 3A 01 00 00 6A 00 6A 00 6A 00 A1 64 66 00 10 50 E8 9B F6 FF FF 83 E8 10 50 A1 64 66 00 10 50 E8 BC F6 FF FF 6A 00 68 80 66 00 10 6A 10 68 68 66 00 10 A1 64 66 00 10 50 E8 8B F6 FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1170_PPC_PROTECT {
	meta:
		tool = "P"
		name = "PPC-PROTECT"
		version = "1.1x"
		pattern = "FF5F2DE920009FE5000090E518008FE518009FE5000090E510008FE50100A0E3000000EB020000EA04F01FE5"
	strings:
		$1 = { FF 5F 2D E9 20 00 9F E5 00 00 90 E5 18 00 8F E5 18 00 9F E5 00 00 90 E5 10 00 8F E5 01 00 A0 E3 00 00 00 EB 02 00 00 EA 04 F0 1F E5 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1171_PrincessSandy {
	meta:
		tool = "P"
		name = "PrincessSandy"
		version = "1.0"
		pattern = "6827114000E83C0100006A00E841010000A3002040008B583C03D80FB743140FB74B068D7C1818813F2E4C4F41740B83C7284975F2E9A70000008B5F0C031D00204000891D042040008BFB83C704684C20400068082040006A006A006A206A006A006A00576A00E8CE00000085C07478BD50C300008B3D042040008B078D3C0783C704893D042040008B0F83C7048B1F83C7044D85ED7457606A0051685C20400053FF354C2040"
	strings:
		$1 = { 68 27 11 40 00 E8 3C 01 00 00 6A 00 E8 41 01 00 00 A3 00 20 40 00 8B 58 3C 03 D8 0F B7 43 14 0F B7 4B 06 8D 7C 18 18 81 3F 2E 4C 4F 41 74 0B 83 C7 28 49 75 F2 E9 A7 00 00 00 8B 5F 0C 03 1D 00 20 40 00 89 1D 04 20 40 00 8B FB 83 C7 04 68 4C 20 40 00 68 08 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 57 6A 00 E8 CE 00 00 00 85 C0 74 78 BD 50 C3 00 00 8B 3D 04 20 40 00 8B 07 8D 3C 07 83 C7 04 89 3D 04 20 40 00 8B 0F 83 C7 04 8B 1F 83 C7 04 4D 85 ED 74 57 60 6A 00 51 68 5C 20 40 00 53 FF 35 4C 20 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1172_Private_exe_Protector {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "1.8"
		pattern = "A4B302E86D00000073F631C9E864000000731C31C0E85B0000007323B30241B010E84F00000010C073F7753FAAEBD4E84D00000029D97510E842000000EB28ACD1E8744D11C9EB1C9148C1E008ACE82C0000003D007D0000730A80FC05730683F87F770241419589E8B3015689FE29C6F3A45EEB8E00D275058A164610D2C331C941E8EEFFFFFF11C9E8E7FFFFFF72F2C331FF31F6C3"
	strings:
		$1 = { A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 FF 31 F6 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1173_Private_exe_Protector {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "1.8"
		pattern = "BBDCEE0D76D9D08D1685D890D9D0"
	strings:
		$1 = { BB DC EE 0D 76 D9 D0 8D 16 85 D8 90 D9 D0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1174_Private_exe_Protector {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "1.8 - 1.9"
		pattern = "00000000000000000000000000000000000000004B45524E454C33322E444C4C00????????0000000000004578697450726F63657373"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1175_Private_exe_Protector {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "1.9.7"
		pattern = "558BEC83C4F4FC5357568B7424208B7C242466813E4A430F85A502000083C60A33DBBA00000080C744241408000000438DA424000000008BFF03D275088B1683C604F913D2732C8B4C241033C08DA42400000000050000000003D275088B1683C604F913D213C04975EF0244240C880747EBC603D275088B1683C604F913D20F826E01000003D275088B1683C604F913D20F83DC000000B90400000033C08DA424000000008D64240003D275088B1683C604F913D213C04975EF4874B10F89EF01000003D275088B1683C604F913D27342BD00010000B90800000033C08DA42400000000050000000003D275088B1683C604F913D213C04975EF8807474D75D6"
	strings:
		$1 = { 55 8B EC 83 C4 F4 FC 53 57 56 8B 74 24 20 8B 7C 24 24 66 81 3E 4A 43 0F 85 A5 02 00 00 83 C6 0A 33 DB BA 00 00 00 80 C7 44 24 14 08 00 00 00 43 8D A4 24 00 00 00 00 8B FF 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 2C 8B 4C 24 10 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 02 44 24 0C 88 07 47 EB C6 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 82 6E 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 83 DC 00 00 00 B9 04 00 00 00 33 C0 8D A4 24 00 00 00 00 8D 64 24 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 48 74 B1 0F 89 EF 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 42 BD 00 01 00 00 B9 08 00 00 00 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 88 07 47 4D 75 D6 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1176_Private_exe_Protector {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "1.x"
		pattern = "B8????????B9??9001??BE??1040??68509141??6801??????C3"
	strings:
		$1 = { B8 ?? ?? ?? ?? B9 ?? 90 01 ?? BE ?? 10 40 ?? 68 50 91 41 ?? 68 01 ?? ?? ?? C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1177_Private_exe_Protector {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "2.0"
		pattern = "0000000000000000????????????????00000000000000000000000000000000000000004B45524E454C33322E444C4C00????????000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1178_Private_exe_Protector {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "2.0"
		pattern = "89????380000008B??0000000081??????????89??0000000081??0400000081??0400000081??000000000F85D6FFFFFF"
	strings:
		$1 = { 89 ?? ?? 38 00 00 00 8B ?? 00 00 00 00 81 ?? ?? ?? ?? ?? 89 ?? 00 00 00 00 81 ?? 04 00 00 00 81 ?? 04 00 00 00 81 ?? 00 00 00 00 0F 85 D6 FF FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1179_Private_exe_Protector {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "2.15 - 2.20"
		pattern = "00000000000000000000000000????????????????00000000000000000000000000000000000000004B45524E454C33322E444C4C0000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1180_Private_exe_Protector {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "2.30 - 2.4x"
		pattern = "000000000000000000000000????????????????????????????????????????000000000000000000000000000000000000000000000400????????????????????????????????0000000000000000000000000000000000000000000000E0????????????????????????????????????????????????000000000000000000000000000000E0000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1181_Private_exe_Protector {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "2.5x - 2.7x"
		pattern = "0000000000000000????????????????????????00100000????????00040000000000000000000000000000200000E0????????????????????????????????000000000000000000000000000000000000000000000400????????????????????????????????0000000000000000000000000000000000000000000000E0????????????????????????????????????????????????000000000000000000000000000000E0????????????????????????????????????????????????000000000000000000000000400000C000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 ?? ?? ?? ?? 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1182_Private_Personal_Packer__PPP {
	meta:
		tool = "P"
		name = "Private Personal Packer"
		version = "1.0.2"
		pattern = "E817000000E868000000FF352C370010E8ED0100006A00E82E040000E841040000A3743700106A64E85F040000E830040000A3783700106A64E84E040000E81F040000A37C370010A1743700108B1D783700102BD88B0D7C3700102BC883FB64730F81F9C800000073076A00E8D9030000C36A0A6A076A00"
	strings:
		$1 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1183_Private_Personal_Packer__PPP {
	meta:
		tool = "P"
		name = "Private Personal Packer"
		version = "1.0.3"
		pattern = "E8190000009090E868000000FF352C370010E8ED0100006A00E82E040000E841040000A3743700106A64E85F040000E830040000A3783700106A64E84E040000E81F040000A37C370010A1743700108B1D783700102BD88B0D7C3700102BC883FB64730F81F9C800000073076A00E8D9030000C36A0A6A076A00E8D3030000A320370010506A00E8DE030000A324370010FF35203700106A00E8EA030000A330370010FF3524370010E8C2030000A3283700108B0D303700108B3D28370010EB0949C0043955803439240BC9"
	strings:
		$1 = { E8 19 00 00 00 90 90 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1184_PrivateEXE {
	meta:
		tool = "P"
		name = "PrivateEXE"
		version = "2.0a"
		pattern = "0660C8??????0E68????9A????????3D????0F??????50500E68????9A????????0E"
	strings:
		$1 = { 06 60 C8 ?? ?? ?? 0E 68 ?? ?? 9A ?? ?? ?? ?? 3D ?? ?? 0F ?? ?? ?? 50 50 0E 68 ?? ?? 9A ?? ?? ?? ?? 0E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1185_PrivateEXE {
	meta:
		tool = "P"
		name = "PrivateEXE"
		version = "2.0a"
		pattern = "53E8????????5B8BC32D"
	strings:
		$1 = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1186_PRO_PACK {
	meta:
		tool = "P"
		name = "PRO-PACK"
		version = "2.08"
		pattern = "8CD38EC38CCA8EDA8B0E????8BF183????8BFED1??FDF3A553"
	strings:
		$1 = { 8C D3 8E C3 8C CA 8E DA 8B 0E ?? ?? 8B F1 83 ?? ?? 8B FE D1 ?? FD F3 A5 53 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1187_PRO_PACK {
	meta:
		tool = "P"
		name = "PRO-PACK"
		version = "2.08"
		extra = "emphasis on packed size, locked"
		pattern = "83EC??8BECBE????FCE8????05????8BC8E8????8B"
	strings:
		$1 = { 83 EC ?? 8B EC BE ?? ?? FC E8 ?? ?? 05 ?? ?? 8B C8 E8 ?? ?? 8B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1188_PROACTIVATE {
	meta:
		tool = "P"
		name = "PROACTIVATE"
		pattern = "558BECB90E0000006A006A004975F951535657B8??????00909090909033C05568????????64FF30648920A1????????83C005A3????????C705????????0D000000E885E2FFFF813D????????217E7E"
	strings:
		$1 = { 55 8B EC B9 0E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? ?? ?? 00 90 90 90 90 90 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 A1 ?? ?? ?? ?? 83 C0 05 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0D 00 00 00 E8 85 E2 FF FF 81 3D ?? ?? ?? ?? 21 7E 7E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1189_Program_Protector_XP {
	meta:
		tool = "P"
		name = "Program Protector XP"
		version = "1.0"
		pattern = "E8????????5883D80589C381C3????????8B436450"
	strings:
		$1 = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
