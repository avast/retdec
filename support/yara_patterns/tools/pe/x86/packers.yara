/*
 * YARA rules for x86 PE packer detection.
 * Copyright (c) 2017 Avast Software, licensed under the MIT license
 */

import "pe"

rule ep_exepack_10 {
	meta:
		tool = "P"
		name = "!EP"
		version = "1.0"
		extra = "ExePack"
		pattern = "6068????????B8????????FF1068????????50B8????????FF1068????????6A40FFD08905????????89C7BE????????60FCB28031DBA4B302E86D00000073F631C9E864000000731C31C0E85B0000007323B30241B010E84F00000010C073F7753FAAEBD4E84D00000029D97510E842000000EB28ACD1E8744D11C9EB1C9148C1E008ACE82C0000003D007D0000730A80FC05730683F87F770241419589E8B3015689FE29C6F3A45EEB8E00D275058A164610D2C3"
	strings:
		$1 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 }
	condition:
		$1 at pe.entry_point
}

rule ep_exepack_14lb2 {
	meta:
		tool = "P"
		name = "!EP"
		version = "1.4 lite b2"
		extra = "ExePack"
		pattern = "0000000000000000????????????????????????0000000000000000????????????????0000000000000000000000000000000000000000????????00000000????????????????????????000000004B45524E454C33322E444C4C005553455233322E444C4C00000047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C696272617279410000004D657373616765426F78410000000000EB4C476C6F62616C416C6C6F6300476C6F62616C46726565000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 55 53 45 52 33 32 2E 44 4C 4C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 00 00 00 00 EB 4C 47 6C 6F 62 61 6C 41 6C 6C 6F 63 00 47 6C 6F 62 61 6C 46 72 65 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule ep_exepack_14lf_01 {
	meta:
		tool = "P"
		name = "!EP"
		version = "1.4 lite final"
		extra = "ExePack"
		pattern = "33C08BC068????????68????????E8"
	strings:
		$1 = { 33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule ep_exepack_14lf_02 {
	meta:
		tool = "P"
		name = "!EP"
		version = "1.4 lite final"
		extra = "ExePack"
		pattern = "9090909061B8????????FFE0558BEC60558B75088B7D0CE802000000EB048B1C24C381C30002000053578B07890383C70483C3044E75F35F5EFCB2808A064688074702D275058A164612D273EF02D275058A164612D2734A33C002D275058A164612D20F83D600000002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C07406572BF88A075F880747EBA0B80100000002D275058A164612D213C002D275058A164612D272EA83E8027528B90100000002D275058A164612D213C902D275058A164612D272EA568BF72BF5F3A45EE958FFFFFF48C1E0088A06468BE8B90100000002D275058A164612D213C902D275058A164612D272EA3D007D0000731A3D00050000720E41568BF72BF0F3A45EE918FFFFFF83F87F770383C102568BF72BF0F3A45EE903FFFFFF8A064633C9C0E801741283D1028BE8568BF72BF0F3A45EE9E7FEFFFF5D2B7D0C897DFC615DC3"
	strings:
		$1 = { 90 90 90 90 61 B8 ?? ?? ?? ?? FF E0 55 8B EC 60 55 8B 75 08 8B 7D 0C E8 02 00 00 00 EB 04 8B 1C 24 C3 81 C3 00 02 00 00 53 57 8B 07 89 03 83 C7 04 83 C3 04 4E 75 F3 5F 5E FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 46 12 D2 73 EF 02 D2 75 05 8A 16 46 12 D2 73 4A 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 D6 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 74 06 57 2B F8 8A 07 5F 88 07 47 EB A0 B8 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 72 EA 83 E8 02 75 28 B9 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C9 02 D2 75 05 8A 16 46 12 D2 72 EA 56 8B F7 2B F5 F3 A4 5E E9 58 FF FF FF 48 C1 E0 08 8A 06 46 8B E8 B9 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C9 02 D2 75 05 8A 16 46 12 D2 72 EA 3D 00 7D 00 00 73 1A 3D 00 05 00 00 72 0E 41 56 8B F7 2B F0 F3 A4 5E E9 18 FF FF FF 83 F8 7F 77 03 83 C1 02 56 8B F7 2B F0 F3 A4 5E E9 03 FF FF FF 8A 06 46 33 C9 C0 E8 01 74 12 83 D1 02 8B E8 56 8B F7 2B F0 F3 A4 5E E9 E7 FE FF FF 5D 2B 7D 0C 89 7D FC 61 5D C3 }
	condition:
		$1 at pe.entry_point
}

rule ep_exepack_360_406 {
	meta:
		tool = "P"
		name = "!EP"
		version = "3.60 - 4.06"
		extra = "ExePack"
		pattern = "8CC005????0E1FA3????03??????8EC08B??????8B??4F8BF7FDF3A4"
	strings:
		$1 = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 ?? ?? ?? 8E C0 8B ?? ?? ?? 8B ?? 4F 8B F7 FD F3 A4 }
	condition:
		$1 at pe.entry_point
}

rule spirit_15_01 {
	meta:
		tool = "P"
		name = "$pirit"
		version = "1.5"
		pattern = "??????5B24555044FB322E315D"
	strings:
		$1 = { ?? ?? ?? 5B 24 55 50 44 FB 32 2E 31 5D }
	condition:
		$1 at pe.entry_point
}

rule spirit_15_02 {
	meta:
		tool = "P"
		name = "$pirit"
		version = "1.5"
		pattern = "B44DCD21E8????FDE8????B451CD21"
	strings:
		$1 = { B4 4D CD 21 E8 ?? ?? FD E8 ?? ?? B4 51 CD 21 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01 {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1"
		pattern = "9090909068????????6764FF360000676489260000F190909090"
	strings:
		$1 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_32lite {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [32Lite 0.03]"
		pattern = "6006FC1E07BE909090906A04689010909068"
	strings:
		$1 = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_armadillo {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [Armadillo 3.00]"
		pattern = "60E82A0000005D5051EB0FB9EB0FB8EB07B9EB0F90EB08FDEB0BF2EBF5EBF6F2EB08FDEBE9F3EBE4FCE959585051EB85"
	strings:
		$1 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_cdcops {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [CD-Cops II]"
		pattern = "5360BD909090908D45908D5D90E8000000008D01"
	strings:
		$1 = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_codesafe {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [CodeSafe 2.0]"
		pattern = "90909090909090909090909090909090909090909090EB0B83EC10535657E8C4010085"
	strings:
		$1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_crunch {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [Crunch/PE Heuristic]"
		pattern = "55E80E0000005D83ED068BC5556089AD????????2B8500000000"
	strings:
		$1 = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_dxpack {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [DxPack 1.0]"
		pattern = "60E8000000005D8BFD81ED909090902BB90000000081EF9090909083BD90909090900F8400000000"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_fsg {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [FSG 1.31]"
		pattern = "BE90909000BF90909000BB9090900053BB90909000B280"
	strings:
		$1 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_gleam {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [Gleam 1.00]"
		pattern = "90909090909090909090909090909090909090909090EB0B83EC0C535657E8240200FF"
	strings:
		$1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_jdpack_jdprotect {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [JDPack 1.x / JDProtect 0.9]"
		pattern = "60E8220000005D8BD581ED909090902B959090909081EA0690909089959090909083BD4500010001"
	strings:
		$1 = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_lcc {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [LCC Win32 1.x]"
		pattern = "64A1010000005589E56AFF68????????689A10409050"
	strings:
		$1 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_lockless_intro_pack {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [Lockless Intro Pack]"
		pattern = "2CE8EB1A90905D8BC581EDF67390902B859090909083E8068985FF01ECAD"
	strings:
		$1 = { 2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_mew {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [MEW 11 SE 1.0]"
		pattern = "E909000000000000020000000C90"
	strings:
		$1 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_msvc {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [MSVC 7.0 DLL]"
		pattern = "558D6C010081EC000000008B459083F801560F840000000085C00F84"
	strings:
		$1 = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_mingw {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [MinGW GCC 2.x]"
		pattern = "5589E5E802000000C9C39090455845"
	strings:
		$1 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_pe_pack {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [PE Pack 0.99]"
		pattern = "60E8110000005D83ED0680BDE0049090010F84F2FFCC0A"
	strings:
		$1 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_peprotect {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [PE-Protect 0.9]"
		pattern = "525155576467A1300085C0780DE8070000005883C007C690C3"
	strings:
		$1 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_peshield {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [PE-SHiELD 0.25]"
		pattern = "60E82B0000009090909090909090909090909090909090909090909090909090909090909090909090909090909090CCCC"
	strings:
		$1 = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_realbasic {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [REALBasic]"
		pattern = "5589E5909090909090909090905090909090900001"
	strings:
		$1 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_vbox_stealthpe {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [VBOX 4.3 MTE / Ste@lth PE 1.01]"
		pattern = "0BC00BC00BC00BC00BC00BC00BC00BC0"
	strings:
		$1 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_vob_protectcd {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [VOB ProtectCD 5]"
		pattern = "363E268AC060E800000000"
	strings:
		$1 = { 36 3E 26 8A C0 60 E8 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_asprotect {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [ASProtect]"
		pattern = "609090909090905D909090909090909090909003DD"
	strings:
		$1 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_upx {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [UPX 0.6]"
		pattern = "60E8000000005883E83D508DB8000000FF578DB0E8000000"
	strings:
		$1 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_watcom {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [WATCOM C/C++]"
		pattern = "E900000000909090905741"
	strings:
		$1 = { E9 00 00 00 00 90 90 90 90 57 41 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_02_xcr {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [XCR 0.11]"
		pattern = "608BF033DB83C30183C001E9"
	strings:
		$1 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_acprotect {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [ACProtect 1.09]"
		pattern = "6090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090EB02000090909004909090909090909090909090909090909090909090"
	strings:
		$1 = { 60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_borland_delphi_30 {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Borland Delphi 3.0]"
		pattern = "558BEC83C49090909068????????9090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090"
	strings:
		$1 = { 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_borland_delphi_50 {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Borland Delphi 5.0 KOL/MCK]"
		pattern = "558BEC9090909068????????9090909090909090909090909090909090909090909090909090909000FF90909090909090900001909090909090909090EB0400000001909090909090900001909090909090909090"
	strings:
		$1 = { 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_def {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [DEF 1.0]"
		pattern = "BE000140006A0559807E070074118B46909090909090909090909090909090909083C101E9"
	strings:
		$1 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_exesmasher {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [ExeSmasher]"
		pattern = "9CFE039060BE909041908DBE9010FFFF5783CDFFEB1090909090909090909090909090909090FE0BE9"
	strings:
		$1 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_lcc {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [LCC Win32 DLL]"
		pattern = "5589E5535657837D0C017505E817909090FF7510FF750CFF7508A1????????E9"
	strings:
		$1 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_ltc {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [LTC 1.3]"
		pattern = "54E8000000005D8BC581EDF67340002B858775400083E806E9"
	strings:
		$1 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_msvb {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Microsoft Visual Basic 5.0 - 6.0]"
		pattern = "68????????E80A00000000000000000030000000E9"
	strings:
		$1 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_msvc_50 {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [MSVC 5.0+ (MFC)]"
		pattern = "558BEC6AFF68????????68????????64A10000000050E9"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_msvc_60_debug {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [MSVC 6.0 (Debug)]"
		pattern = "558BEC5190909001019090909068????????90909090909090909090909000019090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909000019090909090"
	strings:
		$1 = { 55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_morphine {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Morphine 1.2]"
		pattern = "90909090909090909090909090909090EB06009090909090909090EB08E890000000669090909090909090909090909090909090909090909090909090909090516690909059909090909090909090909090909090"
	strings:
		$1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_neolite {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Neolite 2.0]"
		pattern = "E9A60000009090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090"
	strings:
		$1 = { E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_pe_shrinker {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [NorthStar PE Shrinker 1.3]"
		pattern = "9C60E8000000005DB8B38540002DAC8540002BE88DB500000000E9"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_pack_master {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Pack Master 1.0 (PeX Clone)]"
		pattern = "60E801010000E883C404E801909090E95D81EDD3224090E804029090E8EB08EB02CD20FF24249A66BE4746909090909090909090909090909090909090909090909090909090909090909090909090909090909090"
	strings:
		$1 = { 60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_pe_intro {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [PE Intro 1.0]"
		pattern = "8B04249C60E8140000005D81ED0A45409080BD67444090900F8548FFED0AE9"
	strings:
		$1 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_pe_ninja {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [PE Ninja 1.31]"
		pattern = "909090909090909090909090909090909090909090909090909090909090909090909090E9"
	strings:
		$1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_penightmare {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [PENightMare 2 Beta]"
		pattern = "60E910000000EF4003A7078F071C375D43A704B92C3AE9"
	strings:
		$1 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_pex {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [PEX 0.99]"
		pattern = "60E8010000005583C404E801000000905D81FFFFFF0001E9"
	strings:
		$1 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_video_lan_client {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Video-Lan-Client]"
		pattern = "5589E583EC08909090909090909090909090909001FFFF0101010001909090909090909090909090909000010001000190900001E9"
	strings:
		$1 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_01_yodas_protector {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [yoda's Protector 1.02]"
		pattern = "E803000000EB019090E9"
	strings:
		$1 = { E8 03 00 00 00 EB 01 90 90 E9 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_bfjnt_11b {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [.BJFNT 1.1b]"
		pattern = "EB01EA9CEB01EA53EB01EA51EB01EA52EB01EA5690"
	strings:
		$1 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_bfjnt_12 {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [.BJFNT 1.2]"
		pattern = "EB0269B183EC04EB03CD20EBEB01EB9CEB01EBEB00"
	strings:
		$1 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00 }
	condition:
		$1 at pe.entry_point
}
rule pseudosigner_02_borlandcpp {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Borland C++]"
		pattern = "EB1066623A432B2B484F4F4B90E990909090"
	strings:
		$1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_borland_delphi {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Borland Delphi]"
		pattern = "558BEC83C4B4B890909090E800000000E8000000008D4000"
	strings:
		$1 = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_borland_delphi_sm {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Borland Delphi Setup Module]"
		pattern = "558BEC83C49053565733C08945F08945D48945D0E800000000"
	strings:
		$1 = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_codelock {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Code-Lock]"
		pattern = "434F44452D4C4F434B2E4F435800012801504B47054C3FB4044D4C474B"
	strings:
		$1 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_def {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [DEF 1.0]"
		pattern = "BE000140006A0559807E070074118B46909090909090909090909090909090909083C101"
	strings:
		$1 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_exesmasher {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [ExeSmasher]"
		pattern = "9CFE039060BE909041908DBE9010FFFF5783CDFFEB1090909090909090909090909090909090FE0B"
	strings:
		$1 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_lcc {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [LCC Win32 DLL]"
		pattern = "5589E5535657837D0C017505E817909090FF7510FF750CFF7508A1"
	strings:
		$1 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_msvb {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Microsoft Visual Basic 5.0 - 6.0]"
		pattern = "68????????E80A00000000000000000030000000"
	strings:
		$1 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_peshrinker {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [NorthStar PE Shrinker 1.3]"
		pattern = "9C60E8000000005DB8B38540002DAC8540002BE88DB500000000"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_pe_intro {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [PE Intro 1.0]"
		pattern = "8B04249C60E8140000005D81ED0A45409080BD67444090900F8548FFED0A"
	strings:
		$1 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_penightmare {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [PENightMare 2 Beta]"
		pattern = "60E910000000EF4003A7078F071C375D43A704B92C3A"
	strings:
		$1 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_pex {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [PEX 0.99]"
		pattern = "60E8010000005583C404E801000000905D81FFFFFF0001"
	strings:
		$1 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_video_lan_client {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Video-Lan-Client]"
		pattern = "5589E583EC08909090909090909090909090909001FFFF0101010001909090909090909090909090909000010001000190900001"
	strings:
		$1 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_watcom {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Watcom C/C++]"
		pattern = "535657558B7424148B7C24188B6C241C83FF030F8701000000F1"
	strings:
		$1 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_yodas_protector {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [yoda's Protector 1.02]"
		pattern = "E803000000EB019090"
	strings:
		$1 = { E8 03 00 00 00 EB 01 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_zcode {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [ZCode 1.01]"
		pattern = "E912000000000000000000000000000000E9FBFFFFFFC3680000000064FF3500000000"
	strings:
		$1 = { E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pseudosigner_02_ddem_pe_engine {
	meta:
		tool = "P"
		name = "*** Protector"
		version = "1.1.11 (DDeM->PE Engine v0.9, DDeM->CI v0.9.2)"
		pattern = "535156E8000000005B81EB081000008DB334100000B9F3030000BA63172AEE311683C604"
	strings:
		$1 = { 53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04 }
	condition:
		$1 at pe.entry_point
}

rule bfjnt_11b {
	meta:
		tool = "P"
		name = ".BJFnt"
		version = "1.1b"
		pattern = "EB01EA9CEB01EA53EB01EA51EB01EA52EB01EA56"
	strings:
		$1 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 }
	condition:
		$1 at pe.entry_point
}

rule bfjnt_12rc {
	meta:
		tool = "P"
		name = ".BJFnt"
		version = "1.2rc"
		pattern = "EB0269B183EC04EB03CD20EBEB01EB9CEB01EBEB"
	strings:
		$1 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB }
	condition:
		$1 at pe.entry_point
}

rule bfjnt_13 {
	meta:
		tool = "P"
		name = ".BJFnt"
		version = "1.3"
		pattern = "EB??3A????1EEB??CD209CEB??CD20EB??CD2060EB"
	strings:
		$1 = { EB ?? 3A ?? ?? 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB }
	condition:
		$1 at pe.entry_point
}

rule lite32_003a {
	meta:
		tool = "P"
		name = "32Lite"
		version = "0.03a"
		pattern = "6006FC1E07BE????????6A0468??10????68"
	strings:
		$1 = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68 }
	condition:
		$1 at pe.entry_point
}

rule anticrack_software_protector_109_01 {
	meta:
		tool = "P"
		name = "Anticrack Software Protector"
		version = "1.09"
		pattern = "60??????????????????E801000000????????????????????????????????????????????0000??????04"
	strings:
		$1 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 04 }
	condition:
		$1 at pe.entry_point
}

rule anticrack_software_protector_109_02 {
	meta:
		tool = "P"
		name = "Anticrack Software Protector"
		version = "1.09"
		pattern = "60????????????????0000????????????????????????E801000000??83042406C3??????????00"
	strings:
		$1 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 83 04 24 06 C3 ?? ?? ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule mslrh_01 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.1"
		pattern = "60EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB0181E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB0181E80A000000E8EB0C0000E8"
	strings:
		$1 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 }
	condition:
		$1 at pe.entry_point
}

rule mslrh_031a {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.31a"
		pattern = "60D1CB0FCAC1CAE0D1CA0FC8EB01F10FC0C9D2D10FC1C0D3DAC0D6A8EB01DED0EC0FC1CBD0CF0FC1D1D2DB0FC8EB01BCC0E9C6C1D0910FCBEB01730FCA87D987D2D0CF87D90FC8EB01C1EB01A286CAD0E10FC0CB0F"
	strings:
		$1 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F }
	condition:
		$1 at pe.entry_point
}

rule mslrh_031 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.31"
		pattern = "60D1CB0FCAC1CAE0D1CA0FC8EB01F1"
	strings:
		$1 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_01 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a"
		pattern = "E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018174047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C4082B042474047502EB02EB018183C404E80A000000E8"
	strings:
		$1 = { E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_02 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a"
		pattern = "EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB0181E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003"
	strings:
		$1 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [.BJFNT 1.3]"
		pattern = "EB033A4D3A1EEB02CD209CEB02CD20EB02CD2060EB02C705EB02CD20E803000000E9EB04584050C3619D1FEB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C4082B042474047502EB02EB01"
	strings:
		$1 = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 EB 02 C7 05 EB 02 CD 20 E8 03 00 00 00 E9 EB 04 58 40 50 C3 61 9D 1F EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_aspack_211d {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [ASPack 2.11d]"
		pattern = "60E802000000EB095D5581ED39394400C361EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_asppack_212 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [ASPack 2.12]"
		pattern = "60E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00A002EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 A0 02 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_exe32pack {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [EXE32Pack 1.3x]"
		pattern = "3BC074028183553BC074028183533BC97401BC563BD27402818557E8000000003BDB74019083C414EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 56 3B D2 74 02 81 85 57 E8 00 00 00 00 3B DB 74 01 90 83 C4 14 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_msvc_01 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [MSVC]"
		pattern = "558BEC6AFF68CA374100680638410064A1000000005064892500000000648F050000000083C40C5DEB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C4082B042474047502EB02EB01"
	strings:
		$1 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 83 C4 0C 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_msvc_02 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [MSVC]"
		pattern = "558BEC5657BF010000008B750C85F65F5E5DEB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_msvc_60 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [MSVC 6.0]"
		pattern = "558BEC538B5D08568B750C578B7D1085F65F5E5B5DEB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_msvc_70 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [MSVC 7.0]"
		pattern = "558BEC538B5D08568B750C5E5B5DEB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_neolite {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [Neolite 2.0]"
		pattern = "E9A6000000B07B4000786040007C60400000000000B03F0000126240004E656F4C6974652045786563757461626C652046696C6520436F6D70726573736F720D0A436F707972696768742028632920313939382C31393939204E656F576F727820496E630D0A506F7274696F6E7320436F707972696768742028632920313939372D31393939204C65652048617369756B0D0A416C6C205269676874732052657365727665642E00000000EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C4082B042474047502EB02EB01"
	strings:
		$1 = { E9 A6 00 00 00 B0 7B 40 00 78 60 40 00 7C 60 40 00 00 00 00 00 B0 3F 00 00 12 62 40 00 4E 65 6F 4C 69 74 65 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 43 6F 6D 70 72 65 73 73 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 38 2C 31 39 39 39 20 4E 65 6F 57 6F 72 78 20 49 6E 63 0D 0A 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 37 2D 31 39 39 39 20 4C 65 65 20 48 61 73 69 75 6B 0D 0A 41 6C 6C 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2E 00 00 00 00 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_nspack {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [NsPacK 1.3]"
		pattern = "9C60E8000000005DB8B38540002DAC8540002BE88DB5D3FEFFFF8B0683F80074118DB5DFFEFFFF8B0683F8010F84F1010000619DEB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C4082B042474047502EB02EB01"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D3 FE FF FF 8B 06 83 F8 00 74 11 8D B5 DF FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_pc_guard {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [PC Guard 4.xx]"
		pattern = "FC5550E8000000005DEB01E360E803000000D2EB0B58EB014840EB0135FFE0E761585DEB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 58 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_pecrypt {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [PE Crypt 1.02]"
		pattern = "E8000000005B83EB05EB04524E442185C07302F70550E808000000EAFF58EB18EB010FEB02CD20EB03EACD205858EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 05 50 E8 08 00 00 00 EA FF 58 EB 18 EB 01 0F EB 02 CD 20 EB 03 EA CD 20 58 58 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_peshield {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [PE-SHiELD 0.25]"
		pattern = "60E82B0000000D0A0D0A0D0A5265676973744172656420746F3A204E4F4E2D434F4D4D45524349414C21210D0A0D0A0D005861EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 60 E8 2B 00 00 00 0D 0A 0D 0A 0D 0A 52 65 67 69 73 74 41 72 65 64 20 74 6F 3A 20 4E 4F 4E 2D 43 4F 4D 4D 45 52 43 49 41 4C 21 21 0D 0A 0D 0A 0D 00 58 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_pebundle_03_3x {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [PEBundle 0.2 - 3.x]"
		pattern = "9C60E80200000033C08BC483C004938BE38B5BFC81EB0730400087DD619DEB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_pebundle_20_24 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [PEBundle 2.0x - 2.4x]"
		pattern = "9C60E80200000033C08BC483C004938BE38B5BFC81EB0730400087DD83BD9C38400001619DEB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 83 BD 9C 38 40 00 01 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_pecompact {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [PECompact 1.4x]"
		pattern = "EB06682EA80000C39C60E80200000033C08BC483C004938BE38B5BFC81EB3F904000619DEB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { EB 06 68 2E A8 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_pelock {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [PELock NT 2.04]"
		pattern = "EB03CD20C71EEB03CD20EA9CEB02EB01EB01EB60EB03CD20EBEB01EBE803000000E9EB04584050C3EB03CD20EBEB03CD2003619D83C404EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 03 CD 20 EB EB 03 CD 20 03 61 9D 83 C4 04 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_petite {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [Petite 2.1]"
		pattern = "B8005040006A0068BB21400064FF350000000064892500000000669C605083C40461669D648F050000000083C408EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { B8 00 50 40 00 6A 00 68 BB 21 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 83 C4 04 61 66 9D 64 8F 05 00 00 00 00 83 C4 08 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_pex {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [PeX 0.99]"
		pattern = "60E801000000E883C404E801000000E95D81EDFF22400061EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C4082B042474047502EB02EB01"
	strings:
		$1 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED FF 22 40 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_svkp {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [SVKP 1.11]"
		pattern = "60E8000000005D81ED0600000064A02300000083C50661EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C4082B042474047502EB02EB01"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 64 A0 23 00 00 00 83 C5 06 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_upx {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [UPX 0.89.6 - 1.02 / 1.05 - 1.24]"
		pattern = "60BE00908B008DBE0080B4FF5783CDFFEB3A9090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB730B75198B1E83EEFC11DB7210586190EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_wwpack32 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [WWPack32 1.x]"
		pattern = "53558BE833DBEB600D0A0D0A57575061636B3332206465636F6D7072657373696F6E20726F7574696E652076657273696F6E20312E31320D0A28632920313939382050696F747220576172657A616B20616E6420526166616C20576965727A6269636B690D0A0D0A5D5B90EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 20 64 65 63 6F 6D 70 72 65 73 73 69 6F 6E 20 72 6F 75 74 69 6E 65 20 76 65 72 73 69 6F 6E 20 31 2E 31 32 0D 0A 28 63 29 20 31 39 39 38 20 50 69 6F 74 72 20 57 61 72 65 7A 61 6B 20 61 6E 64 20 52 61 66 61 6C 20 57 69 65 72 7A 62 69 63 6B 69 0D 0A 0D 0A 5D 5B 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mslrh_032a_yodas_cryptor_12 {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.32a [yoda's cryptor 1.2]"
		pattern = "60E8000000005D81EDF31D4000B97B0900008DBD3B1E40008BF7AC902C8AC0C078900462EB010061EB05E8EB044000EBFAE80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF83C40874047502EB02EB018150E802000000295A586BC003E802000000295A83C4045874047502EB02EB01810F31500F31E80A000000E8EB0C0000E8F6FFFFFFE8F2FFFFFF"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC 90 2C 8A C0 C0 78 90 04 62 EB 01 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule box {
	meta:
		tool = "P"
		name = "_BOX_"
		pattern = "5868????????68????????68????00005068??????00C3909090909090909090"
	strings:
		$1 = { 58 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? 00 00 50 68 ?? ?? ?? 00 C3 90 90 90 90 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule aase_crypter {
	meta:
		tool = "P"
		name = "Aase Crypter"
		pattern = "558BEC83C4F053B8A03E0010E893DEFFFF68F8420010E879DFFFFF6800430010680C430010E842DFFFFF50E844DFFFFFA398660010833D986600100075136A006818430010681C4300106A00E84BDFFFFF682C430010680C43????????DFFFFF50E80EDFFFFFA394660010833D946600100075136A00681843001068384300106A00E815DFFFFF6848430010680C430010E8D6DEFFFF50E8D8DEFFFFA3A0660010833DA06600100075136A00681843001068584300106A00E8DFDEFFFF686C430010680C430010E8A0DEFFFF50E8A2DEFFFF"
	strings:
		$1 = { 55 8B EC 83 C4 F0 53 B8 A0 3E 00 10 E8 93 DE FF FF 68 F8 42 00 10 E8 79 DF FF FF 68 00 43 00 10 68 0C 43 00 10 E8 42 DF FF FF 50 E8 44 DF FF FF A3 98 66 00 10 83 3D 98 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 1C 43 00 10 6A 00 E8 4B DF FF FF 68 2C 43 00 10 68 0C 43 ?? ?? ?? ?? DF FF FF 50 E8 0E DF FF FF A3 94 66 00 10 83 3D 94 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 38 43 00 10 6A 00 E8 15 DF FF FF 68 48 43 00 10 68 0C 43 00 10 E8 D6 DE FF FF 50 E8 D8 DE FF FF A3 A0 66 00 10 83 3D A0 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 58 43 00 10 6A 00 E8 DF DE FF FF 68 6C 43 00 10 68 0C 43 00 10 E8 A0 DE FF FF 50 E8 A2 DE FF FF }
	condition:
		$1 at pe.entry_point
}

rule abc_cryptor_10 {
	meta:
		tool = "P"
		name = "ABC Cryptor"
		version = "1.0"
		pattern = "68FF6424F0685858585890FFD4508B40F205B095F6950F850181BBFF68????????BF00??????B900??????8037??4739CF75F8????????????????????????????????????????????????????????????????????????????????????????????????????????????BF00??????B900??????8037??4739CF75F8"
	strings:
		$1 = { 68 FF 64 24 F0 68 58 58 58 58 90 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 ?? ?? ?? ?? BF 00 ?? ?? ?? B9 00 ?? ?? ?? 80 37 ?? 47 39 CF 75 F8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BF 00 ?? ?? ?? B9 00 ?? ?? ?? 80 37 ?? 47 39 CF 75 F8 }
	condition:
		$1 at pe.entry_point
}

rule ace_compression_uv_01 {
	meta:
		tool = "P"
		name = "ACE COMPRESSION"
		pattern = "3?3?268AC060E8??000000????48FA????????6A773839336A7339326A6139736A733933615F3B28254C492C3A00EFBEADDE??????78??000000"
	strings:
		$1 = { 3? 3? 26 8A C0 60 E8 ?? 00 00 00 ?? ?? 48 FA ?? ?? ?? ?? 6A 77 38 39 33 6A 73 39 32 6A 61 39 73 6A 73 39 33 61 5F 3B 28 25 4C 49 2C 3A 00 EF BE AD DE ?? ?? ?? 78 ?? 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule ace_compression_uv_02 {
	meta:
		tool = "P"
		name = "ACE COMPRESSION"
		pattern = "3?3?268AC060E8??000000????48FA4D4554494E46????0000000000000000000000000000000000000000000000EFBEADDE??????78??000000"
	strings:
		$1 = { 3? 3? 26 8A C0 60 E8 ?? 00 00 00 ?? ?? 48 FA 4D 45 54 49 4E 46 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 EF BE AD DE ?? ?? ?? 78 ?? 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule ace_compression_uv_03 {
	meta:
		tool = "P"
		name = "ACE COMPRESSION"
		pattern = "E9????????436F707972696768742062792041434520436F6D7072657373696F6E20536F6674776172652028313939382D3230303029"
	strings:
		$1 = { E9 ?? ?? ?? ?? 43 6F 70 79 72 69 67 68 74 20 62 79 20 41 43 45 20 43 6F 6D 70 72 65 73 73 69 6F 6E 20 53 6F 66 74 77 61 72 65 20 28 31 39 39 38 2D 32 30 30 30 29 }
	condition:
		$1 at pe.entry_point
}

rule acidcrypt_uv_01 {
	meta:
		tool = "P"
		name = "AcidCrypt"
		pattern = "60B9??????00BA??????00BE??????000238404E75FA8BC28A1832DFC0CB"
	strings:
		$1 = { 60 B9 ?? ?? ?? 00 BA ?? ?? ?? 00 BE ?? ?? ?? 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
	condition:
		$1 at pe.entry_point
}

rule acidcrypt_uv_02 {
	meta:
		tool = "P"
		name = "AcidCrypt"
		pattern = "BE????????0238404E75FA8BC28A1832DFC0CB"
	strings:
		$1 = { BE ?? ?? ?? ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
	condition:
		$1 at pe.entry_point
}

rule acprotect_109 {
	meta:
		tool = "P"
		name = "ACProtect"
		version = "1.09"
		pattern = "60F950E8010000007C58584950E8010000007E5858790466B9B872E8010000007A83C40485C8EB01EBC1F8BE72037301740F8101000000F9EB0175F9E8010000"
	strings:
		$1 = { 60 F9 50 E8 01 00 00 00 7C 58 58 49 50 E8 01 00 00 00 7E 58 58 79 04 66 B9 B8 72 E8 01 00 00 00 7A 83 C4 04 85 C8 EB 01 EB C1 F8 BE 72 03 73 01 74 0F 81 01 00 00 00 F9 EB 01 75 F9 E8 01 00 00 }
	condition:
		$1 at pe.entry_point
}

rule acprotect_135_01 {
	meta:
		tool = "P"
		name = "ACProtect"
		version = "1.35"
		pattern = "4B45524E454C33322E444C4C00????????????????????????????????????????5553455233322E444C4C00??????????????????????????????????????????????????????????????????0047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C696272617279410000004578697450726F636573730000004D657373616765426F784100904D696E65496D706F72745F"
	strings:
		$1 = { 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 53 45 52 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 6F 72 74 5F }
	condition:
		$1 at pe.entry_point
}

rule acprotect_135_02 {
	meta:
		tool = "P"
		name = "ACProtect"
		version = "1.35"
		pattern = "4B45524E454C33322E444C4C00????????????????????????????????????????5553455233322E444C4C00??????????????????????????????????????????????????????????????????0047657450726F63"
	strings:
		$1 = { 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 53 45 52 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 47 65 74 50 72 6F 63 }
	condition:
		$1 at pe.entry_point
}

rule acprotect_13x {
	meta:
		tool = "P"
		name = "ACProtect"
		version = "1.3x"
		pattern = "6050E8010000007583"
	strings:
		$1 = { 60 50 E8 01 00 00 00 75 83 }
	condition:
		$1 at pe.entry_point
}

rule acprotect_141_01 {
	meta:
		tool = "P"
		name = "ACProtect"
		version = "1.41"
		pattern = "60760377017B74037501784787EEE8010000007683C40485EEEB017F85F2EB01790F8601000000FCEB0178790287F261518F051938010160EB01E9E901000000"
	strings:
		$1 = { 60 76 03 77 01 7B 74 03 75 01 78 47 87 EE E8 01 00 00 00 76 83 C4 04 85 EE EB 01 7F 85 F2 EB 01 79 0F 86 01 00 00 00 FC EB 01 78 79 02 87 F2 61 51 8F 05 19 38 01 01 60 EB 01 E9 E9 01 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule acprotect_141_02 {
	meta:
		tool = "P"
		name = "ACProtect"
		version = "1.41"
		pattern = "E801000000??83"
	strings:
		$1 = { E8 01 00 00 00 ?? 83 }
	condition:
		$1 at pe.entry_point
}

rule acprotect_14x_01 {
	meta:
		tool = "P"
		name = "ACProtect"
		version = "1.4x"
		pattern = "47657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C696272617279410000004578697450726F636573730000004D657373616765426F784100904D696E65496D706F72745F456E64737300"
	strings:
		$1 = { 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 6F 72 74 5F 45 6E 64 73 73 00 }
	condition:
		$1 at pe.entry_point
}

rule acprotect_14x_02 {
	meta:
		tool = "P"
		name = "ACProtect"
		version = "1.4x"
		pattern = "60E8010000007C83042406C3"
	strings:
		$1 = { 60 E8 01 00 00 00 7C 83 04 24 06 C3 }
	condition:
		$1 at pe.entry_point
}

rule acprotect_190 {
	meta:
		tool = "P"
		name = "ACProtect"
		version = "1.90"
		pattern = "600F87020000001BF8E8010000007383042406C3"
	strings:
		$1 = { 60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3 }
	condition:
		$1 at pe.entry_point
}

rule acprotect_20 {
	meta:
		tool = "P"
		name = "ACProtect"
		version = "2.0"
		pattern = "68????????68????????C3C3"
	strings:
		$1 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C3 C3 }
	condition:
		$1 at pe.entry_point
}

rule activemark_uv_01 {
	meta:
		tool = "P"
		name = "ActiveMark"
		pattern = "00544D53414D564F48A49BFDFF2624E9D7F1D6F0D6AEBEFCD6DFB5C1D01F07CEEFEEDDDE4FF1D1AEBE6B62A09BA49BFDFF2621ECCEF1D6F0D6AEBE01001400"
	strings:
		$1 = { 00 54 4D 53 41 4D 56 4F 48 A4 9B FD FF 26 24 E9 D7 F1 D6 F0 D6 AE BE FC D6 DF B5 C1 D0 1F 07 CE EF EE DD DE 4F F1 D1 AE BE 6B 62 A0 9B A4 9B FD FF 26 21 EC CE F1 D6 F0 D6 AE BE 01 00 14 00 }
	condition:
		$1 at pe.entry_point
}

rule activemark_uv_02 {
	meta:
		tool = "P"
		name = "ActiveMark"
		pattern = "8925????????EB"
	strings:
		$1 = { 89 25 ?? ?? ?? ?? EB }
	condition:
		$1 at pe.entry_point
}

rule activemark_5x{
	meta:
		tool = "P"
		name = "ActiveMark"
		version = "5.x"
		pattern = "202D2D4D50524D4D4756412D2D007573657233322E646C6C004D657373616765426F78410054686973206170706C69636174696F6E2063616E6E6F742072756E207769746820616E2061637469766520646562756767657220696E206D656D6F72792E0D0A506C6561736520756E6C6F61642074686520646562756767657220616E64207265737461727420746865206170706C69636174696F6E2E005761726E696E67"
	strings:
		$1 = { 20 2D 2D 4D 50 52 4D 4D 47 56 41 2D 2D 00 75 73 65 72 33 32 2E 64 6C 6C 00 4D 65 73 73 61 67 65 42 6F 78 41 00 54 68 69 73 20 61 70 70 6C 69 63 61 74 69 6F 6E 20 63 61 6E 6E 6F 74 20 72 75 6E 20 77 69 74 68 20 61 6E 20 61 63 74 69 76 65 20 64 65 62 75 67 67 65 72 20 69 6E 20 6D 65 6D 6F 72 79 2E 0D 0A 50 6C 65 61 73 65 20 75 6E 6C 6F 61 64 20 74 68 65 20 64 65 62 75 67 67 65 72 20 61 6E 64 20 72 65 73 74 61 72 74 20 74 68 65 20 61 70 70 6C 69 63 61 74 69 6F 6E 2E 00 57 61 72 6E 69 6E 67 }
	condition:
		$1 at pe.entry_point
}

rule activemark_531 {
	meta:
		tool = "P"
		name = "ActiveMark"
		version = "5.31"
		pattern = "79117FAB9A4A83B5C96B1A48F927B425"
	strings:
		$1 = { 79 11 7F AB 9A 4A 83 B5 C9 6B 1A 48 F9 27 B4 25 }
	condition:
		$1 at pe.entry_point
}

rule adflt2 {
	meta:
		tool = "P"
		name = "AdFlt2"
		pattern = "6800019C0FA00FA860FD6A000FA1BE????AD"
	strings:
		$1 = { 68 00 01 9C 0F A0 0F A8 60 FD 6A 00 0F A1 BE ?? ?? AD }
	condition:
		$1 at pe.entry_point
}

rule ahpack_01 {
	meta:
		tool = "P"
		name = "AHPack"
		version = "0.1"
		pattern = "606854??????B848??????FF1068B3??????50B844????00FF106800"
	strings:
		$1 = { 60 68 54 ?? ?? ?? B8 48 ?? ?? ?? FF 10 68 B3 ?? ?? ?? 50 B8 44 ?? ?? 00 FF 10 68 00 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_041 {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 - 0.41"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE0"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_aspack {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [ASPack 2.12]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE060E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_asprotect {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [ASProtect 1.0]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE060E801000000905D81ED00000000BB0000000003DD2B9D"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 01 00 00 00 90 5D 81 ED 00 00 00 00 BB 00 00 00 00 03 DD 2B 9D }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_borland_delphi {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [Borland Delphi 6.0 - 7.0]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE0538BD833C0A3000000006A00E8000000FFA300000000A100000000A30000000033C0A30000000033C0A300000000E8"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 53 8B D8 33 C0 A3 00 00 00 00 6A 00 E8 00 00 00 FF A3 00 00 00 00 A1 00 00 00 00 A3 00 00 00 00 33 C0 A3 00 00 00 00 33 C0 A3 00 00 00 00 E8 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_kkryptor {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [k.kryptor 9 / kryptor a]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE060E8????????5EB9000000002BC002040ED3C04979F8418D7E2C3346??66B9"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 ?? ?? ?? ?? 5E B9 00 00 00 00 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_msvc_70 {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [MSVC 7.0]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE06A0068????????E8????????BF????????8BC7E8????????8965008BF4893E56FF15????????8B4E??890D??????008B4600A3"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 00 8B F4 89 3E 56 FF 15 ?? ?? ?? ?? 8B 4E ?? 89 0D ?? ?? ?? 00 8B 46 00 A3 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_pcguard {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [PCGuard 4.03 - 4.15]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE0FC5550E8000000005DEB01E360E803000000D2EB0B58EB014840EB01"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_pecrypt {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [PE-Crypt 1.02]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE0E8000000005B83EB05EB04524E44"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_pelock {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [PELock NT 2.04]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE0EB03CD20C71EEB03CD20EA9CEB02EB01EB01EB60EB03CD20EBEB01EB"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_peshield {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [PE-SHiELD 2.x]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE060E800000000414E414B494E5D83ED06EB02EA04"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_petite {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [Petite 2.2]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE0B800000000680000000064FF350000000064892500000000669C6050"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 B8 00 00 00 00 68 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_spalsher {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [Spalsher 1.x - 3.x]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE09C608B442424E8000000005D81ED0000000050E8ED0200008CC00F84"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 9C 60 8B 44 24 24 E8 00 00 00 00 5D 81 ED 00 00 00 00 50 E8 ED 02 00 00 8C C0 0F 84 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_stones_pe_encryptor {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [Stone's PE Encryptor 2.0]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE0535152565755E8000000005D81ED42304000FF9532354000B83730400003C52B851B34400089852734400083"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 53 51 52 56 57 55 E8 00 00 00 00 5D 81 ED 42 30 40 00 FF 95 32 35 40 00 B8 37 30 40 00 03 C5 2B 85 1B 34 40 00 89 85 27 34 40 00 83 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_svkp {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [SVKP 1.3x]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE060E8000000005D81ED06000000EB05B80000000064A023000000EB03C784E884C0EB03C784E97567B9490000008DB5C50200005680064446E2FA8B8DC10200005E55516A00"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 00 00 00 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_telock {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [tElock 0.61]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE0E90000000060E8000000005883C008F3EBFFE083C02850E8000000005EB3338D460E8D76312818F87300C38BFEB93C02"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 F3 EB FF E0 83 C0 28 50 E8 00 00 00 00 5E B3 33 8D 46 0E 8D 76 31 28 18 F8 73 00 C3 8B FE B9 3C 02 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_virus {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [VIRUS / I-Worm Hybris]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE0EB16A85400004741424C4B43474300000000000052495300FC684C704000FF15"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 EB 16 A8 54 00 00 47 41 42 4C 4B 43 47 43 00 00 00 00 00 00 52 49 53 00 FC 68 4C 70 40 00 FF 15 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_vob_protectcd {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [VOB ProtectCD]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE05F81EF00000000BE000040008B870000000003C657568CA700000000FF108987000000005E5F"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 5F 81 EF 00 00 00 00 BE 00 00 40 00 8B 87 00 00 00 00 03 C6 57 56 8C A7 00 00 00 00 FF 10 89 87 00 00 00 00 5E 5F }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_extreme_protector {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [Xtreme-Protector 1.05]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE0E8000000005D8100000000006A45E8A30000006800000000E8"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E8 00 00 00 00 5D 81 00 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 }
	condition:
		$1 at pe.entry_point
}

rule ahteam_ep_protector_03_zcode {
	meta:
		tool = "P"
		name = "AHTeam EP Protector"
		version = "0.3 [ZCode 1.01]"
		pattern = "90????????????????????????????????????????????????????????????????????????????????????????????90FFE0E912000000000000000000000000000000E9FBFFFFFFC3680000000064FF35"
	strings:
		$1 = { 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 90 FF E0 E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 }
	condition:
		$1 at pe.entry_point
}

rule ai1_creator_1b2 {
	meta:
		tool = "P"
		name = "AI1 Creator"
		version = "1b2"
		pattern = "E8FEFDFFFF6A00E80D000000CCFF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { E8 FE FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		$1 at pe.entry_point
}

rule alex_protector_04b1 {
	meta:
		tool = "P"
		name = "Alex Protector"
		version = "0.4b1"
		pattern = "60E801000000C783C40433C9E8010000006883C404E8010000006883C404B9??000000E8010000006883C404E800000000E801000000C783C4048B2C2483C404E801000000A983C40481ED3C134000E8010000006883C404E800000000E80000000049E8010000006883C40485C975DFE8B9020000E801000000C783C4048D9563144000E801000000C783C404909090E8CA01000001020304056890608B7424248B7C2428FCB2"
	strings:
		$1 = { 60 E8 01 00 00 00 C7 83 C4 04 33 C9 E8 01 00 00 00 68 83 C4 04 E8 01 00 00 00 68 83 C4 04 B9 ?? 00 00 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 01 00 00 00 C7 83 C4 04 8B 2C 24 83 C4 04 E8 01 00 00 00 A9 83 C4 04 81 ED 3C 13 40 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 00 00 00 00 49 E8 01 00 00 00 68 83 C4 04 85 C9 75 DF E8 B9 02 00 00 E8 01 00 00 00 C7 83 C4 04 8D 95 63 14 40 00 E8 01 00 00 00 C7 83 C4 04 90 90 90 E8 CA 01 00 00 01 02 03 04 05 68 90 60 8B 74 24 24 8B 7C 24 28 FC B2 }
	condition:
		$1 at pe.entry_point
}

rule alex_protector_10b2 {
	meta:
		tool = "P"
		name = "Alex Protector"
		version = "1.0b2"
		pattern = "60E8000000005D81ED06104000E824000000EB01E98B44240CEB03EB03C7EBFBE801000000A883C4048380B80000000233C0EB01E9C35883C404EB03EB03C7EBFBE801000000A883C4045064FF350000000064892500000000EB01E9FFFF60EB03EB03C7EBFBE801000000A883C4040F318BD8EB03EB03C7EBFBE801000000A883C4048BCAEB03EB03C7EBFBE801000000A883C4040F312BC3EB03EB03C7EBFBE801000000A883"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 00 00 00 02 33 C0 EB 01 E9 C3 58 83 C4 04 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 EB 01 E9 FF FF 60 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 0F 31 8B D8 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 8B CA EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 0F 31 2B C3 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 }
	condition:
		$1 at pe.entry_point
}

rule alex_protector_10 {
	meta:
		tool = "P"
		name = "Alex Protector"
		version = "1.0"
		pattern = "60E8000000005D81ED06104000E824000000EB01E98B"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B }
	condition:
		$1 at pe.entry_point
}

rule alloy_1x2000 {
	meta:
		tool = "P"
		name = "Alloy"
		version = "1.x.2000"
		pattern = "9C60E802??????33C08BC483C004938BE38B5BFC81EB072040??87DD6A0468??10????68??02????6A??FF95462340??0B"
	strings:
		$1 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 46 23 40 ?? 0B }
	condition:
		$1 at pe.entry_point
}

rule alloy_4x {
	meta:
		tool = "P"
		name = "Alloy"
		version = "4.x"
		pattern = "9C60E80200000033C08BC483C004938BE38B5BFC81EB0730400087DD6A04680010000068000200006A00FF95A83340000BC00F84F601000089852E33400083BDE832400001740D83BDE432400001742A8BF8EB3E68D801000050FF95CC334000508D852833400050FFB52E334000FF95D03340005883C005EB0C68D801000050FF95C03340008BBD2E33400003F8C6075C478DB500334000AC0AC07403AAEBF883BDDC32400001"
	strings:
		$1 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 A8 33 40 00 0B C0 0F 84 F6 01 00 00 89 85 2E 33 40 00 83 BD E8 32 40 00 01 74 0D 83 BD E4 32 40 00 01 74 2A 8B F8 EB 3E 68 D8 01 00 00 50 FF 95 CC 33 40 00 50 8D 85 28 33 40 00 50 FF B5 2E 33 40 00 FF 95 D0 33 40 00 58 83 C0 05 EB 0C 68 D8 01 00 00 50 FF 95 C0 33 40 00 8B BD 2E 33 40 00 03 F8 C6 07 5C 47 8D B5 00 33 40 00 AC 0A C0 74 03 AA EB F8 83 BD DC 32 40 00 01 }
	condition:
		$1 at pe.entry_point
}

rule andpakk_2006 {
	meta:
		tool = "P"
		name = "ANDpakk"
		version = "2.0.06"
		pattern = "60FCBE????????BF????????5783CDFF33C9F9EB05A402DB75058A1E4612DB72F433C04002DB75058A1E4612DB13C002DB75058A1E4612DB720E4802DB75058A1E4612DB13C0EBDC83E803720FC1E008AC83F0FF744DD1F88BE8EB0902DB75058A1E4612DB13C902DB75058A1E4612DB13C9751A4102DB75058A1E4612DB13C902DB75058A1E4612DB73EA83C10281FD????????83D101568D342FF3A45EE973FFFFFFC3"
	strings:
		$1 = { 60 FC BE ?? ?? ?? ?? BF ?? ?? ?? ?? 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD ?? ?? ?? ?? 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3 }
	condition:
		$1 at pe.entry_point
}

rule andpakk_2018 {
	meta:
		tool = "P"
		name = "ANDpakk"
		version = "2.0.18"
		pattern = "FCBE????????BF????????5783CDFF33C9F9EB05A402DB75058A1E4612DB72F433C04002DB75058A1E4612DB13C002DB75058A1E4612DB720E4802DB75058A1E4612DB13C0EBDC83E803720FC1E008AC83F0FF744DD1F88BE8EB0902DB75058A1E4612DB13C902DB75058A1E4612DB13C9751A4102DB75058A1E4612DB13C902DB75058A1E4612DB73EA83C10281FD????????83D101568D342FF3A45EE973FFFFFFC3"
	strings:
		$1 = { FC BE ?? ?? ?? ?? BF ?? ?? ?? ?? 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD ?? ?? ?? ?? 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3 }
	condition:
		$1 at pe.entry_point
}

rule anskya_binder_11 {
	meta:
		tool = "P"
		name = "Anskya Binder"
		version = "1.1"
		pattern = "BE??????00BBF811400033ED83EE04392E7411"
	strings:
		$1 = { BE ?? ?? ?? 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }
	condition:
		$1 at pe.entry_point
}

rule anskya_ntpacker_generator {
	meta:
		tool = "P"
		name = "Anskya NTPacker Generator"
		pattern = "558BEC83C4F053B8881D0010E8C7FAFFFF6A0A68201E0010A11431001050E871FBFFFF8BD885DB742F53A11431001050E897FBFFFF85C0741F53A11431001050E85FFBFFFF85C0740F50E85DFBFFFF85C07405E870FCFFFF5BE8F2F6FFFF00004845415254"
	strings:
		$1 = { 55 8B EC 83 C4 F0 53 B8 88 1D 00 10 E8 C7 FA FF FF 6A 0A 68 20 1E 00 10 A1 14 31 00 10 50 E8 71 FB FF FF 8B D8 85 DB 74 2F 53 A1 14 31 00 10 50 E8 97 FB FF FF 85 C0 74 1F 53 A1 14 31 00 10 50 E8 5F FB FF FF 85 C0 74 0F 50 E8 5D FB FF FF 85 C0 74 05 E8 70 FC FF FF 5B E8 F2 F6 FF FF 00 00 48 45 41 52 54 }
	condition:
		$1 at pe.entry_point
}

rule anslym_fud_crypter {
	meta:
		tool = "P"
		name = "Anslym FUD Crypter"
		pattern = "558BEC83C4F05356B838170510E85A45FBFF33C05568211C051064FF30648920EB08FCFCFCFCFCFC2754E8854CFBFF6A00E80E47FBFF6A0AE82749FBFFE8EA47FBFF6A0A"
	strings:
		$1 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A }
	condition:
		$1 at pe.entry_point
}

rule anti007_uv {
	meta:
		tool = "P"
		name = "Anti007"
		extra = "NsPacK Private"
		pattern = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000????????????????????????0010000000000000????????000000000000000000000000600000E0????????????????????????????????????????????????000000000000000000000000600000E0????????????????????????????????00000000????????000000000000000000000000600000E0"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 60 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 60 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 60 00 00 E0 }
	condition:
		$1 at pe.entry_point
}

rule anti007_10_2x {
	meta:
		tool = "P"
		name = "Anti007"
		version = "1.0 - 2.x"
		extra = "NsPacK Private"
		pattern = "0000004C6F61644C6962726172794100000047657450726F63416464726573730000005669727475616C50726F746563740000005669727475616C416C6C6F630000005669727475616C467265650000004578697450726F63657373000000"
	strings:
		$1 = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule anti007_26 {
	meta:
		tool = "P"
		name = "Anti007"
		version = "2.6"
		pattern = "0000004C6F61644C6962726172794100000047657450726F63416464726573730000005669727475616C50726F746563740000005669727475616C416C6C6F630000005669727475616C4672656500000047657453797374656D4469726563746F72794100000043726561746546696C6541000000577269746546696C65000000436C6F736548616E646C650000004578697450726F636573730000"
	strings:
		$1 = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 57 72 69 74 65 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 }
	condition:
		$1 at pe.entry_point
}

rule anti007_27_35 {
	meta:
		tool = "P"
		name = "Anti007"
		version = "2.7 - 3.5"
		pattern = "0000004C6F61644C6962726172794100000047657450726F63416464726573730000005669727475616C50726F746563740000005669727475616C416C6C6F630000005669727475616C4672656500000047657454656D70506174684100000043726561746546696C6541000000577269746546696C65000000436C6F736548616E646C650000004578697450726F63657373000000"
	strings:
		$1 = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 57 72 69 74 65 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule antidote_10_14 {
	meta:
		tool = "P"
		name = "AntiDote"
		version = "1.0 - 1.4"
		pattern = "000000000901476574436F6D6D616E644C696E654100DB0147657456657273696F6E4578410073014765744D6F64756C6546696C654E616D654100007A0357616974466F7253696E676C654F626A65637400BF02526573756D6554687265616400002903536574546872656164436F6E7465787400009403577269746550726F636573734D656D6F727900006B035669727475616C416C6C6F6345780000A6025265616450726F636573734D656D6F727900CA01476574546872656164436F6E746578740000620043726561746550726F636573734100004B45524E454C33322E646C6C"
	strings:
		$1 = { 00 00 00 00 09 01 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 DB 01 47 65 74 56 65 72 73 69 6F 6E 45 78 41 00 73 01 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 00 7A 03 57 61 69 74 46 6F 72 53 69 6E 67 6C 65 4F 62 6A 65 63 74 00 BF 02 52 65 73 75 6D 65 54 68 72 65 61 64 00 00 29 03 53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 94 03 57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 00 6B 03 56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 00 00 A6 02 52 65 61 64 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 CA 01 47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 62 00 43 72 65 61 74 65 50 72 6F 63 65 73 73 41 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C }
	condition:
		$1 at pe.entry_point
}

rule antidote_10b {
	meta:
		tool = "P"
		name = "AntiDote"
		version = "1.0b"
		pattern = "E8BBFFFFFF84C0742F680401000068C02360006A00FF1508106000E840FFFFFF506878116000686811600068C0236000E8ABFDFFFF83C41033C0C210009090908B4C2408568B74240833D28BC6F7F18BC685D2740833D2F7F1400FAFC15EC3908B4424045355568B483C5703C833D28B79548B71388BC7F7F685D2740C8BC733D2F7F68BF8470FAFFE33C033DB668B41148D54081833C0668B4106895424148D68FF85ED7C3733C0"
	strings:
		$1 = { E8 BB FF FF FF 84 C0 74 2F 68 04 01 00 00 68 C0 23 60 00 6A 00 FF 15 08 10 60 00 E8 40 FF FF FF 50 68 78 11 60 00 68 68 11 60 00 68 C0 23 60 00 E8 AB FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 66 8B 41 06 89 54 24 14 8D 68 FF 85 ED 7C 37 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule antidote_12b_demo {
	meta:
		tool = "P"
		name = "AntiDote"
		version = "1.2b demo"
		pattern = "6869D60000E8C6FDFFFF6869D60000E8BCFDFFFF83C408E8A4FFFFFF84C0742F680401000068B02160006A00FF1508106000E829FFFFFF506888106000687810600068B0216000E8A4FDFFFF83C41033C0C210009090909090909090909090908B4C2408568B74240833D28BC6F7F18BC685D2740833D2F7F1400FAFC15EC3908B4424045355568B483C5703C833D28B79548B71388BC7F7F685D2740C8BC733D2F7F68BF8470FAFFE33C033DB668B41148D54081833C0"
	strings:
		$1 = { 68 69 D6 00 00 E8 C6 FD FF FF 68 69 D6 00 00 E8 BC FD FF FF 83 C4 08 E8 A4 FF FF FF 84 C0 74 2F 68 04 01 00 00 68 B0 21 60 00 6A 00 FF 15 08 10 60 00 E8 29 FF FF FF 50 68 88 10 60 00 68 78 10 60 00 68 B0 21 60 00 E8 A4 FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 90 90 90 90 90 90 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule antidote_12_demo {
	meta:
		tool = "P"
		name = "AntiDote"
		version = "1.2 demo"
		pattern = "E8F7FEFFFF05CB220000FFE0E8EBFEFFFF05BB190000FFE0E8BD00000008B262000152170C0F2C2B207F527901300717294F013C302B5A3DC726112606590E782E10140B131A1A3F641D7133572109248B1B093708610F1D1D2A0187354C07390B"
	strings:
		$1 = { E8 F7 FE FF FF 05 CB 22 00 00 FF E0 E8 EB FE FF FF 05 BB 19 00 00 FF E0 E8 BD 00 00 00 08 B2 62 00 01 52 17 0C 0F 2C 2B 20 7F 52 79 01 30 07 17 29 4F 01 3C 30 2B 5A 3D C7 26 11 26 06 59 0E 78 2E 10 14 0B 13 1A 1A 3F 64 1D 71 33 57 21 09 24 8B 1B 09 37 08 61 0F 1D 1D 2A 01 87 35 4C 07 39 0B }
	condition:
		$1 at pe.entry_point
}

rule antidote_12_14 {
	meta:
		tool = "P"
		name = "AntiDote"
		version = "1.2, 1.4"
		pattern = "EB1066623A432B2B484F4F4B90E9083290909090909090909090807C2408010F85????????60BE????????8DBE????????5783CDFFEB0B908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73EF75098B1E83EEFC11DB73E431C983E803720DC1E0088A064683F0FF747489C501DB75078B1E83EEFC11DB11C901DB75078B1E83EEFC11DB11C975204101DB75078B1E83EEFC11DB11C901DB73EF75098B1E83EEFC11DB73E483C10281FD00F3FFFF83D1018D142F83FDFC760F8A02428807474975F7E963FFFFFF908B0283C204890783C70483E90477F101CFE94CFFFFFF"
	strings:
		$1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule antidote_14 {
	meta:
		tool = "P"
		name = "AntiDote"
		version = "1.4"
		pattern = "6890030000E8C6FDFFFF6890030000E8BCFDFFFF6890030000E8B2FDFFFF50E8ACFDFFFF50E8A6FDFFFF6869D60000E89CFDFFFF50E896FDFFFF50E890FDFFFF83C420E878FFFFFF84C0744F680401000068102260006A00FF15081060006890030000E868FDFFFF6869D60000E85EFDFFFF50E858FDFFFF50E852FDFFFFE8DDFEFFFF5068A410600068941060006810226000E858FDFFFF83C42033C0C210008B4C2408568B74240833D28BC6F7F18BC685D2740833D2F7F1400FAFC15EC3"
	strings:
		$1 = { 68 90 03 00 00 E8 C6 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50 E8 AC FD FF FF 50 E8 A6 FD FF FF 68 69 D6 00 00 E8 9C FD FF FF 50 E8 96 FD FF FF 50 E8 90 FD FF FF 83 C4 20 E8 78 FF FF FF 84 C0 74 4F 68 04 01 00 00 68 10 22 60 00 6A 00 FF 15 08 10 60 00 68 90 03 00 00 E8 68 FD FF FF 68 69 D6 00 00 E8 5E FD FF FF 50 E8 58 FD FF FF 50 E8 52 FD FF FF E8 DD FE FF FF 50 68 A4 10 60 00 68 94 10 60 00 68 10 22 60 00 E8 58 FD FF FF 83 C4 20 33 C0 C2 10 00 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 }
	condition:
		$1 at pe.entry_point
}

rule antivirus_vaccine_103 {
	meta:
		tool = "P"
		name = "AntiVirus Vaccine"
		version = "1.03"
		pattern = "FA33DBB9????0E1F33F6FCAD35????03D8E2"
	strings:
		$1 = { FA 33 DB B9 ?? ?? 0E 1F 33 F6 FC AD 35 ?? ?? 03 D8 E2 }
	condition:
		$1 at pe.entry_point
}

rule apatch_gui_11 {
	meta:
		tool = "P"
		name = "APatch GUI"
		version = "1.1"
		pattern = "5231C0E8FFFFFFFF"
	strings:
		$1 = { 52 31 C0 E8 FF FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule apex_30a {
	meta:
		tool = "P"
		name = "Apex"
		version = "3.0a"
		pattern = "5FB91400000051BE00104000B900????008A07300646E2FB4759E2EA68??????00C3"
	strings:
		$1 = { 5F B9 14 00 00 00 51 BE 00 10 40 00 B9 00 ?? ?? 00 8A 07 30 06 46 E2 FB 47 59 E2 EA 68 ?? ?? ?? 00 C3 }
	condition:
		$1 at pe.entry_point
}

rule apex_c_blt_apex_40 {
	meta:
		tool = "P"
		name = "APEX_C"
		version = "BLT Apex 4.0"
		pattern = "68????????B9FFFFFF0001D0F7E2720148E2F7B9FF0000008B34248036FD46E2FAC3"
	strings:
		$1 = { 68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 }
	condition:
		$1 at pe.entry_point
}

rule app_encryptor {
	meta:
		tool = "P"
		name = "App Encryptor"
		pattern = "60E8000000005D81ED1F1F4000B97B0900008DBD671F40008BF7AC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 1F 1F 40 00 B9 7B 09 00 00 8D BD 67 1F 40 00 8B F7 AC }
	condition:
		$1 at pe.entry_point
}

rule app_protector {
	meta:
		tool = "P"
		name = "App Protector"
		pattern = "E9970000000D0A53696C656E74205465616D204170702050726F746563746F720D0A437265617465642062792053696C656E7420536F6674776172650D0A5468656E6B7A20746F20446F6368746F7220580D0A0D0A"
	strings:
		$1 = { E9 97 00 00 00 0D 0A 53 69 6C 65 6E 74 20 54 65 61 6D 20 41 70 70 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 72 65 61 74 65 64 20 62 79 20 53 69 6C 65 6E 74 20 53 6F 66 74 77 61 72 65 0D 0A 54 68 65 6E 6B 7A 20 74 6F 20 44 6F 63 68 74 6F 72 20 58 0D 0A 0D 0A }
	condition:
		$1 at pe.entry_point
}

rule arm_protector {
	meta:
		tool = "P"
		name = "ARM Protector"
		version = "0.1 - 0.3"
		pattern = "E8040000008360EB0C5DEB054555EB04B8EBF900C3E8000000005DEB010081ED5E1F4000EB0283098DB5EF1F4000EB028309BAA3110000EB01008D8D923140008B09E81400000083EB01008BFEE8000000005883C0"
	strings:
		$1 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_uv {
	meta:
		tool = "P"
		name = "Armadillo"
		pattern = "E8????????E9????????6A0C68????????E8????????8B4D0833FF3BCF762E6AE05833D2F7F13B450C1BC040751FE8????????C7000C0000005757575757E8"
	strings:
		$1 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 ?? ?? ?? ?? C7 00 0C 00 00 00 57 57 57 57 57 E8 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_19x_200b1_250b1 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "1.9x, 2.00b1, 2.50b1"
		pattern = "558BEC6AFF6898??????6810??????64A1????????50648925????????83EC585356578965E8FF15"
	strings:
		$1 = { 55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_200 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.00"
		pattern = "558BEC6AFF680002410068C4A0400064A100000000506489250000000083EC58"
	strings:
		$1 = { 55 8B EC 6A FF 68 00 02 41 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_250_250b3 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.50, 2.50b3"
		pattern = "558BEC6AFF68B8??????68F8??????64A1????????50648925????????83EC585356578965E8FF1520??????33D28AD48915D0"
	strings:
		$1 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_251 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.51"
		pattern = "558BEC6AFF68B8??????68D0??????64A1????????50648925????????83EC585356578965E8FF1520"
	strings:
		$1 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_252b2_01 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.52b2"
		pattern = "558BEC6AFF68????????B0????????686064A100000000506489250000000083EC585356578965E8FF??????1524"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? B0 ?? ?? ?? ?? 68 60 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 24 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_252b2_02 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.52b2"
		pattern = "558BEC6AFF68B0??????6860??????64A1????????50648925????????83EC585356578965E8FF1524"
	strings:
		$1 = { 55 8B EC 6A FF 68 B0 ?? ?? ?? 68 60 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 24 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_252_01 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.52"
		pattern = "558BEC6AFF68????????E0????????68D464A100000000506489250000000083EC585356578965E8FF??????1538"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? E0 ?? ?? ?? ?? 68 D4 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 38 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_252_02 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.52"
		pattern = "558BEC6AFF68E0??????68D4??????64A1????????50648925????????83EC585356578965E8FF1538"
	strings:
		$1 = { 55 8B EC 6A FF 68 E0 ?? ?? ?? 68 D4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 38 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_253_01 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.53"
		pattern = "558BEC6AFF68????????40????????685464A100000000506489250000000083EC585356578965E8FF??????155833D28AD489"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 40 ?? ?? ?? ?? 68 54 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 58 33 D2 8A D4 89 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_253_02 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.53"
		pattern = "558BEC6AFF6840??????6854??????64A1????????50648925????????83EC585356578965E8FF1558??????33D28AD48915EC"
	strings:
		$1 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 54 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }
	condition:
		$1 at pe.entry_point
}

rule armadillo_253b3 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.53b3"
		pattern = "558BEC6AFF68D8??????6814??????64A1????????50648925????????83EC585356578965E8FF15"
	strings:
		$1 = { 55 8B EC 6A FF 68 D8 ?? ?? ?? 68 14 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_25x_26x {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.5x - 2.6x"
		pattern = "558BEC6AFF68????????68????????64A100000000506489250000000083EC585356578965E8FF1558??????33D28AD48915EC"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }
	condition:
		$1 at pe.entry_point
}

rule armadillo_260a {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.60a"
		pattern = "558BEC6AFF68????????6894??????64A1????????50648925????????83EC585356578965E8FF156C??????33D28AD48915B4"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 94 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 B4 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_260b1 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.60b1"
		pattern = "558BEC6AFF6850??????6874??????64A1????????50648925????????83EC585356578965E8FF1558??????33D28AD48915FC"
	strings:
		$1 = { 55 8B EC 6A FF 68 50 ?? ?? ?? 68 74 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 FC }
	condition:
		$1 at pe.entry_point
}

rule armadillo_260b2 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.60b2"
		pattern = "558BEC6AFF6890??????6824??????64A1????????50648925????????83EC585356578965E8FF1560??????33D28AD489153C"
	strings:
		$1 = { 55 8B EC 6A FF 68 90 ?? ?? ?? 68 24 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 60 ?? ?? ?? 33 D2 8A D4 89 15 3C }
	condition:
		$1 at pe.entry_point
}

rule armadillo_260c {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.60c"
		pattern = "558BEC6AFF6840??????68F4??????64A1????????50648925????????83EC585356578965E8FF156C??????33D28AD48915F4"
	strings:
		$1 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 F4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 F4 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_260 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.60"
		pattern = "558BEC6AFF68D0??????6834??????64A1????????50648925????????83EC585356578965E8FF1568??????33D28AD4891584"
	strings:
		$1 = { 55 8B EC 6A FF 68 D0 ?? ?? ?? 68 34 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 68 ?? ?? ?? 33 D2 8A D4 89 15 84 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_261 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.61"
		pattern = "558BEC6AFF6828??????68E4??????64A1????????50648925????????83EC585356578965E8FF156C??????33D28AD489150C"
	strings:
		$1 = { 55 8B EC 6A FF 68 28 ?? ?? ?? 68 E4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 0C }
	condition:
		$1 at pe.entry_point
}

rule armadillo_265b1 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.65b1"
		pattern = "558BEC6AFF6838??????6840??????64A1????????50648925????????83EC585356578965E8FF1528??????33D28AD48915F4"
	strings:
		$1 = { 55 8B EC 6A FF 68 38 ?? ?? ?? 68 40 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 F4 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_275_285 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.75 - 2.85"
		pattern = "558BEC6AFF6868??????68????????64A1????????50648925????????83EC585356578965E8FF1528??????33D28AD4891524"
	strings:
		$1 = { 55 8B EC 6A FF 68 68 ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 28 ?? ?? ?? 33 D2 8A D4 89 15 24 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_2xx {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.xx (CopyMem II)"
		pattern = "6A??8BB5????????C1E6048B85????????2507????8079054883C8F84033C98A88????????8B95????????81E207????8079054A83CAF84233C08A82"
	strings:
		$1 = { 6A ?? 8B B5 ?? ?? ?? ?? C1 E6 04 8B 85 ?? ?? ?? ?? 25 07 ?? ?? 80 79 05 48 83 C8 F8 40 33 C9 8A 88 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 81 E2 07 ?? ?? 80 79 05 4A 83 CA F8 42 33 C0 8A 82 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_300_305 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "3.00 - 3.05"
		pattern = "60E8000000005D5051EB0F??EB0F??EB07??EB0F??EB08FDEB0BF2EBF5EBF6F2EB08FDEBE9F3EBE4FC??59585051EB0F??EB0F??EB07??EB0F??EB08FDEB0BF2EBF5EBF6F2EB08FDEBE9F3EBE4FC??59585051EB0F"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F }
	condition:
		$1 at pe.entry_point
}

rule armadillo_300_37x {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "3.00a, 3.01 - 3.50a, 3.01 - 3.50, 3.6x, 3.7x"
		pattern = "60E8000000005D5051EB0F??EB0F??EB07??EB0F??EB08FDEB0BF2EBF5EBF6F2EB08FDEBE9F3EBE4FC??59585051EB0F??EB0F??EB07??EB0F??EB08FDEB0BF2EBF5EBF6F2EB08FDEBE9F3EBE4FC??59585051EB0F??EB0F??EB07??EB0F??EB08FDEB0BF2EBF5EBF6F2EB08FDEBE9F3EBE4FC??59586033C97502EB15??33C975187A0C700EEB0D??720E79F1??????790974F0??87DB7AF0????615051EB0F??EB0F??EB07"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 ?? 87 DB 7A F0 ?? ?? 61 50 51 EB 0F ?? EB 0F ?? EB 07 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_310_01 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "3.10"
		pattern = "558BEC6AFF68E09744006820C0420064A100000000506489250000000083EC585356578965E8FF154C41440033D28AD4891590A144008BC881E1FF000000890D8CA14400C1E10803CA890D88A14400C1E810A384A1440033F656E8721600005985C075086A1CE8B0000000598975FCE83D130000FF1530404400A384B74400E8FB110000A3E0A14400E8A40F0000E8E60E0000E84EF6FFFF8975D08D45A450FF1538404400E877"
	strings:
		$1 = { 55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1 44 00 33 F6 56 E8 72 16 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 3D 13 00 00 FF 15 30 40 44 00 A3 84 B7 44 00 E8 FB 11 00 00 A3 E0 A1 44 00 E8 A4 0F 00 00 E8 E6 0E 00 00 E8 4E F6 FF FF 89 75 D0 8D 45 A4 50 FF 15 38 40 44 00 E8 77 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_310_02 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "3.10"
		pattern = "558BEC6AFF68E09744006820C0420064A100000000506489250000000083EC585356578965E8FF154C41440033D28AD4891590A144008BC881E1FF000000890D8CA14400C1E10803CA890D88A14400C1E810A384A1"
	strings:
		$1 = { 55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_378 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "3.78"
		pattern = "60E8????????5D50510FCAF7D29CF7D20FCAEB0FB9EB0FB8EB07B9EB0F90EB08FDEB0B"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B }
	condition:
		$1 at pe.entry_point
}

rule armadillo_3xx_6xx {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "3.xx - 6.xx"
		pattern = "60E8000000005D50510FCAF7D29CF7D20FCAEB0FB9EB0FB8EB07B9EB0F90EB08FDEB0BF2EBF5EBF6F2EB08FDEBE9F3EBE4FCE99D0FC98BCAF7D1595850510FCAF7D29CF7D20FCAEB0FB9EB0FB8EB07B9EB0F90EB08"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_3xx {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "3.xx"
		pattern = "60E8????????5D5051EB0FB9EB0FB8EB07B9EB0F90EB08FDEB0B"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B }
	condition:
		$1 at pe.entry_point
}

rule armadillo_400 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "4.00"
		pattern = "558BEC6AFF68208B4B006880E4480064A100000000506489250000000083EC585356578965E8FF1588314B0033D28AD48915A4A14B008BC881E1FF000000890DA0A14B00C1E10803CA890D9CA14B00C1E810A398A1"
	strings:
		$1 = { 55 8B EC 6A FF 68 20 8B 4B 00 68 80 E4 48 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4B 00 33 D2 8A D4 89 15 A4 A1 4B 00 8B C8 81 E1 FF 00 00 00 89 0D A0 A1 4B 00 C1 E1 08 03 CA 89 0D 9C A1 4B 00 C1 E8 10 A3 98 A1 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_410 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "4.10"
		comment = "Silicon Realms Toolworks"
		pattern = "558BEC6AFF68F88E4C0068D0EA490064A100000000506489250000000083EC585356578965E8FF1588314C0033D28AD489157CA54C008BC881E1FF000000890D78A54C00C1E10803CA890D74A54C00C1E810A370A5"
	strings:
		$1 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 D0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 7C A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 78 A5 4C 00 C1 E1 08 03 CA 89 0D 74 A5 4C 00 C1 E8 10 A3 70 A5 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_420 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "4.20"
		comment = "Silicon Realms Toolworks"
		pattern = "558BEC6AFF68F88E4C0068F0EA490064A100000000506489250000000083EC585356578965E8FF1588314C0033D28AD4891584A54C008BC881E1FF000000890D80A54C00C1E10803CA890D7CA54C00C1E810A378A5"
	strings:
		$1 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 F0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 84 A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 80 A5 4C 00 C1 E1 08 03 CA 89 0D 7C A5 4C 00 C1 E8 10 A3 78 A5 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_430a {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "4.30a"
		pattern = "4464654461746120696E697469616C697A65642028414E5349292C2061707020737472696E677320617265202725732720616E6420272573270000004464654461746120696E697469616C697A65642028554E49434F4445292C2061707020737472696E677320617265202725532720616E64202725532700000000507574537472696E6728272573272900476574537472696E6728292C2066616C7365000047657453"
	strings:
		$1 = { 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 41 4E 53 49 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 73 27 20 61 6E 64 20 27 25 73 27 00 00 00 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 55 4E 49 43 4F 44 45 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 53 27 20 61 6E 64 20 27 25 53 27 00 00 00 00 50 75 74 53 74 72 69 6E 67 28 27 25 73 27 29 00 47 65 74 53 74 72 69 6E 67 28 29 2C 20 66 61 6C 73 65 00 00 47 65 74 53 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_430_440 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "4.30 - 4.40"
		pattern = "558BEC6AFF6840????006880????0064A100000000506489250000000083EC585356578965E8FF1588????0033D28AD4891530????008BC881E1FF000000890D2C????00C1E10803CA890D28????00C1E810A324"
	strings:
		$1 = { 55 8B EC 6A FF 68 40 ?? ?? 00 68 80 ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 ?? ?? 00 33 D2 8A D4 89 15 30 ?? ?? 00 8B C8 81 E1 FF 00 00 00 89 0D 2C ?? ?? 00 C1 E1 08 03 CA 89 0D 28 ?? ?? 00 C1 E8 10 A3 24 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_440 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "4.40"
		pattern = "312E312E34000000C2E094BE93FCDEC6B62483F7D2A492774027CFEBD86F50B4B52924FA45080452D51BD28C8A1E6EFF8C5F4289F183B127C56957FC550ADD44BE2A02976B6515AA31E9287D491BDFB55D08A8BAA873DCF6D105425553797374656D0000530079007300740065006D00000000004444452050726F63657373696E67000053775044444500004400440045002000500072006F00630065007300730069006E0067"
	strings:
		$1 = { 31 2E 31 2E 34 00 00 00 C2 E0 94 BE 93 FC DE C6 B6 24 83 F7 D2 A4 92 77 40 27 CF EB D8 6F 50 B4 B5 29 24 FA 45 08 04 52 D5 1B D2 8C 8A 1E 6E FF 8C 5F 42 89 F1 83 B1 27 C5 69 57 FC 55 0A DD 44 BE 2A 02 97 6B 65 15 AA 31 E9 28 7D 49 1B DF B5 5D 08 A8 BA A8 73 DC F6 D1 05 42 55 53 79 73 74 65 6D 00 00 53 00 79 00 73 00 74 00 65 00 6D 00 00 00 00 00 44 44 45 20 50 72 6F 63 65 73 73 69 6E 67 00 00 53 77 50 44 44 45 00 00 44 00 44 00 45 00 20 00 50 00 72 00 6F 00 63 00 65 00 73 00 73 00 69 00 6E 00 67 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_50x {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "5.0x"
		pattern = "E8E3400000E916FEFFFF6A0C68????????E8441500008B4D0833FF3BCF762E6AE05833D2F7F13B450C1BC040751FE836130000C7000C0000005757575757E8C712000083C41433C0E9D50000000FAF4D0C8BF18975083BF7750333F64633DB895DE483FEE07769833D????????03754B83C60F83E6F089750C8B45083B05????????77376A04E84811000059897DFC??7508E801490000598945E4C745FCFEFFFFFFE85F0000008B5DE43BDF7411FF75085753E866D3FFFF83C40C3BDF7561566A08FF35????????FF15????????8BD83BDF754C393D????????743356E8AFF9FFFF5985C00F8572FFFFFF8B45103BC70F8450FFFFFFC7000C000000E945FFFFFF33FF8B750C6A04E8EE0F000059C3"
	strings:
		$1 = { E8 E3 40 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 44 15 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 36 13 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 C7 12 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 48 11 00 00 59 89 7D FC ?? 75 08 E8 01 49 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 66 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 AF F9 FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 EE 0F 00 00 59 C3 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_5xx {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "5.xx"
		pattern = "837C2408017505E8????????FF7424048B4C24108B54240CE8????????59C20C006A0C68????????E8????????8B4D0833FF3BCF762E6AE05833D2F7F13B450C1BC040751FE8????????C7000C0000005757575757E8????????83C41433C0E9D50000000FAF4D0C8BF18975083BF7750333F64633DB895DE483FEE07769833D????????03754B83C60F83E6F089750C8B45083B05????????77376A04E8????????59897DFCFF7508E8????????598945E4C745FCFEFFFFFFE8????????8B5DE43BDF7411FF75085753E8????????83C40C3BDF7561566A08FF35????????FF15????????8BD83BDF754C393D????????743356E8????????5985C00F8572FFFFFF8B45103BC70F8450FFFFFFC7000C000000E945FFFFFF33FF8B750C6A04E8????????59C3"
	strings:
		$1 = { 83 7C 24 08 01 75 05 E8 ?? ?? ?? ?? FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ?? ?? ?? ?? 59 C2 0C 00 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 ?? ?? ?? ?? C7 00 0C 00 00 00 57 57 57 57 57 E8 ?? ?? ?? ?? 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 ?? ?? ?? ?? 59 89 7D FC FF 75 08 E8 ?? ?? ?? ?? 59 89 45 E4 C7 45 FC FE FF FF FF E8 ?? ?? ?? ?? 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 ?? ?? ?? ?? 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 ?? ?? ?? ?? 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 ?? ?? ?? ?? 59 C3 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_520b1 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "5.20b1"
		pattern = "E88E3F0000E916FEFFFF6A0C68????????E89E1600008B4D0833FF3BCF762E6AE05833D2F7F13B450C1BC040751FE8F5140000C7000C0000005757575757E88614000083C41433C0E9D50000000FAF4D0C8BF18975083BF7750333F64633DB895DE483FEE07769833D??????????754B83C60F83E6F089750C8B45083B05????????77376A04E80713000059897DFCFF7508E8AC470000598945E4C745FCFEFFFFFFE85F0000008B5DE43BDF7411FF75085753E87CD3FFFF83C40C3BDF7561566A08FF35????????FF15????????8BD83BDF754C393D????????743356E8C7F9FFFF5985C00F8572FFFFFF8B45103BC70F8450FFFFFFC7000C000000E945FFFFFF33FF8B750C6A04E8AD11000059C3"
	strings:
		$1 = { E8 8E 3F 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 9E 16 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 F5 14 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 86 14 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? ?? 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 07 13 00 00 59 89 7D FC FF 75 08 E8 AC 47 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 7C D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 C7 F9 FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 AD 11 00 00 59 C3 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_520 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "5.20"
		pattern = "E8383D0000E916FEFFFF6A0C68????????E8981E00008B4D0833FF3BCF762E6AE05833D2F7F13B450C1BC040751FE8EC1C0000C7000C0000005757575757E87D1C000083C41433C0E9D50000000FAF4D0C8BF18975083BF7750333F64633DB895DE483FEE07769833D??????????754B83C60F83E6F089750C8B45083B05????????77376A04E8FE1A000059897DFCFF7508E856450000598945E4C745FCFEFFFFFFE85F0000008B5DE43BDF7411FF75085753E896D3FFFF83C40C3BDF7561566A08FF35????????FF15????????8BD83BDF754C393D????????743356E8C0FAFFFF5985C00F8572FFFFFF8B45103BC70F8450FFFFFFC7000C000000E945FFFFFF33FF8B750C6A04E8A419000059C33BDF750D8B45103BC77406C7000C0000008BC3E8CC1D0000C3558BEC518365FC00578D45FC50FF750CFF7508E8CAFEFFFF8BF883C40C85FF7519568B75FC85F67410E8C91B000085C07407E8C01B000089305E8BC75FC9C36A0C68????????E83B1D00008B750885F67475833D??????????75436A04E8FF190000598365FC0056E8843C0000598945E485C074095650E8A03C00005959C745FCFEFFFFFFE80B000000837DE4007537FF7508EB0A6A04E8ED18000059C3"
	strings:
		$1 = { E8 38 3D 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 98 1E 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 EC 1C 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 7D 1C 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? ?? 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 FE 1A 00 00 59 89 7D FC FF 75 08 E8 56 45 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 96 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 C0 FA FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 A4 19 00 00 59 C3 3B DF 75 0D 8B 45 10 3B C7 74 06 C7 00 0C 00 00 00 8B C3 E8 CC 1D 00 00 C3 55 8B EC 51 83 65 FC 00 57 8D 45 FC 50 FF 75 0C FF 75 08 E8 CA FE FF FF 8B F8 83 C4 0C 85 FF 75 19 56 8B 75 FC 85 F6 74 10 E8 C9 1B 00 00 85 C0 74 07 E8 C0 1B 00 00 89 30 5E 8B C7 5F C9 C3 6A 0C 68 ?? ?? ?? ?? E8 3B 1D 00 00 8B 75 08 85 F6 74 75 83 3D ?? ?? ?? ?? ?? 75 43 6A 04 E8 FF 19 00 00 59 83 65 FC 00 56 E8 84 3C 00 00 59 89 45 E4 85 C0 74 09 56 50 E8 A0 3C 00 00 59 59 C7 45 FC FE FF FF FF E8 0B 00 00 00 83 7D E4 00 75 37 FF 75 08 EB 0A 6A 04 E8 ED 18 00 00 59 C3 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_540_542 {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "5.40 - 5.42"
		pattern = "E8933E0000E916FEFFFF6A0C68????????E8B41F00008B4D0833FF3BCF762E6AE05833D2F7F13B450C1BC040751FE8AF1D0000C7000C0000005757575757E8401D000083C41433C0E9D50000000FAF4D0C8BF18975083BF7750333F64633DB895DE483FEE07769833D??????????754B83C60F83E6F089750C8B45083B05????????77376A04E8C11B000059897DFCFF7508E8B1460000598945E4C745FCFEFFFFFFE85F0000008B5DE43BDF7411FF75085753E886D3FFFF83C40C3BDF7561566A08FF35????????FF15????????8BD83BDF754C393D????????743356E8C4FAFFFF5985C00F8572FFFFFF8B45103BC70F8450FFFFFFC7000C000000E945FFFFFF33FF8B750C6A04E8671A000059C3"
	strings:
		$1 = { E8 93 3E 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 B4 1F 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 AF 1D 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 40 1D 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? ?? 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 C1 1B 00 00 59 89 7D FC FF 75 08 E8 B1 46 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 86 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 C4 FA FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 67 1A 00 00 59 C3 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_6xx {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "6.xx"
		comment = "Silicon Realms Toolworks * Sign.By.fly * 20081227"
		pattern = "00000000000000000000000020000060????????????????????????????????00D00000????????00000000000000000000000020000060????????????????????????????????00600100????????000000000000000000000000400000C0????????????????????????????????00800000????????00000000000000000000000040000042????????????????????????????????????????????????000000000000000000000000400000C0"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 D0 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 60 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 80 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 }
	condition:
		$1 at pe.entry_point
}

rule armadillo_6xx_minimu_protection {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "6.xx Minimum Protection"
		pattern = "E8????????E9????????6A0C68????????E8????????8365E4008B75083B35????????77226A04E8????????598365FC0056E8????????598945E4C745FCFEFF"
	strings:
		$1 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 65 E4 00 8B 75 08 3B 35 ?? ?? ?? ?? 77 22 6A 04 E8 ?? ?? ?? ?? 59 83 65 FC 00 56 E8 ?? ?? ?? ?? 59 89 45 E4 C7 45 FC FE FF }
	condition:
		$1 at pe.entry_point
}

rule ascrypt_01_01 {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "80??????83????????90909051??????0100000083????E2"
	strings:
		$1 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 51 ?? ?? ?? 01 00 00 00 83 ?? ?? E2 }
	condition:
		$1 at pe.entry_point
}

rule ascrypt_01_02 {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "80??????83????????90909083????E2"
	strings:
		$1 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 83 ?? ?? E2 }
	condition:
		$1 at pe.entry_point
}

rule ascrypt_01_03 {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "80??????83????????909090E2"
	strings:
		$1 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 E2 }
	condition:
		$1 at pe.entry_point
}

rule ascrypt_01_04 {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "81????????????83??????????????83????E2??EB"
	strings:
		$1 = { 81 ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? ?? 83 ?? ?? E2 ?? EB }
	condition:
		$1 at pe.entry_point
}

rule ascrypt_01_05 {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "83????E2????E2??FF"
	strings:
		$1 = { 83 ?? ?? E2 ?? ?? E2 ?? FF }
	condition:
		$1 at pe.entry_point
}

rule ascrypt_01_06 {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "B9????????81????????????83042404??90909083E903E2ECEB??00000000000000000000"
	strings:
		$1 = { B9 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? ?? 83 04 24 04 ?? 90 90 90 83 E9 03 E2 EC EB ?? 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule asdpack_uv {
	meta:
		tool = "P"
		name = "ASDPack"
		pattern = "00000000????????0000000000000000????????????????0000000000000000000000000000000000000000????????000000004B65726E656C33322E646C6C008D49001F014765744D6F64756C6548616E646C65410090"
	strings:
		$1 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8D 49 00 1F 01 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 90 }
	condition:
		$1 at pe.entry_point
}

rule asdpack_10 {
	meta:
		tool = "P"
		name = "ASDPack"
		version = "1.0"
		pattern = "558BEC5653E85C01000000000000000000000000000000100000??????00000000000000400000????000000000000000000??????00000000000000000000000000??????00000000000000000000????000010000000??000000????0000????0000????0000??000000????0000??000000????0000??000000????00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005B81EBE61D4000837D0C01751155E84F010000E86A0100005DE82C0000008BB31A1E400003B3FA1D40008B760CAD0BC0740DFF7510FF750CFF7508FFD0EBEEB8010000005B5EC9C20C00556A00FF93202140008983FA1D40006A406800100000FFB3021E40006A00FF932C2140008983061E40008B83F21D40000383FA1D400050FFB3061E400050E86D0100005F"
	strings:
		$1 = { 55 8B EC 56 53 E8 5C 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 ?? ?? ?? 00 00 00 00 00 00 00 40 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 10 00 00 00 ?? 00 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5B 81 EB E6 1D 40 00 83 7D 0C 01 75 11 55 E8 4F 01 00 00 E8 6A 01 00 00 5D E8 2C 00 00 00 8B B3 1A 1E 40 00 03 B3 FA 1D 40 00 8B 76 0C AD 0B C0 74 0D FF 75 10 FF 75 0C FF 75 08 FF D0 EB EE B8 01 00 00 00 5B 5E C9 C2 0C 00 55 6A 00 FF 93 20 21 40 00 89 83 FA 1D 40 00 6A 40 68 00 10 00 00 FF B3 02 1E 40 00 6A 00 FF 93 2C 21 40 00 89 83 06 1E 40 00 8B 83 F2 1D 40 00 03 83 FA 1D 40 00 50 FF B3 06 1E 40 00 50 E8 6D 01 00 00 5F }
	condition:
		$1 at pe.entry_point
}

rule asdpack_20_01 {
	meta:
		tool = "P"
		name = "ASDPack"
		version = "2.0"
		pattern = "5B43837B74000F8408000000894314E9"
	strings:
		$1 = { 5B 43 83 7B 74 00 0F 84 08 00 00 00 89 43 14 E9 }
	condition:
		$1 at pe.entry_point
}

rule asdpack_20_02 {
	meta:
		tool = "P"
		name = "ASDPack"
		version = "2.0"
		pattern = "8B442404565753E8CD010000C30000000000000000000000000010000000"
	strings:
		$1 = { 8B 44 24 04 56 57 53 E8 CD 01 00 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule aspack_uv_01 {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "5D81ED??????00BB??????0003DD2B9D??????0083BD??????0000899D??????000F85????00008D85??????0050FF95??????008985"
	strings:
		$1 = { 5D 81 ED ?? ?? ?? 00 BB ?? ?? ?? 00 03 DD 2B 9D ?? ?? ?? 00 83 BD ?? ?? ?? 00 00 89 9D ?? ?? ?? 00 0F 85 ?? ?? 00 00 8D 85 ?? ?? ?? 00 50 FF 95 ?? ?? ?? 00 89 85 }
	condition:
		$1 in (pe.entry_point + 6 .. pe.entry_point + 7)
}

rule aspack_uv_02 {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8??????00E9????????????008BFEB997000000AD3578563412AB4975F6EB"
	strings:
		$1 = { 60 E8 ?? ?? ?? 00 E9 ?? ?? ?? ?? ?? ?? 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB }
	condition:
		$1 at pe.entry_point
}

rule aspack_uv_03 {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8??????00EB3387DB90"
	strings:
		$1 = { 60 E8 ?? ?? ?? 00 EB 33 87 DB 90 }
	condition:
		$1 at pe.entry_point
}

rule aspack_uv_04 {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8??????00EB4?0000000000000000"
	strings:
		$1 = { 60 E8 ?? ?? ?? 00 EB 4? 00 00 00 00 00 00 00 00 }
	condition:
		$1 in (pe.entry_point .. pe.entry_point + 1)
}

rule aspack_uv_05 {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8????0000EB095D5581ED39394400C3E9????0000"
	strings:
		$1 = { 60 E8 ?? ?? 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 ?? ?? 00 00 }
	condition:
		$1 at pe.entry_point
}

rule aspack_uv_06 {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8000000005D81ED??????00B8??????0003C52B85??????008985??????0080BD??????00007515FE85??????00E81D000000E8????0000E8????00008B85"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? 00 B8 ?? ?? ?? 00 03 C5 2B 85 ?? ?? ?? 00 89 85 ?? ?? ?? 00 80 BD ?? ?? ?? 00 00 75 15 FE 85 ?? ?? ?? 00 E8 1D 00 00 00 E8 ?? ?? 00 00 E8 ?? ?? 00 00 8B 85 }
	condition:
		$1 at pe.entry_point
}

rule aspack_uv_07 {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8000000005D81ED76AA4400BB70AA440003DD2B9DE1B2440083BDDCB2440000899DEDB0"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 76 AA 44 00 BB 70 AA 44 00 03 DD 2B 9D E1 B2 44 00 83 BD DC B2 44 00 00 89 9D ED B0 }
	condition:
		$1 at pe.entry_point
}

rule aspack_uv_08 {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E93D040000"
	strings:
		$1 = { 60 E9 3D 04 00 00 }
	condition:
		$1 at pe.entry_point
}

rule aspack_100b {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.00b"
		pattern = "60E8????????5D81ED921A44??B88C1A44??03C52B85CD1D44??8985D91D44??80BDC41D44"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }
	condition:
		$1 at pe.entry_point
}

rule aspack_101b {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.01b"
		pattern = "60E8????????5D81EDD22A44??B8CC2A44??03C52B85A52E44??8985B12E44??80BD9C2E44"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }
	condition:
		$1 at pe.entry_point
}

rule aspack_102b {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.02a"
		pattern = "60E8????????5D81ED3ED943??B838??????03C52B850BDE43??898517DE43??80BD01DE43????7515FE8501DE43??E81D??????E87902????E81203????8B8503DE43??038517DE43??8944241C61FF"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 3E D9 43 ?? B8 38 ?? ?? ?? 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 ?? ?? 75 15 FE 85 01 DE 43 ?? E8 1D ?? ?? ?? E8 79 02 ?? ?? E8 12 03 ?? ?? 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }
	condition:
		$1 at pe.entry_point
}

rule aspack_102b_01 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.02b"
		pattern = "60E8????????5D81ED967843??B8907843??03C52B857D7C43??8985897C43??80BD747C43"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }
	condition:
		$1 at pe.entry_point
}

rule aspack_102b_02 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.02b"
		pattern = "60E8000000005D81ED96784300B89078430003C5"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }
	condition:
		$1 at pe.entry_point
}

rule aspack_103b {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.03b"
		pattern = "60E8????????5D81EDAE9843??B8A89843??03C52B85189D43??8985249D43??80BD0E9D43"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }
	condition:
		$1 at pe.entry_point
}

rule aspack_104b {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.04b"
		pattern = "60E8????????5D81ED????????B8????????03C52B85??129D??89851E9D????80BD089D"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? ?? 80 BD 08 9D }
	condition:
		$1 at pe.entry_point
}

rule aspack_105b_01 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.05b"
		pattern = "7500E9"
	strings:
		$1 = { 75 00 E9 }
	condition:
		$1 at pe.entry_point
}

rule aspack_105b_02 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.05b"
		pattern = "60E8????????5D81EDCE3A44??B8C83A44??03C52B85B53E44??8985C13E44??80BDAC3E44"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }
	condition:
		$1 at pe.entry_point
}

rule aspack_106b_01 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.06b"
		pattern = "60E8????????5D81EDEAA843??B8E4A843??03C52B8578AD43??898584AD43??80BD6EAD43"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }
	condition:
		$1 at pe.entry_point
}

rule aspack_106b_02 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.06b"
		pattern = "9090907500E9"
	strings:
		$1 = { 90 90 90 75 00 E9 }
	condition:
		$1 at pe.entry_point
}

rule aspack_107b_01 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.07b"
		pattern = "60E8000000005D????????????B8????????03C5"
	strings:
		$1 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }
	condition:
		$1 at pe.entry_point
}

rule aspack_107b_02 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.07b"
		pattern = "60E8????????5D81ED????????B8????????03C52B85??0BDE??898517DE????80BD01DE"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE ?? ?? 80 BD 01 DE }
	condition:
		$1 at pe.entry_point
}

rule aspack_108_01 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08"
		pattern = "909090750190E9"
	strings:
		$1 = { 90 90 90 75 01 90 E9 }
	condition:
		$1 at pe.entry_point
}

rule aspack_108_02 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08"
		pattern = "9090907501FFE9"
	strings:
		$1 = { 90 90 90 75 01 FF E9 }
	condition:
		$1 at pe.entry_point
}

rule aspack_10801_10802 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08.01 - 1.08.02"
		pattern = "60EB0A5DEB02FF2545FFE5E8E9E8F1FFFFFFE981??????44??BB10??44??03DD2B9D"
	strings:
		$1 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D }
	condition:
		$1 at pe.entry_point
}

rule aspack_10803 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08.03"
		pattern = "60E8000000005D????????????BB????????03DD2B9DB150440083BDAC50440000899DBB4E"
	strings:
		$1 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }
	condition:
		$1 at pe.entry_point
}

rule aspack_10804 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08.04"
		pattern = "60E841060000EB41"
	strings:
		$1 = { 60 E8 41 06 00 00 EB 41 }
	condition:
		$1 at pe.entry_point
}

rule aspack_1080x {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.08.x"
		pattern = "60EB035DFFE5E8F8FFFFFF81ED1B6A4400BB106A440003DD2B9D2A"
	strings:
		$1 = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A }
	condition:
		$1 at pe.entry_point
}

rule aspack_2000 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.000"
		pattern = "60E870050000EB4C"
	strings:
		$1 = { 60 E8 70 05 00 00 EB 4C }
	condition:
		$1 at pe.entry_point
}

rule aspack_2001 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.001"
		pattern = "60E872050000EB4C"
	strings:
		$1 = { 60 E8 72 05 00 00 EB 4C }
	condition:
		$1 at pe.entry_point
}

rule aspack_21 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.1"
		pattern = "60E872050000EB3387DB9000"
	strings:
		$1 = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }
	condition:
		$1 at pe.entry_point
}

rule aspack_211b {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.11b"
		pattern = "60E802000000EB095D5581ED39394400C3E93D040000"
	strings:
		$1 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00 }
	condition:
		$1 at pe.entry_point
}

rule aspack_211c {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.11c"
		pattern = "60E802000000EB095D5581ED39394400C3E959040000"
	strings:
		$1 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }
	condition:
		$1 at pe.entry_point
}

rule aspack_211d {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.11d"
		pattern = "60E802000000EB095D5581ED39394400C36?"
	strings:
		$1 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 6? }
	condition:
		$1 at pe.entry_point
}

rule aspack_asprotect_2xx {
	meta:
		tool = "P"
		name = "ASPack or ASProtect"
		version = "2.xx"
		pattern = "60E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB"
	strings:
		$1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }
	condition:
		$1 at pe.entry_point
}

rule aspack_2xx {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.xx"
		pattern = "A803????617508B801??????C20C??68????????C38B852604????8D8D3B04????5150FF95"
	strings:
		$1 = { A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95 }
	condition:
		$1 at pe.entry_point
}

rule aspack_212 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.12"
		pattern = "60E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00?0??0083BD2204000000899D220400000F85650300008D852E04000050FF954D0F00008985260400008BF88D5D5E5350FF95490F000089854D0500008D5D6B5357FF95490F00"
	strings:
		$1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?0 ?? 00 83 BD 22 04 00 00 00 89 9D 22 04 00 00 0F 85 65 03 00 00 8D 85 2E 04 00 00 50 FF 95 4D 0F 00 00 89 85 26 04 00 00 8B F8 8D 5D 5E 53 50 FF 95 49 0F 00 00 89 85 4D 05 00 00 8D 5D 6B 53 57 FF 95 49 0F 00 }
	condition:
		$1 at pe.entry_point
}

rule aspack_220 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.20"
		pattern = "60E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00?0??0083BD7D04000000899D7D0400000F85C00300008D858904000050FF95090F00008985810400008BF08D7D515756FF95050F0000ABB000AE75FD380775EE8D457AFFE056"
	strings:
		$1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?0 ?? 00 83 BD 7D 04 00 00 00 89 9D 7D 04 00 00 0F 85 C0 03 00 00 8D 85 89 04 00 00 50 FF 95 09 0F 00 00 89 85 81 04 00 00 8B F0 8D 7D 51 57 56 FF 95 05 0F 00 00 AB B0 00 AE 75 FD 38 07 75 EE 8D 45 7A FF E0 56 }
	condition:
		$1 at pe.entry_point
}

rule aspack_224_228 {
	meta:
		tool = "P"
		name = "ASPack"
		version = "2.24, 2.28"
		pattern = "60E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00?0??0083BD8804000000899D880400000F85CB0300008D859404000050FF95A90F000089858C0400008BF08D7D515756FF95A50F0000ABB000AE75FD380775EE8D457AFFE056"
	strings:
		$1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?0 ?? 00 83 BD 88 04 00 00 00 89 9D 88 04 00 00 0F 85 CB 03 00 00 8D 85 94 04 00 00 50 FF 95 A9 0F 00 00 89 85 8C 04 00 00 8B F0 8D 7D 51 57 56 FF 95 A5 0F 00 00 AB B0 00 AE 75 FD 38 07 75 EE 8D 45 7A FF E0 56 }
	condition:
		$1 at pe.entry_point
}

rule aspack_asprotect_uv_01 {
	meta:
		tool = "P"
		name = "ASPack-ASPROTECT"
		pattern = "60E9D5040000F7100F0F0F9F6C90FCDB8C540FCACF8C540F12EC3AAC2795540F92CC0F94540F0F98AC0F94540F1E9458120F0FD694D28C540F0F0F0F0F9C9417"
	strings:
		$1 = { 60 E9 D5 04 00 00 F7 10 0F 0F 0F 9F 6C 90 FC DB 8C 54 0F CA CF 8C 54 0F 12 EC 3A AC 27 95 54 0F 92 CC 0F 94 54 0F 0F 98 AC 0F 94 54 0F 1E 94 58 12 0F 0F D6 94 D2 8C 54 0F 0F 0F 0F 0F 9C 94 17 }
	condition:
		$1 at pe.entry_point
}

rule aspack_asprotect_uv_02 {
	meta:
		tool = "P"
		name = "ASPack-ASPROTECT"
		pattern = "60E9DB05000047605F5F5FEFBCE04CA715A45F1A9B15A45F623C8AFCE01DA45FE21CD71CA45F5FE8FCD71CA45F6EE4A8625F5F26E49E15A45F5F5F5F5FECE4DF"
	strings:
		$1 = { 60 E9 DB 05 00 00 47 60 5F 5F 5F EF BC E0 4C A7 15 A4 5F 1A 9B 15 A4 5F 62 3C 8A FC E0 1D A4 5F E2 1C D7 1C A4 5F 5F E8 FC D7 1C A4 5F 6E E4 A8 62 5F 5F 26 E4 9E 15 A4 5F 5F 5F 5F 5F EC E4 DF }
	condition:
		$1 at pe.entry_point
}

rule aspack_asprotect_uv_03 {
	meta:
		tool = "P"
		name = "ASPack-ASPROTECT"
		pattern = "60E9DC050000C19EB7BBD92C153DC6E56D01D957F4711E9DBA98043A397A1E9D3A79515AFDBBD925553496E2B7CA5EE6BABBD9633DFB8FE2B7BBD99CB7485E1D"
	strings:
		$1 = { 60 E9 DC 05 00 00 C1 9E B7 BB D9 2C 15 3D C6 E5 6D 01 D9 57 F4 71 1E 9D BA 98 04 3A 39 7A 1E 9D 3A 79 51 5A FD BB D9 25 55 34 96 E2 B7 CA 5E E6 BA BB D9 63 3D FB 8F E2 B7 BB D9 9C B7 48 5E 1D }
	condition:
		$1 at pe.entry_point
}

rule aspack_asprotect_uv_04 {
	meta:
		tool = "P"
		name = "ASPack-ASPROTECT"
		pattern = "60E9F305000067A022E78F317F6662E994A28F1A1E51CAA1213AA43CA359CAA1A15AF71C67E78F28BF9F32E422E80AE821E78F66A7D839E422E78FA1226A0A21"
	strings:
		$1 = { 60 E9 F3 05 00 00 67 A0 22 E7 8F 31 7F 66 62 E9 94 A2 8F 1A 1E 51 CA A1 21 3A A4 3C A3 59 CA A1 A1 5A F7 1C 67 E7 8F 28 BF 9F 32 E4 22 E8 0A E8 21 E7 8F 66 A7 D8 39 E4 22 E7 8F A1 22 6A 0A 21 }
	condition:
		$1 at pe.entry_point
}
rule aspack_asprotect_uv_05 {
	meta:
		tool = "P"
		name = "ASPack-ASPROTECT"
		pattern = "E801000000EB5DBB??FFFFFF03DD81EB008A0F00EB02EB39C645100033C08B733CFF7433580FB75433064A4A8DBC33F80000008B770C8B4F100BC9740703F3"
	strings:
		$1 = { E8 01 00 00 00 EB 5D BB ?? FF FF FF 03 DD 81 EB 00 8A 0F 00 EB 02 EB 39 C6 45 10 00 33 C0 8B 73 3C FF 74 33 58 0F B7 54 33 06 4A 4A 8D BC 33 F8 00 00 00 8B 77 0C 8B 4F 10 0B C9 74 07 03 F3 }
	condition:
		$1 in (pe.entry_point .. pe.entry_point + 1)
}

rule aspr_stripper_2x {
	meta:
		tool = "P"
		name = "ASPR Stripper"
		version = "2.x"
		pattern = "BB????????E9????????609CFCBF????????B9????????F3AA9D61C3558BEC"
	strings:
		$1 = { BB ?? ?? ?? ?? E9 ?? ?? ?? ?? 60 9C FC BF ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 AA 9D 61 C3 55 8B EC }
	condition:
		$1 at pe.entry_point
}

rule asprotect_ske_21_22_21x {
	meta:
		tool = "P"
		name = "ASProtect SKE"
		version = "2.1, 2.2, 2.1x"
		pattern = "9060E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00??????807D4D01750C8B74242883FE01895D4E75318D45535053FFB5ED0900008D453550E98200000000000000000000000000000000"
	strings:
		$1 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule asprotect_uv_01 {
	meta:
		tool = "P"
		name = "ASProtect"
		pattern = "????????????????????????????????????????????????????????????????????????????????????????????????????????2B95CD3C400081EA2C00000080BD083D40000074188B85ED3C40000385F73C40003B??7401"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2B 95 CD 3C 40 00 81 EA 2C 00 00 00 80 BD 08 3D 40 00 00 74 18 8B 85 ED 3C 40 00 03 85 F7 3C 40 00 3B ?? 74 01 }
	condition:
		$1 at pe.entry_point
}

rule asprotect_uv_02 {
	meta:
		tool = "P"
		name = "ASProtect"
		pattern = "60??????????905D??????????????????????03DD"
	strings:
		$1 = { 60 ?? ?? ?? ?? ?? 90 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 DD }
	condition:
		$1 at pe.entry_point
}

rule asprotect_uv_03 {
	meta:
		tool = "P"
		name = "ASProtect"
		pattern = "68????????E8????0000C3C3"
	strings:
		$1 = { 68 ?? ?? ?? ?? E8 ?? ?? 00 00 C3 C3 }
	condition:
		$1 at pe.entry_point
}

rule asprotect_uv_04 {
	meta:
		tool = "P"
		name = "ASProtect"
		pattern = "9060E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00????00807D4D01750C8B74242883FE01895D4E75318D45535053FFB5DD0900008D453550E98200000000000000000000000000000000"
	strings:
		$1 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule asprotect_10 {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.0"
		pattern = "60E801??????905D81ED????????BB????????03DD2B9D"
	strings:
		$1 = { 60 E8 01 ?? ?? ?? 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }
	condition:
		$1 at pe.entry_point
}

rule asprotect_11_brs {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.1 BRS"
		pattern = "60E9??05"
	strings:
		$1 = { 60 E9 ?? 05 }
	condition:
		$1 at pe.entry_point
}

rule asprotect_11_mte {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.1 MTE"
		pattern = "60E9????????9178797979E9"
	strings:
		$1 = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }
	condition:
		$1 at pe.entry_point
}

rule asprotect_11b {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.1b"
		pattern = "9060E9??04"
	strings:
		$1 = { 90 60 E9 ?? 04 }
	condition:
		$1 at pe.entry_point
}

rule asprotect_11c {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.1c"
		pattern = "9060E81B??????E9FC"
	strings:
		$1 = { 90 60 E8 1B ?? ?? ?? E9 FC }
	condition:
		$1 at pe.entry_point
}

rule asprotect_11 {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.1"
		pattern = "60E9??04????E9??????????????EE"
	strings:
		$1 = { 60 E9 ?? 04 ?? ?? E9 ?? ?? ?? ?? ?? ?? ?? EE }
	condition:
		$1 at pe.entry_point
}

rule asprotect_12_21 {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.2 - 2.1"
		pattern = "6801??????E801??????C3C3"
	strings:
		$1 = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3 }
	condition:
		$1 at pe.entry_point
}

rule asprotect_12_01 {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.2"
		pattern = "6801??????C3"
	strings:
		$1 = { 68 01 ?? ?? ?? C3 }
	condition:
		$1 at pe.entry_point
}

rule asprotect_12_02 {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.2"
		pattern = "9060E81B000000E9FC8DB50F0600008BFEB997000000AD3578563412AB4975F6EB045D4555C3E9??????00"
	strings:
		$1 = { 90 60 E8 1B 00 00 00 E9 FC 8D B5 0F 06 00 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB 04 5D 45 55 C3 E9 ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule asprotect_123_rc4_01 {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.23 RC4"
		pattern = "60E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB00??????807D4D01750C8B74242883FE01895D4E75318D45535053FFB5D50900008D453550E9820000000000000000000000000000000000"
	strings:
		$1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule asprotect_123_rc4_02 {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.23 RC4"
		pattern = "9060E803000000E9EB045D4555C3E801000000EB5DBBEDFFFFFF03DD81EB????????807D4D01750C8B74242883FE01895D4E75318D45535053FFB5D50900008D453550E9820000000000000000000000000000000000000000000000000000000000000000B8F8C0A523505003454E5B85C0741CEB01E881FBF8C0A523743533D2566A0056FF754EFFD05E83FE00752433D28B454185C074075252FF7535FFD08B453585C0740D"
	strings:
		$1 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 B8 F8 C0 A5 23 50 50 03 45 4E 5B 85 C0 74 1C EB 01 E8 81 FB F8 C0 A5 23 74 35 33 D2 56 6A 00 56 FF 75 4E FF D0 5E 83 FE 00 75 24 33 D2 8B 45 41 85 C0 74 07 52 52 FF 75 35 FF D0 8B 45 35 85 C0 74 0D }
	condition:
		$1 at pe.entry_point
}

rule asprotect_12x {
	meta:
		tool = "P"
		name = "ASProtect"
		version = "1.2x"
		pattern = "00006801??????C3AA"
	strings:
		$1 = { 00 00 68 01 ?? ?? ?? C3 AA }
	condition:
		$1 at pe.entry_point
}

rule ass_crypter {
	meta:
		tool = "P"
		name = "ass - crypter"
		pattern = "558BEC83C4EC53????????8945ECB898400010E8ACEAFFFF33C055687851001064????????206A0A6888510010A1E097001050E8D8EAFFFF8BD853A1E097001050E812EBFFFF8BF853A1E097001050E8DCEAFFFF8BD853E8DCEAFFFF8BF085F674268BD74AB8F0970010E8C9E7FFFFB8F0970010E8B7E7FFFF8BCF8BD6E8EEEAFFFF53E898EAFFFF8D4DECBA9C510010A1F0970010E822EBFFFF8B55ECB8F0970010E889E6FFFFB8F0970010E87FE7FFFFE86EECFFFF33C05A5959648910687F5100108D45ECE811E6FFFFC3E9FFDFFFFFEBF05F5E5BE80DE5FFFF0053455454494E475300000000FFFFFFFF1C000000454E54455220594F5552204F574E2050415353574F52442048455245"
	strings:
		$1 = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 98 40 00 10 E8 AC EA FF FF 33 C0 55 68 78 51 00 10 64 ?? ?? ?? ?? 20 6A 0A 68 88 51 00 10 A1 E0 97 00 10 50 E8 D8 EA FF FF 8B D8 53 A1 E0 97 00 10 50 E8 12 EB FF FF 8B F8 53 A1 E0 97 00 10 50 E8 DC EA FF FF 8B D8 53 E8 DC EA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 F0 97 00 10 E8 C9 E7 FF FF B8 F0 97 00 10 E8 B7 E7 FF FF 8B CF 8B D6 E8 EE EA FF FF 53 E8 98 EA FF FF 8D 4D EC BA 9C 51 00 10 A1 F0 97 00 10 E8 22 EB FF FF 8B 55 EC B8 F0 97 00 10 E8 89 E6 FF FF B8 F0 97 00 10 E8 7F E7 FF FF E8 6E EC FF FF 33 C0 5A 59 59 64 89 10 68 7F 51 00 10 8D 45 EC E8 11 E6 FF FF C3 E9 FF DF FF FF EB F0 5F 5E 5B E8 0D E5 FF FF 00 53 45 54 54 49 4E 47 53 00 00 00 00 FF FF FF FF 1C 00 00 00 45 4E 54 45 52 20 59 4F 55 52 20 4F 57 4E 20 50 41 53 53 57 4F 52 44 20 48 45 52 45 }
	condition:
		$1 at pe.entry_point
}

rule avercryptor_10 {
	meta:
		tool = "P"
		name = "AverCryptor"
		version = "1.0"
		pattern = "60E8000000005D81ED751740008BBD9C1840008B8DA4184000B8BC18400003C580300583F9007471817F1CAB00000075628B570C0395A018400033C05133C966B9FA006683F90074498B570C0395A01840008B85A818400083F802750681C200020000518B4F1083F802750681E90002000057BFC80000008BF1E8270000008BC85FB8BC18400003C5E8240000005949EBB15983C72849EB8A8B85981840008944241C61FFE056574FF7D723F78BC65F5EC3"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 75 17 40 00 8B BD 9C 18 40 00 8B 8D A4 18 40 00 B8 BC 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 A0 18 40 00 33 C0 51 33 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 A0 18 40 00 8B 85 A8 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 BC 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 98 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }
	condition:
		$1 at pe.entry_point
}

rule avercryptor_102b {
	meta:
		tool = "P"
		name = "AverCryptor"
		version = "1.02b"
		pattern = "60E8000000005D81ED0C1740008BBD331840008B8D3B184000B85118400003C580300583F9007471817F1CAB00000075628B570C03953718400033C05133C966B9F7006683F90074498B570C0395371840008B853F18400083F802750681C200020000518B4F1083F802750681E90002000057BFC80000008BF1E8270000008BC85FB85118400003C5E8240000005949EBB15983C72849EB8A8B852F1840008944241C61FFE056574FF7D723F78BC65F5EC3"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 0C 17 40 00 8B BD 33 18 40 00 8B 8D 3B 18 40 00 B8 51 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 37 18 40 00 33 C0 51 33 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 37 18 40 00 8B 85 3F 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 51 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 2F 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }
	condition:
		$1 at pe.entry_point
}

rule azpprotect_0001_01 {
	meta:
		tool = "P"
		name = "AZProtect"
		version = "0001"

		pattern = "EB70FC608C804D110070258100400D91BB608C804D11007021811D610D810040CE608C804D11007025812581258125812961418131611D610040B73000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060BE00????00BF00004000EB174B45524E454C33322E444C4C0000000000FF25??????008BC603C78BF857558BEC057F00000050E8E5FFFFFFBA8C????008902E91A010000??0000004765744D6F64756C6546696C654E616D654100476574566F6C756D65496E666F726D6174696F6E41004D657373616765426F7841004578697450726F63657373004765744D6F64756C6548616E646C6541"
	strings:
		$1 = { EB 70 FC 60 8C 80 4D 11 00 70 25 81 00 40 0D 91 BB 60 8C 80 4D 11 00 70 21 81 1D 61 0D 81 00 40 CE 60 8C 80 4D 11 00 70 25 81 25 81 25 81 25 81 29 61 41 81 31 61 1D 61 00 40 B7 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 60 BE 00 ?? ?? 00 BF 00 00 40 00 EB 17 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 FF 25 ?? ?? ?? 00 8B C6 03 C7 8B F8 57 55 8B EC 05 7F 00 00 00 50 E8 E5 FF FF FF BA 8C ?? ?? 00 89 02 E9 1A 01 00 00 ?? 00 00 00 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 47 65 74 56 6F 6C 75 6D 65 49 6E 66 6F 72 6D 61 74 69 6F 6E 41 00 4D 65 73 73 61 67 65 42 6F 78 41 00 45 78 69 74 50 72 6F 63 65 73 73 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 }
	condition:
		$1 at pe.entry_point
}

rule azpprotect_0001_02 {
	meta:
		tool = "P"
		name = "AZProtect"
		version = "0001"
		pattern = "FC33C9498BD133C033DBAC32C18ACD8AEA8AD6B60866D1EB66D1D87309663520836681F3B8EDFECE75EB33C833D34F75D5F7D2F7D18BC2C1C010668BC1C3F0DA558BEC535633C933DB8B4D0C8B55108B75084E4A83FB08720533DB43EB014333C08A04318A24132AC4880431E2E65E5BC9C20C"
	strings:
		$1 = { FC 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 8B C2 C1 C0 10 66 8B C1 C3 F0 DA 55 8B EC 53 56 33 C9 33 DB 8B 4D 0C 8B 55 10 8B 75 08 4E 4A 83 FB 08 72 05 33 DB 43 EB 01 43 33 C0 8A 04 31 8A 24 13 2A C4 88 04 31 E2 E6 5E 5B C9 C2 0C }
	condition:
		$1 at pe.entry_point
}

rule bambam_001 {
	meta:
		tool = "P"
		name = "BamBam"
		version = "0.01"
		pattern = "6A14E89A0500008BD85368FB??????E86CFDFFFFB9050000008BF3BFFB??????53F3A5E88D0500008B3D03??????A1????????668B15????????B9????????2BCF8945E8890D????????668955EC8B413C33D203C1"
	strings:
		$1 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 FB ?? ?? ?? E8 6C FD FF FF B9 05 00 00 00 8B F3 BF FB ?? ?? ?? 53 F3 A5 E8 8D 05 00 00 8B 3D 03 ?? ?? ?? A1 ?? ?? ?? ?? 66 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B CF 89 45 E8 89 0D ?? ?? ?? ?? 66 89 55 EC 8B 41 3C 33 D2 03 C1 }
	condition:
		$1 at pe.entry_point
}

rule bambvam_004 {
	meta:
		tool = "P"
		name = "BamBam"
		version = "0.04"
		pattern = "BF????????83C9FF33C068????????F2AEF7D1495168????????E8110A000083C40C68????????FF15????????8BF0BF????????83C9FF33C0F2AEF7D149BF????????8BD168????????C1E902F3AB8BCA83E103F3AABF????????83C9FF33C0F2AEF7D1495168????????E8C0090000"
	strings:
		$1 = { BF ?? ?? ?? ?? 83 C9 FF 33 C0 68 ?? ?? ?? ?? F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 11 0A 00 00 83 C4 0C 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F0 BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 BF ?? ?? ?? ?? 8B D1 68 ?? ?? ?? ?? C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 C0 09 00 00 }
	condition:
		$1 at pe.entry_point
}

rule beria_007 {
	meta:
		tool = "P"
		name = "Beria"
		version = "0.07 public WIP"
		pattern = "83EC18538B1D0030????555657683007000033ED55FFD38BF03BF5740D89AE20070000E8880F0000EB0233F66A105589353040????FFD38BF03BF57409892EE83CFEFFFFEB0233F66A18558935D843????FFD38BF03BF574378B460C3BC58B3D0430????892E896E04896E08740650FFD7896E0C8B46103BC5740650FFD7896E108B46143BC5740A50FFD7896E14EB0233F66A10558935A440????FFD38BF03BF57409E8081200"
	strings:
		$1 = { 83 EC 18 53 8B 1D 00 30 ?? ?? 55 56 57 68 30 07 00 00 33 ED 55 FF D3 8B F0 3B F5 74 0D 89 AE 20 07 00 00 E8 88 0F 00 00 EB 02 33 F6 6A 10 55 89 35 30 40 ?? ?? FF D3 8B F0 3B F5 74 09 89 2E E8 3C FE FF FF EB 02 33 F6 6A 18 55 89 35 D8 43 ?? ?? FF D3 8B F0 3B F5 74 37 8B 46 0C 3B C5 8B 3D 04 30 ?? ?? 89 2E 89 6E 04 89 6E 08 74 06 50 FF D7 89 6E 0C 8B 46 10 3B C5 74 06 50 FF D7 89 6E 10 8B 46 14 3B C5 74 0A 50 FF D7 89 6E 14 EB 02 33 F6 6A 10 55 89 35 A4 40 ?? ?? FF D3 8B F0 3B F5 74 09 E8 08 12 00 }
	condition:
		$1 at pe.entry_point
}

rule beroexepacker_100 {
	meta:
		tool = "P"
		name = "BeRoEXEPacker"
		version = "1.00"
		pattern = "BA????????8DB2????????8B46??85C0745103C28B7E??8B1E85DB75028BDF03DA03FA525750FF15????????5F5A85C0742F8BC88B0385C074220FBAF01F72048D44????5152575051FF15????????5F5A5985C0740BAB83C304EBD883C614EBAA61C3"
	strings:
		$1 = { BA ?? ?? ?? ?? 8D B2 ?? ?? ?? ?? 8B 46 ?? 85 C0 74 51 03 C2 8B 7E ?? 8B 1E 85 DB 75 02 8B DF 03 DA 03 FA 52 57 50 FF 15 ?? ?? ?? ?? 5F 5A 85 C0 74 2F 8B C8 8B 03 85 C0 74 22 0F BA F0 1F 72 04 8D 44 ?? ?? 51 52 57 50 51 FF 15 ?? ?? ?? ?? 5F 5A 59 85 C0 74 0B AB 83 C3 04 EB D8 83 C6 14 EB AA 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule beroexepacker_100_lzbrr_01 {
	meta:
		tool = "P"
		name = "BeRoEXEPacker"
		version = "1.00 [LZBRR]"
		pattern = "60BE????????BF????????FCB28033DBA4B302E8????????73F633C9E8????????731C33C0E8????????7323B30241B010"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10 }
	condition:
		$1 at pe.entry_point
}

rule beroexepacker_100_lzbrr_02 {
	meta:
		tool = "P"
		name = "BeRoEXEPacker"
		version = "1.00 [LZBRR]"
		pattern = "837C2408010F85????????60BE????????BF????????FCB28033DBA4B302E8????????73F633C9E8????????731C33C0E8????????7323B30241B010"
	strings:
		$1 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8 ?? ?? ?? ?? 73 F6 33 C9 E8 ?? ?? ?? ?? 73 1C 33 C0 E8 ?? ?? ?? ?? 73 23 B3 02 41 B0 10 }
	condition:
		$1 at pe.entry_point
}

rule beroexepacker_100_lzbrs_01 {
	meta:
		tool = "P"
		name = "BeRoEXEPacker"
		version = "1.00 [LZBRS]"
		pattern = "60BE????????BF????????FCAD8D1C07B0803BFB733BE8????????7203A4EBF2E8????????8D51FFE8????????568BF72BF2F3A45EEBDB02C07503AC12C0C333"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }
	condition:
		$1 at pe.entry_point
}

rule beroexepacker_100_lzbrs_02 {
	meta:
		tool = "P"
		name = "BeRoEXEPacker"
		version = "1.00 [LZBRS]"
		pattern = "837C2408010F85????????60BE????????BF????????FCAD8D1C07B0803BFB733BE8????????7203A4EBF2E8????????8D51FFE8????????568BF72BF2F3A45EEBDB02C07503AC12C0C333"
	strings:
		$1 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 ?? ?? ?? ?? 72 03 A4 EB F2 E8 ?? ?? ?? ?? 8D 51 FF E8 ?? ?? ?? ?? 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }
	condition:
		$1 at pe.entry_point
}

rule beroexepacker_100_lzma_01 {
	meta:
		tool = "P"
		name = "BeRoEXEPacker"
		version = "1.00 [LZMA]"
		pattern = "6068????????68????????68????????E8????????BE????????B9040000008BF981FE????????7F10AC4704182C0273F0293E03F103F9EBE8"
	strings:
		$1 = { 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 04 00 00 00 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }
	condition:
		$1 at pe.entry_point
}

rule beroexepacker_100_lzma_02 {
	meta:
		tool = "P"
		name = "BeRoEXEPacker"
		version = "1.00 [LZMA] DLL"
		pattern = "837C2408010F85????????6068????????68????????68????????E8????????BE????????B9????????8BF981FE????????7F10AC4704182C0273F0293E03F103F9EBE8"
	strings:
		$1 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8B F9 81 FE ?? ?? ?? ?? 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }
	condition:
		$1 at pe.entry_point
}

rule bitarts {
	meta:
		tool = "P"
		name = "BITARTS"
		pattern = "55E8000000005D83ED068BC5556089AD????00002B85????00008985????000055BB????000003DD536467FF36000064678926000080BD????0000007509C685"
	strings:
		$1 = { 55 E8 00 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? 00 00 2B 85 ?? ?? 00 00 89 85 ?? ?? 00 00 55 BB ?? ?? 00 00 03 DD 53 64 67 FF 36 00 00 64 67 89 26 00 00 80 BD ?? ?? 00 00 00 75 09 C6 85 }
	condition:
		$1 at pe.entry_point
}

rule blackenergy_ddos_bot_crypter {
	meta:
		tool = "P"
		name = "BlackEnergy DDoS Bot Crypter"
		pattern = "55????81EC1C0100005356576A04BE0030000056FF35002011136A00E8??030000????83C410??FF897DF40F"
	strings:
		$1 = { 55 ?? ?? 81 EC 1C 01 00 00 53 56 57 6A 04 BE 00 30 00 00 56 FF 35 00 20 11 13 6A 00 E8 ?? 03 00 00 ?? ?? 83 C4 10 ?? FF 89 7D F4 0F }
	condition:
		$1 at pe.entry_point
}

rule blade_joiner_15 {
	meta:
		tool = "P"
		name = "Blade Joiner"
		version = "1.5"
		pattern = "558BEC81C4E4FEFFFF53565733C08945F08985"
	strings:
		$1 = { 55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89 85 }
	condition:
		$1 at pe.entry_point
}

rule berio_100b {
	meta:
		tool = "P"
		name = "Berio"
		version = "1.00b"
		pattern = "909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090E9011200"
	strings:
		$1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 01 12 00 }
	condition:
		$1 at pe.entry_point
}

rule berio200b {
	meta:
		tool = "P"
		name = "Berio"
		version = "2.00b"
		pattern = "909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090E9017401"
	strings:
		$1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 01 74 01 }
	condition:
		$1 at pe.entry_point
}

rule blindspot_10 {
	meta:
		tool = "P"
		name = "BlindSpot"
		version = "1.0"
		pattern = "558BEC81EC500200008D85B0FEFFFF5356A390124000578D85B0FDFFFF680001000033F65056FF15241040005668800000006A0356568D85B0FDFFFF680000008050FF152010400056566800080000508945FCFF151C1040008D45F88B1D1810400056506A34FF3590124000FF75FCFFD385C00F847F0100003975F80F8476010000A190124000668B4030663D010075148D85E4FEFFFF680401000050FF1514104000EB2C663D020075148D85E4FEFFFF506804010000FF1510104000EB128D85E4FEFFFF680401000050FF150C1040008B3D081040008D85E4FEFFFF685410400050"
	strings:
		$1 = { 55 8B EC 81 EC 50 02 00 00 8D 85 B0 FE FF FF 53 56 A3 90 12 40 00 57 8D 85 B0 FD FF FF 68 00 01 00 00 33 F6 50 56 FF 15 24 10 40 00 56 68 80 00 00 00 6A 03 56 56 8D 85 B0 FD FF FF 68 00 00 00 80 50 FF 15 20 10 40 00 56 56 68 00 08 00 00 50 89 45 FC FF 15 1C 10 40 00 8D 45 F8 8B 1D 18 10 40 00 56 50 6A 34 FF 35 90 12 40 00 FF 75 FC FF D3 85 C0 0F 84 7F 01 00 00 39 75 F8 0F 84 76 01 00 00 A1 90 12 40 00 66 8B 40 30 66 3D 01 00 75 14 8D 85 E4 FE FF FF 68 04 01 00 00 50 FF 15 14 10 40 00 EB 2C 66 3D 02 00 75 14 8D 85 E4 FE FF FF 50 68 04 01 00 00 FF 15 10 10 40 00 EB 12 8D 85 E4 FE FF FF 68 04 01 00 00 50 FF 15 0C 10 40 00 8B 3D 08 10 40 00 8D 85 E4 FE FF FF 68 54 10 40 00 50 }
	condition:
		$1 at pe.entry_point
}

rule bobpack_100 {
	meta:
		tool = "P"
		name = "BobPack"
		version = "1.00"
		pattern = "60E8000000008B0C2489CD83E90681ED????????E83D0000008985????????89C2B85D0A00008D0408E8E40000008B700401D6E876000000E851010000E80101"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED ?? ?? ?? ?? E8 3D 00 00 00 89 85 ?? ?? ?? ?? 89 C2 B8 5D 0A 00 00 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01 }
	condition:
		$1 at pe.entry_point
}

rule bobcrypt_10 {
	meta:
		tool = "P"
		name = "BopCrypt"
		version = "1.0"
		pattern = "60BD????????E8????0000"
	strings:
		$1 = { 60 BD ?? ?? ?? ?? E8 ?? ?? 00 00 }
	condition:
		$1 at pe.entry_point
}

rule borland_precompiled_header {
	meta:
		tool = "P"
		name = "Borland precompiled header file"
		pattern = "545053"
	strings:
		$1 = { 54 50 53 }
	condition:
		$1 at pe.entry_point
}

rule ci_crypt_01 {
	meta:
		tool = "P"
		name = "C.I Crypt"
		version = "0.1"
		pattern = "0000000000000000????????????????0000000000000000000000000000000000000000????????????????00000000????????????????000000006B65726E656C33322E646C6C000047657450726F634164647265737300004C6F61644C6962726172794100000000000000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule ci_crypt_02 {
	meta:
		tool = "P"
		name = "C.I Crypt"
		version = "0.2"
		pattern = "0000000000000000????????????????0000000000000000000000000000000000000000????????????????0000000000000000????????????????00000000000000006B65726E656C33322E646C6C000047657450726F634164647265737300004C6F61644C696272617279410000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule cd_cops_ii {
	meta:
		tool = "P"
		name = "CD-Cops"
		version = "II"
		pattern = "5360BD????????8D45??8D5D??E8????????8D"
	strings:
		$1 = { 53 60 BD ?? ?? ?? ?? 8D 45 ?? 8D 5D ?? E8 ?? ?? ?? ?? 8D }
	condition:
		$1 at pe.entry_point
}

rule cds_ss_10b1 {
	meta:
		tool = "P"
		name = "CDS SS"
		version = "1.0b1"
		pattern = "60E8000000005D81EDCA474000FF742420E8D30300000BC00F84130300008985B84E4000668CD8A804740CC7858C4E400001000000EB1264A1300000000FB640020AC00F85E80200008D85F64C400050FFB5B84E4000E8FC0300000BC00F84CE020000E81E0300008985904E40008D85034D400050FFB5B8"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED CA 47 40 00 FF 74 24 20 E8 D3 03 00 00 0B C0 0F 84 13 03 00 00 89 85 B8 4E 40 00 66 8C D8 A8 04 74 0C C7 85 8C 4E 40 00 01 00 00 00 EB 12 64 A1 30 00 00 00 0F B6 40 02 0A C0 0F 85 E8 02 00 00 8D 85 F6 4C 40 00 50 FF B5 B8 4E 40 00 E8 FC 03 00 00 0B C0 0F 84 CE 02 00 00 E8 1E 03 00 00 89 85 90 4E 40 00 8D 85 03 4D 40 00 50 FF B5 B8 }
	condition:
		$1 at pe.entry_point
}

rule celsius_crypt_21_01 {
	meta:
		tool = "P"
		name = "Celsius Crypt"
		version = "2.1"
		pattern = "5589E583EC08C7042401000000FF1584924400E8C8FEFFFF908DB426000000005589E583EC08C7042402000000FF1584924400E8A8FEFFFF908DB42600000000558B0DC492440089E55DFFE18D742600558B0DAC92440089E55DFFE1909090905589E55DE977C20000909090909090905589E583EC288B4510890424E83F140100488945FC8B450C488945F48D45F4894424048D45FC890424E812A303008B008945F88B45FC8945F0C645EF01C745E8000000008B45E83B45F87339807DEF0074338B45F0894424048B4510890424E81C1A010089C18B45088B55E801C20FB6013A020F94C08845EF8D45F0FF088D45E8FF00EBBF837DF0007434807DEF00742E8B45F0894424048B4510890424E8DD19010089C18B45088B55F801C20FB6013A020F94C08845EF8D45F0FF08EBC6C7442404000000008B4510890424E8AE19010089C18B45088B55F801C20FB6013A027F0C0FB645EF83E0018845E7EB04C645E7000FB645E78845EF0FB645EFC9C3"
	strings:
		$1 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 84 92 44 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 84 92 44 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D C4 92 44 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D AC 92 44 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 77 C2 00 00 90 90 90 90 90 90 90 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 1C 1A 01 00 89 C1 8B 45 08 8B 55 E8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 8D 45 E8 FF 00 EB BF 83 7D F0 00 74 34 80 7D EF 00 74 2E 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 DD 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 EB C6 C7 44 24 04 00 00 00 00 8B 45 10 89 04 24 E8 AE 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 7F 0C 0F B6 45 EF 83 E0 01 88 45 E7 EB 04 C6 45 E7 00 0F B6 45 E7 88 45 EF 0F B6 45 EF C9 C3 }
	condition:
		$1 at pe.entry_point
}

rule celsius_crypt_21_02 {
	meta:
		tool = "P"
		name = "Celsius Crypt"
		version = "2.1"
		pattern = "5589E583EC288B4510890424E83F140100488945FC8B450C488945F48D45F4894424048D45FC890424E812A303008B008945F88B45FC8945F0C645EF01C745E8000000008B45E83B45F87339807DEF0074338B45F0894424048B4510890424E81C1A010089C18B45088B55E801C20FB6013A020F94C08845EF8D45F0FF088D45E8FF00EBBF837DF0007434807DEF00742E8B45F0894424048B4510890424E8DD19010089C18B45088B55F801C20FB6013A020F94C08845EF8D45F0FF08EBC6C7442404000000008B4510890424E8AE19010089C18B45088B55F801C20FB6013A027F0C0FB645EF83E0018845E7EB04C645E7000FB645E78845EF0FB645EFC9C3"
	strings:
		$1 = { 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 1C 1A 01 00 89 C1 8B 45 08 8B 55 E8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 8D 45 E8 FF 00 EB BF 83 7D F0 00 74 34 80 7D EF 00 74 2E 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 DD 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 EB C6 C7 44 24 04 00 00 00 00 8B 45 10 89 04 24 E8 AE 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 7F 0C 0F B6 45 EF 83 E0 01 88 45 E7 EB 04 C6 45 E7 00 0F B6 45 E7 88 45 EF 0F B6 45 EF C9 C3 }
	condition:
		$1 at pe.entry_point
}

rule cexe_10a_10b {
	meta:
		tool = "P"
		name = "CExe"
		version = "1.0a, 1.0b"
		pattern = "558BEC81EC0C02????56BE0401????8D85F8FEFFFF56506A??FF15541040??8A8DF8FEFFFF33D284C98D85F8FEFFFF7416"
	strings:
		$1 = { 55 8B EC 81 EC 0C 02 ?? ?? 56 BE 04 01 ?? ?? 8D 85 F8 FE FF FF 56 50 6A ?? FF 15 54 10 40 ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16 }
	condition:
		$1 at pe.entry_point
}

rule checkprg {
	meta:
		tool = "P"
		name = "CHECKPRG"
		pattern = "33C0BE????8BD8B9????BF????BA????474A74"
	strings:
		$1 = { 33 C0 BE ?? ?? 8B D8 B9 ?? ?? BF ?? ?? BA ?? ?? 47 4A 74 }
	condition:
		$1 at pe.entry_point
}

rule chinaprotect {
	meta:
		tool = "P"
		name = "ChinaProtect"
		pattern = "C3E8????????B9????????E8????????FF30C3B9????????E8????????FF30C3B9????????E8????????FF30C3B9????????E8????????FF30C3568B??????6A4068001000008D????506A00E8????????893083C0045EC38B44????568D????6800400000FF3656E8????????68008000006A0056E8????????5EC3"
	strings:
		$1 = { C3 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 30 C3 56 8B ?? ?? ?? 6A 40 68 00 10 00 00 8D ?? ?? 50 6A 00 E8 ?? ?? ?? ?? 89 30 83 C0 04 5E C3 8B 44 ?? ?? 56 8D ?? ?? 68 00 40 00 00 FF 36 56 E8 ?? ?? ?? ?? 68 00 80 00 00 6A 00 56 E8 ?? ?? ?? ?? 5E C3 }
	condition:
		$1 at pe.entry_point
}

rule cicompress {
	meta:
		tool = "P"
		name = "CICompress"
		version = "1.0"
		pattern = "6A046800100000FF359C1440006A00FF1538104000A3FC10400097BE00204000E8710000003B059C14400075616A006A206A026A006A0368000000C06894104000FF152C104000A3F81040006A0068F4104000FF359C144000FF35FC104000FF35F8104000FF1534104000FF35F8104000FF15301040006800400000FF359C144000FF35FC104000FF153C1040006A00FF15281040006033DB33C9E87F000000730AB108E88200"
	strings:
		$1 = { 6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35 9C 14 40 00 FF 35 FC 10 40 00 FF 35 F8 10 40 00 FF 15 34 10 40 00 FF 35 F8 10 40 00 FF 15 30 10 40 00 68 00 40 00 00 FF 35 9C 14 40 00 FF 35 FC 10 40 00 FF 15 3C 10 40 00 6A 00 FF 15 28 10 40 00 60 33 DB 33 C9 E8 7F 00 00 00 73 0A B1 08 E8 82 00 }
	condition:
		$1 at pe.entry_point
}

rule code_virtualizer_1310 {
	meta:
		tool = "P"
		name = "Code Virtualizer"
		version = "1.3.1.0"
		pattern = "609CFCE8000000005F81EF????????8BC781C7????????3B472C7502EB2E89472CB9A7000000EB0501448F??490BC975F7837F400074158B774003F0EB098B1E03D8010383C604833E0075F28B7424248BDE03F0B90100000033C0F00FB14F3075F7AC"
	strings:
		$1 = { 60 9C FC E8 00 00 00 00 5F 81 EF ?? ?? ?? ?? 8B C7 81 C7 ?? ?? ?? ?? 3B 47 2C 75 02 EB 2E 89 47 2C B9 A7 00 00 00 EB 05 01 44 8F ?? 49 0B C9 75 F7 83 7F 40 00 74 15 8B 77 40 03 F0 EB 09 8B 1E 03 D8 01 03 83 C6 04 83 3E 00 75 F2 8B 74 24 24 8B DE 03 F0 B9 01 00 00 00 33 C0 F0 0F B1 4F 30 75 F7 AC }
	condition:
		$1 at pe.entry_point
}

rule codelock {
	meta:
		tool = "P"
		name = "Code-Lock"
		pattern = "434F44452D4C4F434B2E4F435800"
	strings:
		$1 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 }
	condition:
		$1 at pe.entry_point
}

rule codecrypt_014b {
	meta:
		tool = "P"
		name = "CodeCrypt"
		version = "0.14b"
		pattern = "E9C5020000EB02833D58EB02FF1D5BEB020FC75F"
	strings:
		$1 = { E9 C5 02 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }
	condition:
		$1 at pe.entry_point
}

rule codecrypt_015b {
	meta:
		tool = "P"
		name = "CodeCrypt"
		version = "0.15b"
		pattern = "E931030000EB02833D58EB02FF1D5BEB020FC75F"
	strings:
		$1 = { E9 31 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }
	condition:
		$1 at pe.entry_point
}

rule codecrypt_016_0164 {
	meta:
		tool = "P"
		name = "CodeCrypt"
		version = "0.16 - 0.164"
		pattern = "E92E030000EB02833D58EB02FF1D5BEB020FC75F"
	strings:
		$1 = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }
	condition:
		$1 at pe.entry_point
}

rule codecrypter_031 {
	meta:
		tool = "P"
		name = "codeCrypter"
		version = "0.31"
		pattern = "5058535B90BB??????00FFE390CCCCCC558BEC5DC3CCCCCCCCCCCCCCCCCCCCCC"
	strings:
		$1 = { 50 58 53 5B 90 BB ?? ?? ?? 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }
	condition:
		$1 at pe.entry_point
}

rule bitshape_pe_crypt_15 {
	meta:
		tool = "P"
		name = "BitShape PE Crypt"
		version = "1.5"
		pattern = "60E8000000005D81ED????????B97B0900008DBD????????8BF7AC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 7B 09 00 00 8D BD ?? ?? ?? ?? 8B F7 AC }
	condition:
		$1 at pe.entry_point
}

rule codesafe_20 {
	meta:
		tool = "P"
		name = "CodeSafe"
		version = "2.0"
		pattern = "?83EC10535657E8C40100?"
		start = 23
	strings:
		$1 = { ?8 3E C1 05 35 65 7E 8C 40 10 0? }
	condition:
		$1 at pe.entry_point + 23
}

rule codeveil_12_13 {
	meta:
		tool = "P"
		name = "CodeVeil"
		version = "1.2 - 1.3"
		pattern = "0000000000000000000000000000000000000000000000000000??????????????????????????8D642400558BEC5356578B4D108381B80000000583A1C0000000DF33C05F5E5BC9C38BFF60E801000000B85EE801000000B8582D310100008B002BF081E60000FFFF03763C33C9668B4E148D7431188B5E0C03DE81E300F0FFFF8B5608E805000000E9??000000558BEC83C4F0B9E90000008BF303DAE801000000B8582D770100008B0003C68945F4E801000000B85A81EA86"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D 64 24 00 55 8B EC 53 56 57 8B 4D 10 83 81 B8 00 00 00 05 83 A1 C0 00 00 00 DF 33 C0 5F 5E 5B C9 C3 8B FF 60 E8 01 00 00 00 B8 5E E8 01 00 00 00 B8 58 2D 31 01 00 00 8B 00 2B F0 81 E6 00 00 FF FF 03 76 3C 33 C9 66 8B 4E 14 8D 74 31 18 8B 5E 0C 03 DE 81 E3 00 F0 FF FF 8B 56 08 E8 05 00 00 00 E9 ?? 00 00 00 55 8B EC 83 C4 F0 B9 E9 00 00 00 8B F3 03 DA E8 01 00 00 00 B8 58 2D 77 01 00 00 8B 00 03 C6 89 45 F4 E8 01 00 00 00 B8 5A 81 EA 86 }
	condition:
		$1 at pe.entry_point
}

rule copy_prtector_20 {
	meta:
		tool = "P"
		name = "Copy Protector"
		version = "2.0"
		pattern = "2EA2????5351521E06B4??1E0E1FBA????CD211F"
	strings:
		$1 = { 2E A2 ?? ?? 53 51 52 1E 06 B4 ?? 1E 0E 1F BA ?? ?? CD 21 1F }
	condition:
		$1 at pe.entry_point
}

rule copycontrol_303 {
	meta:
		tool = "P"
		name = "CopyControl"
		version = "3.03"
		pattern = "CC9090EB0B0150515253546133612D35CAD10752D1A13C"
	strings:
		$1 = { CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1 3C }
	condition:
		$1 at pe.entry_point
}

rule copyminder {
	meta:
		tool = "P"
		name = "CopyMinder"
		pattern = "8325????????EF6A00E8????????E8????????CCFF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25????????FF25"
	strings:
		$1 = { 83 25 ?? ?? ?? ?? EF 6A 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 }
	condition:
		$1 at pe.entry_point
}

rule cpav {
	meta:
		tool = "P"
		name = "CPAV"
		pattern = "E8????4D5AB1019301000002"
	strings:
		$1 = { E8 ?? ?? 4D 5A B1 01 93 01 00 00 02 }
	condition:
		$1 at pe.entry_point
}

rule crinkler_01_02 {
	meta:
		tool = "P"
		name = "Crinkler"
		version = "0.1 - 0.2"
		pattern = "B9????????01C068????????6A0058506A005F485DBB03000000BE????????E9"
	strings:
		$1 = { B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9 }
	condition:
		$1 at pe.entry_point
}

rule crinkler_03_04 {
	meta:
		tool = "P"
		name = "Crinkler"
		version = "0.3 - 0.4"
		pattern = "B80000420031DB43EB58"
	strings:
		$1 = { B8 00 00 42 00 31 DB 43 EB 58 }
	condition:
		$1 at pe.entry_point
}

rule crunch_5fusion4 {
	meta:
		tool = "P"
		name = "Crunch"
		version = "5 Fusion 4"
		pattern = "EB1503??????06??????????????????????68????????55E8"
	strings:
		$1 = { EB 15 03 ?? ?? ?? 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 55 E8 }
	condition:
		$1 at pe.entry_point
}

rule crunch_10 {
	meta:
		tool = "P"
		name = "Crunch"
		version = "1.0"
		pattern = "55E8????????5D83ED068BC5556089AD????????2B85????????8985????????80BD??????????7509C685"
	strings:
		$1 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 75 09 C6 85 }
	condition:
		$1 at pe.entry_point
}

rule crunch_20 {
	meta:
		tool = "P"
		name = "Crunch"
		version = "2.0"
		pattern = "55E8????????5D83ED068BC5556089AD????????2B85????????8985????????55BB????????03DD536467FF36????64678926"
	strings:
		$1 = { 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 55 BB ?? ?? ?? ?? 03 DD 53 64 67 FF 36 ?? ?? 64 67 89 26 }
	condition:
		$1 at pe.entry_point
}

rule crunch_30 {
	meta:
		tool = "P"
		name = "Crunch"
		version = "3.0"
		pattern = "EB10????????????????????????????????55E8????????5D81ED18??????8BC555609C2B85????????8985????????FF74"
	strings:
		$1 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? FF 74 }
	condition:
		$1 at pe.entry_point
}

rule crunch_40 {
	meta:
		tool = "P"
		name = "Crunch"
		version = "4.0"
		pattern = "EB10????????????????????????????????55E8????????5D81ED18??????8BC555609C2B85E906????8985E106????FF74242CE8BB0100000F8292050000E8F1030000490F8886050000686CD9B29633C050E824"
	strings:
		$1 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 5D 81 ED 18 ?? ?? ?? 8B C5 55 60 9C 2B 85 E9 06 ?? ?? 89 85 E1 06 ?? ?? FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 }
	condition:
		$1 at pe.entry_point
}

rule crunch_50 {
	meta:
		tool = "P"
		name = "Crunch"
		version = "5.0"
		pattern = "EB1503000000060000000000000000000000680000000055E8000000005D81ED1D0000008BC555609C2B85FC0700008985E8070000FF74242CE8200200000F8294060000E8F3040000490F88880600008BB5E80700"
	strings:
		$1 = { EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 FC 07 00 00 89 85 E8 07 00 00 FF 74 24 2C E8 20 02 00 00 0F 82 94 06 00 00 E8 F3 04 00 00 49 0F 88 88 06 00 00 8B B5 E8 07 00 }
	condition:
		$1 at pe.entry_point
}

rule cruncher_10 {
	meta:
		tool = "P"
		name = "Cruncher"
		version = "1.0"
		pattern = "2E????????2E??????B430CD213C0373??BB????8EDB8D??????B409CD210633C050CB"
	strings:
		$1 = { 2E ?? ?? ?? ?? 2E ?? ?? ?? B4 30 CD 21 3C 03 73 ?? BB ?? ?? 8E DB 8D ?? ?? ?? B4 09 CD 21 06 33 C0 50 CB }
	condition:
		$1 at pe.entry_point
}

rule dirty_cryptor {
	meta:
		tool = "P"
		name = "DirTy CrYpt0r"
		pattern = "B8????????32DBFEC33018403D????????7E??68????????E8"
	strings:
		$1 = { B8 ?? ?? ?? ?? 32 DB FE C3 30 18 40 3D ?? ?? ?? ?? 7E ?? 68 ?? ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule crypkey_5x_6x {
	meta:
		tool = "P"
		name = "CrypKey"
		version = "5.x - 6.x"
		pattern = "E8????????5883E805505F578BF781EF????????83C639BA????????8BDFB90B??????8B06"
	strings:
		$1 = { E8 ?? ?? ?? ?? 58 83 E8 05 50 5F 57 8B F7 81 EF ?? ?? ?? ?? 83 C6 39 BA ?? ?? ?? ?? 8B DF B9 0B ?? ?? ?? 8B 06 }
	condition:
		$1 at pe.entry_point
}

rule crypkey_56x_01 {
	meta:
		tool = "P"
		name = "CrypKey"
		version = "5.6.x"
		pattern = "8B1D????????83FB00750AE8????????E8"
	strings:
		$1 = { 8B 1D ?? ?? ?? ?? 83 FB 00 75 0A E8 ?? ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule crypkey_56x_02 {
	meta:
		tool = "P"
		name = "CrypKey"
		version = "5.6.x"
		pattern = "E8????????E8????????83F80075076A00E8"
	strings:
		$1 = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 00 75 07 6A 00 E8 }
	condition:
		$1 at pe.entry_point
}

rule crypkey_61x {
	meta:
		tool = "P"
		name = "CrypKey"
		version = "6.1.x"
		pattern = "833D????????00753468????????E8"
	strings:
		$1 = { 83 3D ?? ?? ?? ?? 00 75 34 68 ?? ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule crypter_31 {
	meta:
		tool = "P"
		name = "Crypter"
		version = "3.1"
		pattern = "68FF6424F06858585858FFD4508B40F205B095F6950F850181BBFF68"
	strings:
		$1 = { 68 FF 64 24 F0 68 58 58 58 58 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 }
	condition:
		$1 at pe.entry_point
}

rule cryptic_20 {
	meta:
		tool = "P"
		name = "Cryptic"
		version = "2.0"
		pattern = "B800004000BB??????00B900100000BA??????0003D803C803D13BCA74068031??41EBF6FFE3"
	strings:
		$1 = { B8 00 00 40 00 BB ?? ?? ?? 00 B9 00 10 00 00 BA ?? ?? ?? 00 03 D8 03 C8 03 D1 3B CA 74 06 80 31 ?? 41 EB F6 FF E3 }
	condition:
		$1 at pe.entry_point
}

rule cryptolock_202 {
	meta:
		tool = "P"
		name = "Crypto-Lock"
		version = "2.02"
		pattern = "60BE??9040008DBE????FFFF5783CDFFEB109090909090908A0646880747"
	strings:
		$1 = { 60 BE ?? 90 40 00 8D BE ?? ?? FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 }
	condition:
		$1 at pe.entry_point
}

rule cryptocracks_pe_protector_092 {
	meta:
		tool = "P"
		name = "CRYPToCRACk's PE Protector"
		version = "0.9.2"
		pattern = "E801000000E8585B81E300FFFFFF66813B4D5A753784DB75338BF303????813E504500007526"
	strings:
		$1 = { E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 ?? ?? 81 3E 50 45 00 00 75 26 }
	condition:
		$1 at pe.entry_point
}

rule cryptocracks_pe_protector_093 {
	meta:
		tool = "P"
		name = "CRYPToCRACk's PE Protector"
		version = "0.9.3"
		pattern = "5B81E300FFFFFF66813B4D5A75338BF303733C813E5045000075260FB746188BC869C0AD0B0000F7E02DAB5D414B69C9DEC0000003C1"
	strings:
		$1 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 }
	condition:
		$1 at pe.entry_point
}

rule crypwrap {
	meta:
		tool = "P"
		name = "CrypWrap"
		pattern = "E8B8??????E89002????83F8??75076A??E8????????FF15498F40??A9??????80740E"
	strings:
		$1 = { E8 B8 ?? ?? ?? E8 90 02 ?? ?? 83 F8 ?? 75 07 6A ?? E8 ?? ?? ?? ?? FF 15 49 8F 40 ?? A9 ?? ?? ?? 80 74 0E }
	condition:
		$1 at pe.entry_point
}

rule cygwin32 {
	meta:
		tool = "P"
		name = "Cygwin32"
		pattern = "5589E583EC04833D"
	strings:
		$1 = { 55 89 E5 83 EC 04 83 3D }
	condition:
		$1 at pe.entry_point
}

rule d1s1g_uv {
	meta:
		tool = "P"
		name = "D1NS1G"
		pattern = "183700000000000001000A0000001800008000000000????183700000000020000008800008038000080960000805000008000000000????18370000000000000100000000006800000000000000????183700000000000001000000000078000000B0F00000100000000000000000000000C0F0000060000000000000000000000006004400560043004C0041004C000B005000410043004B0041004700450049004E0046004F00000000000000000000000000"
	strings:
		$1 = { 18 37 00 00 00 00 00 00 01 00 0A 00 00 00 18 00 00 80 00 00 00 00 ?? ?? 18 37 00 00 00 00 02 00 00 00 88 00 00 80 38 00 00 80 96 00 00 80 50 00 00 80 00 00 00 00 ?? ?? 18 37 00 00 00 00 00 00 01 00 00 00 00 00 68 00 00 00 00 00 00 00 ?? ?? 18 37 00 00 00 00 00 00 01 00 00 00 00 00 78 00 00 00 B0 F0 00 00 10 00 00 00 00 00 00 00 00 00 00 00 C0 F0 00 00 60 00 00 00 00 00 00 00 00 00 00 00 06 00 44 00 56 00 43 00 4C 00 41 00 4C 00 0B 00 50 00 41 00 43 00 4B 00 41 00 47 00 45 00 49 00 4E 00 46 00 4F 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule d1s1g_11b_scrambled_exe {
	meta:
		tool = "P"
		name = "D1S1G"
		version = "1.1b scrambled EXE"
		pattern = "E807000000E81E000000C3905889C289C22500F0FFFF5083C0558D00FF308D4004FF3052C38D4000558BEC83C4E85356578B4D108B45088945F88B450C8945F48D41618B388D41658B0003C78945FC8D41698B0003C78D516D8B1203D783C1718B0903CF2BCA720A4187D18031FF414A75F98945F0EB718B"
	strings:
		$1 = { E8 07 00 00 00 E8 1E 00 00 00 C3 90 58 89 C2 89 C2 25 00 F0 FF FF 50 83 C0 55 8D 00 FF 30 8D 40 04 FF 30 52 C3 8D 40 00 55 8B EC 83 C4 E8 53 56 57 8B 4D 10 8B 45 08 89 45 F8 8B 45 0C 89 45 F4 8D 41 61 8B 38 8D 41 65 8B 00 03 C7 89 45 FC 8D 41 69 8B 00 03 C7 8D 51 6D 8B 12 03 D7 83 C1 71 8B 09 03 CF 2B CA 72 0A 41 87 D1 80 31 FF 41 4A 75 F9 89 45 F0 EB 71 8B }
	condition:
		$1 at pe.entry_point
}

rule d1s1g_11b {
	meta:
		tool = "P"
		name = "D1S1G"
		version = "1.1b"
		pattern = "00000000????????00000000000001000A0000001800008000000000????????00000000020000008800008038000080960000805000008000000000????????0000000000000100000000006800000000000000????????00000000000001000000000078000000B0????00100000000000000000000000C0????????000000000000000000000006004400560043004C0041004C000B005000410043004B0041004700450049004E0046004F000000"
	strings:
		$1 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 01 00 0A 00 00 00 18 00 00 80 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 02 00 00 00 88 00 00 80 38 00 00 80 96 00 00 80 50 00 00 80 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 00 00 68 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 00 00 78 00 00 00 B0 ?? ?? 00 10 00 00 00 00 00 00 00 00 00 00 00 C0 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 06 00 44 00 56 00 43 00 4C 00 41 00 4C 00 0B 00 50 00 41 00 43 00 4B 00 41 00 47 00 45 00 49 00 4E 00 46 00 4F 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule daemon_protect {
	meta:
		tool = "P"
		name = "DAEMON Protect"
		version = "0.6.7"
		pattern = "60609C8CC932C9E30C520F014C24FE5A83C20C8B1A9D61"
	strings:
		$1 = { 60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D 61 }
	condition:
		$1 at pe.entry_point
}

rule dalkrypt_10 {
	meta:
		tool = "P"
		name = "DalKrypt"
		version = "1.0"
		pattern = "68001040005868??????005F33DBEB0D8A140380EA0780F2048814034381FB??????0072EBFFE7"
	strings:
		$1 = { 68 00 10 40 00 58 68 ?? ?? ?? 00 5F 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB ?? ?? ?? 00 72 EB FF E7 }
	condition:
		$1 at pe.entry_point
}

rule dcrypt_private {
	meta:
		tool = "P"
		name = "DCrypt Private"
		version = "0.9b"
		pattern = "B9??????00E8000000005868??????0083E80B0F1800D00048E2FBC3"
	strings:
		$1 = { B9 ?? ?? ?? 00 E8 00 00 00 00 58 68 ?? ?? ?? 00 83 E8 0B 0F 18 00 D0 00 48 E2 FB C3 }
	condition:
		$1 at pe.entry_point
}

rule def_10_01 {
	meta:
		tool = "P"
		name = "DEF"
		version = "1.0"
		pattern = "BE??0140006A??59807E070074118B46"
	strings:
		$1 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 }
	condition:
		$1 at pe.entry_point
}

rule def_10_02 {
	meta:
		tool = "P"
		name = "DEF"
		version = "1.0"
		pattern = "BE????40006A??59807E070074118B460C05000040008B56103010404A75FA83C628E2E468????4000C30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	strings:
		$1 = { BE ?? ?? 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? ?? 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule diamondcs {
	meta:
		tool = "P"
		name = "DIAMONDCS"
		pattern = "60EB0A4469616D6F6E64435300EB02EB05E8F9FFFFFF582D13000000F2EB0285"
	strings:
		$1 = { 60 EB 0A 44 69 61 6D 6F 6E 64 43 53 00 EB 02 EB 05 E8 F9 FF FF FF 58 2D 13 00 00 00 F2 EB 02 85 }
	condition:
		$1 at pe.entry_point
}

rule ding_boys_pe_lock_007 {
	meta:
		tool = "P"
		name = "Ding Boy's PE-lock"
		version = "0.07"
		pattern = "555756525153E8000000005D8BD581ED23354000"
	strings:
		$1 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 23 35 40 00 }
	condition:
		$1 at pe.entry_point
}

rule ding_boys_pe_lock_08 {
	meta:
		tool = "P"
		name = "Ding Boy's PE-lock"
		version = "0.8 Phantasm"
		pattern = "555756525153E8000000005D8BD581ED0D394000"
	strings:
		$1 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00 }
	condition:
		$1 at pe.entry_point
}

rule ding_boys_pe_lock_10_11 {
	meta:
		tool = "P"
		name = "Ding Boy's PE-lock"
		version = "1.0, 1.1 Phantasm"
		pattern = "5557565251536681C3EB02EBFC6681C3EB02EBFC"
	strings:
		$1 = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC }
	condition:
		$1 at pe.entry_point
}

rule ding_boys_pe_lock_15b3 {
	meta:
		tool = "P"
		name = "Ding Boy's PE-lock"
		version = "1.5b3 Phantasm"
		pattern = "9C5557565251539CFAE8????????5D81ED5B5340??B0"
	strings:
		$1 = { 9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? B0 }
	condition:
		$1 at pe.entry_point
}

rule ding_boys_pe_lock_210_01 {
	meta:
		tool = "P"
		name = "Ding Boy's PE-lock"
		version = "2.10"
		pattern = "9C6A10730BEB02C151E806??????C41173F75BCD83C404EB0299EBFF0C247101E879E07A017583C4049DEB0175685F2040??E8B0EFFFFF7203730175BE"
	strings:
		$1 = { 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 ?? E8 B0 EF FF FF 72 03 73 01 75 BE }
	condition:
		$1 at pe.entry_point
}

rule ding_boys_pe_lock_210_02 {
	meta:
		tool = "P"
		name = "Ding Boy's PE-lock"
		version = "2.10"
		pattern = "EB20????????????????????????????????????????????????????????????????9C5557565251539CE8????????5D81ED????????EB587573657233322E646C6C??4D657373616765426F7841??6B65726E656C33322E646C6C??536C656570??4765745469636B436F756E74"
	strings:
		$1 = { EB 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? EB 58 75 73 65 72 33 32 2E 64 6C 6C ?? 4D 65 73 73 61 67 65 42 6F 78 41 ?? 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C ?? 53 6C 65 65 70 ?? 47 65 74 54 69 63 6B 43 6F 75 6E 74 }
	condition:
		$1 at pe.entry_point
}

rule ding_boys_pe_lock_233 {
	meta:
		tool = "P"
		name = "Ding Boy's PE-lock"
		version = "2.33"
		pattern = "EB20????40??????????????????????????????????????????????????????????9C5557565251539CE8????????5D81ED????????9C6A10730BEB02C151E806??????C41173F75BCD83C404EB0299EBFF0C247101E879E07A017583"
	strings:
		$1 = { EB 20 ?? ?? 40 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 }
	condition:
		$1 at pe.entry_point
}

rule dipacker_1x {
	meta:
		tool = "P"
		name = "diPacker"
		version = "1.x"
		pattern = "0F002DE90100A0E3680100EB8C0000EB2B0000EB000020E01C108FE28E208FE20030A0E3670100EB0F00BDE800C08FE200F09CE5"
	strings:
		$1 = { 0F 00 2D E9 01 00 A0 E3 68 01 00 EB 8C 00 00 EB 2B 00 00 EB 00 00 20 E0 1C 10 8F E2 8E 20 8F E2 00 30 A0 E3 67 01 00 EB 0F 00 BD E8 00 C0 8F E2 00 F0 9C E5 }
	condition:
		$1 at pe.entry_point
}

rule diprotector_1x {
	meta:
		tool = "P"
		name = "diProtector"
		version = "1.x"
		pattern = "0100A0E3140000EB000020E044109FE5032AA0E34030A0E3AE0000EB30008FE50020A0E13A0E8FE2000080E21C109FE520308FE20E0000EB14009FE514109FE57F20A0E3C50000EB04C08FE200F09CE5"
	strings:
		$1 = { 01 00 A0 E3 14 00 00 EB 00 00 20 E0 44 10 9F E5 03 2A A0 E3 40 30 A0 E3 AE 00 00 EB 30 00 8F E5 00 20 A0 E1 3A 0E 8F E2 00 00 80 E2 1C 10 9F E5 20 30 8F E2 0E 00 00 EB 14 00 9F E5 14 10 9F E5 7F 20 A0 E3 C5 00 00 EB 04 C0 8F E2 00 F0 9C E5 }
	condition:
		$1 at pe.entry_point
}

rule djoin_07_rc4 {
	meta:
		tool = "P"
		name = "DJoin"
		version = "0.7 [RC4]"
		pattern = "C605????400000C605????400000????????????????00????????00??????????00??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????00"
	strings:
		$1 = { C6 05 ?? ?? 40 00 00 C6 05 ?? ?? 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule djoin_07_xor {
	meta:
		tool = "P"
		name = "DJoin"
		version = "0.7 [XOR]"
		pattern = "C605????400000????????????????00????????00??????????00??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????00"
	strings:
		$1 = { C6 05 ?? ?? 40 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule dotfix_nice_protect_uv {
	meta:
		tool = "P"
		name = "DotFix Nice Protect"
		pattern = "60E8550000008DBD0010400068??????00033C248BF79068311040009BDBE355DB04248BC7DB442404DEC1DB1C248B1C2466AD51DB04249090DA8D77104000DB1C24D1E129"
	strings:
		$1 = { 60 E8 55 00 00 00 8D BD 00 10 40 00 68 ?? ?? ?? 00 03 3C 24 8B F7 90 68 31 10 40 00 9B DB E3 55 DB 04 24 8B C7 DB 44 24 04 DE C1 DB 1C 24 8B 1C 24 66 AD 51 DB 04 24 90 90 DA 8D 77 10 40 00 DB 1C 24 D1 E1 29 }
	condition:
		$1 at pe.entry_point
}

rule dotfix_nice_protect_2x {
	meta:
		tool = "P"
		name = "DotFix Nice Protect"
		version = "2.x"
		pattern = "E9FF000000608B7424248B7C2428FCB28033DBA4B302E86D00000073F633C9E864000000731C33C0E85B0000007323B30241B010E84F00000012C073F7753FAAEBD4E84D0000002BCB7510E842000000EB28ACD1E8744D13C9EB1C9148C1E008ACE82C0000003D007D0000730A80FC05730683F87F77024141958BC5B301568BF72BF0F3A45EEB8E02D275058A164612D2C333C941E8EEFFFFFF13C9E8E7FFFFFF72F2C32B7C2428897C241C61C360B8????????03C550B8????????03C5FF10BB????????03DD83C30C5350B8????????03C5FF106A406800100000FF74242C6A00FFD08944241C61C3"
	strings:
		$1 = { E9 FF 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 B8 ?? ?? ?? ?? 03 C5 50 B8 ?? ?? ?? ?? 03 C5 FF 10 BB ?? ?? ?? ?? 03 DD 83 C3 0C 53 50 B8 ?? ?? ?? ?? 03 C5 FF 10 6A 40 68 00 10 00 00 FF 74 24 2C 6A 00 FF D0 89 44 24 1C 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule dragonarmor {
	meta:
		tool = "P"
		name = "DragonArmor"
		pattern = "BF4C????0083C9FF33C06834????00F2AEF7D14951684C????00E8110A000083C40C684C????00FF1500????008BF0BF4C????0083C9FF33C0F2AEF7D149BF4C????008BD16834????00C1E902F3AB8BCA83E103F3AABF5C????0083C9FF33C0F2AEF7D14951685C????00E8C00900008B1D04????0083C40C685C????0056FFD3A3D4????00BF5C????0083C9FF33C0F2AEF7D149BF5C????008BD16834????00C1E902F3AB8BCA83E1"
	strings:
		$1 = { BF 4C ?? ?? 00 83 C9 FF 33 C0 68 34 ?? ?? 00 F2 AE F7 D1 49 51 68 4C ?? ?? 00 E8 11 0A 00 00 83 C4 0C 68 4C ?? ?? 00 FF 15 00 ?? ?? 00 8B F0 BF 4C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 4C ?? ?? 00 8B D1 68 34 ?? ?? 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF 5C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 5C ?? ?? 00 E8 C0 09 00 00 8B 1D 04 ?? ?? 00 83 C4 0C 68 5C ?? ?? 00 56 FF D3 A3 D4 ?? ?? 00 BF 5C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 5C ?? ?? 00 8B D1 68 34 ?? ?? 00 C1 E9 02 F3 AB 8B CA 83 E1 }
	condition:
		$1 at pe.entry_point
}

rule dropper_creator_01 {
	meta:
		tool = "P"
		name = "Dropper Creator"
		version = "0.1"
		pattern = "60E8000000005D8D05????????29C58D85????????31C064034030780C8B400C8B701CAD8B4008EB09"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 8D 05 ?? ?? ?? ?? 29 C5 8D 85 ?? ?? ?? ?? 31 C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 }
	condition:
		$1 at pe.entry_point
}

rule dshield {
	meta:
		tool = "P"
		name = "DSHIELD"
		pattern = "06E8????5E83EE??16179C58B9????25????2E"
	strings:
		$1 = { 06 E8 ?? ?? 5E 83 EE ?? 16 17 9C 58 B9 ?? ?? 25 ?? ?? 2E }
	condition:
		$1 at pe.entry_point
}

rule duals_crypt {
	meta:
		tool = "P"
		name = "Dual's Cryptor"
		pattern = "558BEC81EC00050000E8000000005D81ED0E"
	strings:
		$1 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E }
	condition:
		$1 at pe.entry_point
}

rule dup_2x {
	meta:
		tool = "P"
		name = "dUP"
		version = "2.x"
		pattern = "E8????????E8????????8BF06A0068????????56E8????????A2????????6A0068????????56E8????????A2????????6A0068????????56E8????????A2????????68????????68????????56E8????????3C017519BE????????68000200005668"
	strings:
		$1 = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 3C 01 75 19 BE ?? ?? ?? ?? 68 00 02 00 00 56 68 }
	condition:
		$1 at pe.entry_point
}

rule dup_2x_patcher {
	meta:
		tool = "P"
		name = "dUP"
		version = "2.x patcher"
		pattern = "8BCB85C974??803A017408ACAE750A4249EBEF47464249EBE9"
	strings:
		$1 = { 8B CB 85 C9 74 ?? 80 3A 01 74 08 AC AE 75 0A 42 49 EB EF 47 46 42 49 EB E9 }
	condition:
		$1 at pe.entry_point
}

rule dxpack_086 {
	meta:
		tool = "P"
		name = "DxPack"
		version = "0.86"
		pattern = "60E8000000005D8BFD81ED061040002BBD9412400081EF0600000083BD14134000010F842F010000"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00 }
	condition:
		$1 at pe.entry_point
}

rule dxpack_10 {
	meta:
		tool = "P"
		name = "DxPack"
		version = "1.0"
		pattern = "60E8????????5D8BFD81ED????????2BB9????????81EF????????83BD??????????0F84"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 }
	condition:
		$1 at pe.entry_point
}

rule dza_patcher {
	meta:
		tool = "P"
		name = "DZA Patcher"
		version = "1.3"
		pattern = "BF0040400099684820400068002040005252525252525257E81501000085C0751C9952525752E8CB000000FF354C204000E8D20000006A00E8BF000000996858204000525268631040005252E8DB0000006AFFFF3548204000E8C2000000E8C8FFFFFFBF40404000FF354C204000E8A10000008B0F83F90074B1606A006A046A0151FF3548204000E8750000006160BB5C2040006A006A015351FF3548204000E87500000061A0"
	strings:
		$1 = { BF 00 40 40 00 99 68 48 20 40 00 68 00 20 40 00 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35 4C 20 40 00 E8 D2 00 00 00 6A 00 E8 BF 00 00 00 99 68 58 20 40 00 52 52 68 63 10 40 00 52 52 E8 DB 00 00 00 6A FF FF 35 48 20 40 00 E8 C2 00 00 00 E8 C8 FF FF FF BF 40 40 40 00 FF 35 4C 20 40 00 E8 A1 00 00 00 8B 0F 83 F9 00 74 B1 60 6A 00 6A 04 6A 01 51 FF 35 48 20 40 00 E8 75 00 00 00 61 60 BB 5C 20 40 00 6A 00 6A 01 53 51 FF 35 48 20 40 00 E8 75 00 00 00 61 A0 }
	condition:
		$1 at pe.entry_point
}

rule e_you_di_dai {
	meta:
		tool = "P"
		name = "E.You.Di.Dai"
		pattern = "558BECB8????????E8????????5356570F318BD80F318BD02BD3C1EA10B8????????0F6EC0B8????????0F6EC80FF5C10F7EC00F7703C2??????????FFE0"
	strings:
		$1 = { 55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 57 0F 31 8B D8 0F 31 8B D0 2B D3 C1 EA 10 B8 ?? ?? ?? ?? 0F 6E C0 B8 ?? ?? ?? ?? 0F 6E C8 0F F5 C1 0F 7E C0 0F 77 03 C2 ?? ?? ?? ?? ?? FF E0 }
	condition:
		$1 at pe.entry_point
}

rule elicense_system_4000 {
	meta:
		tool = "P"
		name = "Elicense System"
		version = "4.0.0.0"
		pattern = "0000000063796200656C6963656E34302E646C6C00000000"
	strings:
		$1 = { 00 00 00 00 63 79 62 00 65 6C 69 63 65 6E 34 30 2E 64 6C 6C 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule embedpe_100_124 {
	meta:
		tool = "P"
		name = "EmbedPE"
		version = "1.00 - 1.24"
		pattern = "00000000????????0000000000000000????????????????0000000000000000000000000000000000000000????????????????????????00000000????????????????????????000000004B45524E454C33322E646C6C0000000047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C69627261727941000000000000000000"
	strings:
		$1 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule embedpe_113_01 {
	meta:
		tool = "P"
		name = "EmbedPE"
		version = "1.13"
		pattern = "83EC5060685DB9525AE82F990000DC99F3570568"
	strings:
		$1 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 }
	condition:
		$1 at pe.entry_point
}

rule embedpe_113_02 {
	meta:
		tool = "P"
		name = "EmbedPE"
		version = "1.13"
		pattern = "83EC5060685DB9525AE82F990000DC99F3570568B85E2DC6DAFD4863053C71B85E977C367E327C084F06516410A3F14ECF25CB80D2995446EDE1D346862D106893835C464D439B8CD67CBB996997712A2FA3386B33A3F50B85977CBA1D96DD07F8FDD23A9883CC46999DDF6F899254469F9443CC41439B8C61B9D86F963BD1073224DD07058ECB6FA1075C6220E0DBBA9D835446E683517A2B9454648A830568D75E2DC6B75700"
	strings:
		$1 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 B8 5E 2D C6 DA FD 48 63 05 3C 71 B8 5E 97 7C 36 7E 32 7C 08 4F 06 51 64 10 A3 F1 4E CF 25 CB 80 D2 99 54 46 ED E1 D3 46 86 2D 10 68 93 83 5C 46 4D 43 9B 8C D6 7C BB 99 69 97 71 2A 2F A3 38 6B 33 A3 F5 0B 85 97 7C BA 1D 96 DD 07 F8 FD D2 3A 98 83 CC 46 99 9D DF 6F 89 92 54 46 9F 94 43 CC 41 43 9B 8C 61 B9 D8 6F 96 3B D1 07 32 24 DD 07 05 8E CB 6F A1 07 5C 62 20 E0 DB BA 9D 83 54 46 E6 83 51 7A 2B 94 54 64 8A 83 05 68 D7 5E 2D C6 B7 57 00 }
	condition:
		$1 at pe.entry_point
}

rule embedpe_124 {
	meta:
		tool = "P"
		name = "EmbedPE"
		version = "1.24"
		pattern = "83EC506068????????E8CBFF0000"
	strings:
		$1 = { 83 EC 50 60 68 ?? ?? ?? ?? E8 CB FF 00 00 }
	condition:
		$1 at pe.entry_point
}

rule encryptpe_12003318_12003518 {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "1.2003.3.18 - 1.2003.5.18"
		pattern = "609C64FF3500000000E879"
	strings:
		$1 = { 60 9C 64 FF 35 00 00 00 00 E8 79 }
	condition:
		$1 at pe.entry_point
}

rule encryptpe_22004616_22006630 {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2004.6.16 - 2.2006.6.30"
		pattern = "609C64FF3500000000E87A"
	strings:
		$1 = { 60 9C 64 FF 35 00 00 00 00 E8 7A }
	condition:
		$1 at pe.entry_point
}

rule encryptpe_22006115 {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2006.1.15"
		pattern = "4550453A20456E637279707450452056322E323030362E312E3135"
	strings:
		$1 = { 45 50 45 3A 20 45 6E 63 72 79 70 74 50 45 20 56 32 2E 32 30 30 36 2E 31 2E 31 35 }
	condition:
		$1 at pe.entry_point
}

rule encryptpe_22006710_220061025 {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2006.7.10 - 2.2006.10.25"
		pattern = "609C64FF3500000000E873010000"
	strings:
		$1 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 }
	condition:
		$1 at pe.entry_point
}

rule encryptpe_220070411 {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2007.04.11"
		pattern = "609C64FF3500000000E81B020000000000000000000000000000????????????????0000000000000000000000000000000000000000????????????????????????????????????????????????????????????????????????000000006B65726E656C33322E646C6C00000047657454656D70506174684100000043726561746546696C654100000043726561746546696C654D617070696E67410000004D6170566965774F6646696C65000000556E6D6170566965774F6646696C65000000436C6F736548616E646C650000004C6F61644C6962726172794100000047657450726F63416464726573730000004578697450726F63657373"
	strings:
		$1 = { 60 9C 64 FF 35 00 00 00 00 E8 1B 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
	condition:
		$1 at pe.entry_point
}

rule encryptpe_22007121 {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2007.12.1"
		pattern = "000000000000000000000000000000004550453A20456E637279707450452056322E323030372E31322E312C20436F7079726967687420284329205746530000486F6D65506167653A207777772E656E637279707470652E636F6D0000000000454D61696C3A2077667323656E637279707470652E636F6D0000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 45 50 45 3A 20 45 6E 63 72 79 70 74 50 45 20 56 32 2E 32 30 30 37 2E 31 32 2E 31 2C 20 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 57 46 53 00 00 48 6F 6D 65 50 61 67 65 3A 20 77 77 77 2E 65 6E 63 72 79 70 74 70 65 2E 63 6F 6D 00 00 00 00 00 45 4D 61 69 6C 3A 20 77 66 73 23 65 6E 63 72 79 70 74 70 65 2E 63 6F 6D 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule encryptpe_22008618_01 {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2008.6.18"
		pattern = "000000000000000000000000000000000000000000000000000000000000006B65726E656C33322E646C6C0047657454656D7050617468410043726561746546696C65410043726561746546696C654D617070696E6741004D6170566965774F6646696C6500556E6D6170566965774F6646696C6500436C6F736548616E646C65004C6F61644C69627261727941004578697450726F63657373000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000563232303038303631382E455045000000456E637279707450455F496E697400"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 43 72 65 61 74 65 46 69 6C 65 41 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 32 32 30 30 38 30 36 31 38 2E 45 50 45 00 00 00 45 6E 63 72 79 70 74 50 45 5F 49 6E 69 74 00 }
	condition:
		$1 at pe.entry_point
}

rule encryptpe_22008618_02 {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2008.6.18"
		pattern = "68??????00E8520100000000000000000000000000000000000000000000000000000000000000000000000000006B65726E656C33322E646C6C0047657454656D70506174684100437265617465"
	strings:
		$1 = { 68 ?? ?? ?? 00 E8 52 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 43 72 65 61 74 65 }
	condition:
		$1 at pe.entry_point
}

rule enigma_protector_102 {
	meta:
		tool = "P"
		name = "Enigma protector"
		version = "1.02"
		pattern = "60E8000000005D83ED0681ED??????????????????????????????????????????????????????????????????????E8010000009A83C404EB02FF3560E8240000000000FFEB02CD208B44240C8380B80000000331C0C383C008EB02FF1589C461EB2EEAEB2B83042403EB010031C0EB018564FF30EB0183648920EB02CD2089009A648F0500000000EB02C1905861EB013EBE01000000C1E60283EC0487DE891C24"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 FF 15 89 C4 61 EB 2E EA EB 2B 83 04 24 03 EB 01 00 31 C0 EB 01 85 64 FF 30 EB 01 83 64 89 20 EB 02 CD 20 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 90 58 61 EB 01 3E BE 01 00 00 00 C1 E6 02 83 EC 04 87 DE 89 1C 24 }
	condition:
		$1 at pe.entry_point
}

rule enigma_11x {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.1x"
		pattern = "60E8000000005D83ED068BF55756505333D88AC333D8EB132AC3057702000081EB9A0900005B585E5FEB0583C317EBE85756505333D88AC333D8EB132AC30577"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 83 ED 06 8B F5 57 56 50 53 33 D8 8A C3 33 D8 EB 13 2A C3 05 77 02 00 00 81 EB 9A 09 00 00 5B 58 5E 5F EB 05 83 C3 17 EB E8 57 56 50 53 33 D8 8A C3 33 D8 EB 13 2A C3 05 77 }
	condition:
		$1 at pe.entry_point
}

rule enigma_11x_15x {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.1x - 1.5x"
		pattern = "558BEC83C4F0B800104000E8????????9A83C4108BE55DE9"
	strings:
		$1 = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 ?? ?? ?? ?? 9A 83 C4 10 8B E5 5D E9 }
	condition:
		$1 at pe.entry_point
}

rule enigma_10_12 {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.0 - 1.2"
		pattern = "60E8000000005D83????81"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 83 ?? ?? 81 }
	condition:
		$1 at pe.entry_point
}

rule enigma_110_unregistred {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.10 unregistered"
		pattern = "6072807288728C729072947298729C72A072A459A8B05CE839D539E439F131F95C3D58CA5F56B12D207A2E301632722B72361CA533A99CAD9CB19CB59CB99CBD9CC19CC59CC99CCD9CD19CD59CD99CDD9CE19CE589"
	strings:
		$1 = { 60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89 }
	condition:
		$1 at pe.entry_point
}

rule enigma_1x_01 {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.x"
		pattern = "456E69676D612070726F746563746F72207631"
	strings:
		$1 = { 45 6E 69 67 6D 61 20 70 72 6F 74 65 63 74 6F 72 20 76 31 }
	condition:
		$1 at pe.entry_point
}

rule enigma_1x_02 {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.x"
		pattern = "0000005669727475616C416C6C6F630000005669727475616C467265650000004765744D6F64756C6548616E646C654100000047657450726F63416464726573730000004578697450726F636573730000004C6F61644C696272617279410000004D657373616765426F7841000000526567436C6F73654B657900000053797346726565537472696E67000000437265617465466F6E74410000005368656C6C45786563757465410000"
	strings:
		$1 = { 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 00 00 52 65 67 43 6C 6F 73 65 4B 65 79 00 00 00 53 79 73 46 72 65 65 53 74 72 69 6E 67 00 00 00 43 72 65 61 74 65 46 6F 6E 74 41 00 00 00 53 68 65 6C 6C 45 78 65 63 75 74 65 41 00 00 }
	condition:
		$1 at pe.entry_point
}

rule enigma_131 {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.31"
		pattern = "60E8000000005D81ED0600000081ED????????E949000000????????????????????????????????????????????????????????????????????????????????0000000000000000000000000000000000000000000000000000000000000000008A84242800000080F8010F8407000000B8????????FFE0E904000000????????B8????????03C581C0????????B9????????BA????????301040490F85F6FFFFFFE904000000"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 81 ED ?? ?? ?? ?? E9 49 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 8A 84 24 28 00 00 00 80 F8 01 0F 84 07 00 00 00 B8 ?? ?? ?? ?? FF E0 E9 04 00 00 00 ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 81 C0 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 30 10 40 49 0F 85 F6 FF FF FF E9 04 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule ep_10 {
	meta:
		tool = "P"
		name = "EP"
		version = "1.0"
		pattern = "5083C0178BF09733C033C9B124AC86C4ACAA86C4AAE2F600B8400003003C40D2338B661450708B8D3402448B1810487003BA0C????????C033FE8B30AC30D0C1F010C2D030F030C2C1AA104242CAC1E2045FE95EB1C030??68????F300C3AA"
	strings:
		$1 = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 00 B8 40 00 03 00 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C ?? ?? ?? ?? C0 33 FE 8B 30 AC 30 D0 C1 F0 10 C2 D0 30 F0 30 C2 C1 AA 10 42 42 CA C1 E2 04 5F E9 5E B1 C0 30 ?? 68 ?? ?? F3 00 C3 AA }
	condition:
		$1 at pe.entry_point
}

rule ep_20 {
	meta:
		tool = "P"
		name = "EP"
		version = "2.0"
		pattern = "6A??60E90101"
	strings:
		$1 = { 6A ?? 60 E9 01 01 }
	condition:
		$1 at pe.entry_point
}

rule escargot_01_01 {
	meta:
		tool = "P"
		name = "Escargot"
		version = "0.1"
		pattern = "EB0440302E31606861"
	strings:
		$1 = { EB 04 40 30 2E 31 60 68 61 }
	condition:
		$1 at pe.entry_point
}

rule escargot_01_02 {
	meta:
		tool = "P"
		name = "Escargot"
		version = "0.1"
		pattern = "EB0828657363302E312960682B??????64FF350000000064892500000000B85C??????8B00FFD050BE0010????B900????00EB0549803431400BC975F7580BC0740833C0C700DEC0AD0BBE????????E9AC0000008B460CBB0000????03C35050B854??????8B00FFD05F803F007406C6070047EBF533FF8B160BD275038B561003D303D78B0AC702000000000BC9744BF7C100000080741481E1FFFF0000505150B850"
	strings:
		$1 = { EB 08 28 65 73 63 30 2E 31 29 60 68 2B ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 5C ?? ?? ?? 8B 00 FF D0 50 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B 46 0C BB 00 00 ?? ?? 03 C3 50 50 B8 54 ?? ?? ?? 8B 00 FF D0 5F 80 3F 00 74 06 C6 07 00 47 EB F5 33 FF 8B 16 0B D2 75 03 8B 56 10 03 D3 03 D7 8B 0A C7 02 00 00 00 00 0B C9 74 4B F7 C1 00 00 00 80 74 14 81 E1 FF FF 00 00 50 51 50 B8 50 }
	condition:
		$1 at pe.entry_point
}

rule escargot_01f {
	meta:
		tool = "P"
		name = "Escargot"
		version = "0.1f"
		pattern = "EB0440302E31606861??????64FF350000000064892500000000B892??????8B00FFD050B8CD??????8138DEC03713752D68C9??????6A406800??0000680000????B896??????8B00FFD08B4424F08B4C24F4EB0549C60401400BC975F7BE0010????B900????00EB0549803431400BC975F7580BC0740833C0C700DEC0AD0BBE????????E9AC0000008B460CBB0000????03C35050"
	strings:
		$1 = { EB 04 40 30 2E 31 60 68 61 ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 92 ?? ?? ?? 8B 00 FF D0 50 B8 CD ?? ?? ?? 81 38 DE C0 37 13 75 2D 68 C9 ?? ?? ?? 6A 40 68 00 ?? 00 00 68 00 00 ?? ?? B8 96 ?? ?? ?? 8B 00 FF D0 8B 44 24 F0 8B 4C 24 F4 EB 05 49 C6 04 01 40 0B C9 75 F7 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B 46 0C BB 00 00 ?? ?? 03 C3 50 50 }
	condition:
		$1 at pe.entry_point
}

rule excalibur_103_01 {
	meta:
		tool = "P"
		name = "Excalibur"
		version = "1.03"
		pattern = "E90000000060E8140000005D81ED000000006A45E8A30000006800000000E85861EB39"
	strings:
		$1 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 }
	condition:
		$1 at pe.entry_point
}
rule excalibur_103_02 {
	meta:
		tool = "P"
		name = "Excalibur"
		version = "1.03"
		pattern = "E90000000060E8140000005D81ED00000000"
	strings:
		$1 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule exe_guarder_18 {
	meta:
		tool = "P"
		name = "Exe Guarder"
		version = "1.8"
		pattern = "558BEC83C4D05356578D75FC8B442430250000FFFF81384D5A900074072D00100000EBF18945FCE8C8FFFFFF2DB20400008945F48B068B403C03068B407803068BC88B512003168B5924031E895DF08B591C031E895DEC8B41188BC84985C9725A4133C08BD8C1E30203DA8B3B033E813F4765745075408BDF83C304813B726F634175338BDF83C308813B64647265752683C70C66813F7373751C8BD003D20355F00FB712C1E2"
	strings:
		$1 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 5D EC 8B 41 18 8B C8 49 85 C9 72 5A 41 33 C0 8B D8 C1 E3 02 03 DA 8B 3B 03 3E 81 3F 47 65 74 50 75 40 8B DF 83 C3 04 81 3B 72 6F 63 41 75 33 8B DF 83 C3 08 81 3B 64 64 72 65 75 26 83 C7 0C 66 81 3F 73 73 75 1C 8B D0 03 D2 03 55 F0 0F B7 12 C1 E2 }
	condition:
		$1 at pe.entry_point
}

rule exe_locker_10 {
	meta:
		tool = "P"
		name = "Exe Locker"
		version = "1.0"
		pattern = "E800000000608B6C242081ED05000000"
	strings:
		$1 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule exe_manager_30 {
	meta:
		tool = "P"
		name = "EXE Manager"
		version = "3.0"
		source = "(c) Solar Designer"
		pattern = "B4301E06CD212E??????BF????B9????33C02E????47E2"
	strings:
		$1 = { B4 30 1E 06 CD 21 2E ?? ?? ?? BF ?? ?? B9 ?? ?? 33 C0 2E ?? ?? 47 E2 }
	condition:
		$1 at pe.entry_point
}

rule exe_packer_70 {
	meta:
		tool = "P"
		name = "EXE Packer"
		version = "7.0"
		pattern = "1E068CC383????2E????????B9????8CC88ED88BF14E8BFE"
	strings:
		$1 = { 1E 06 8C C3 83 ?? ?? 2E ?? ?? ?? ?? B9 ?? ?? 8C C8 8E D8 8B F1 4E 8B FE }
	condition:
		$1 at pe.entry_point
}

rule exe_stealth_11 {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "1.1"
		pattern = "60E8000000005D81EDFB1D4000B97B0900008BF7AC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED FB 1D 40 00 B9 7B 09 00 00 8B F7 AC }
	condition:
		$1 at pe.entry_point
}

rule exe_stealth_250 {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.50"
		pattern = "6090EB22457865537465616C7468202D207777772E776562746F6F6C6D61737465722E636F6DE800000000"
	strings:
		$1 = { 60 90 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D E8 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule exe_stealth_27 {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.7"
		pattern = "EB0060EB00E8000000005D81EDD32640"
	strings:
		$1 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40 }
	condition:
		$1 at pe.entry_point
}

rule exe_stealth_271 {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.71"
		pattern = "EB0060EB00E8000000005D81EDB02740"
	strings:
		$1 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED B0 27 40 }
	condition:
		$1 at pe.entry_point
}

rule exe_stealth_273 {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.73"
		pattern = "EB00EB2F536861726577617265202D20457865537465616C746800EB167777772E776562746F6F6C6D61737465722E636F6D006090E8000000005D81EDF0274000B91500000083C105EB05EBFE83C756EB0083E90281C178432765EB0081C11025940081E963850000B9770C0000908DBD612840008BF7AC"
	strings:
		$1 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 EB 16 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 60 90 E8 00 00 00 00 5D 81 ED F0 27 40 00 B9 15 00 00 00 83 C1 05 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 77 0C 00 00 90 8D BD 61 28 40 00 8B F7 AC }
	condition:
		$1 at pe.entry_point
}

rule exe_stealth_274_01 {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.74"
		pattern = "EB00EB17??????????????????????????????????????????????6090E8000000005D"
	strings:
		$1 = { EB 00 EB 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 90 E8 00 00 00 00 5D }
	condition:
		$1 at pe.entry_point
}

rule exe_stealth_274_02 {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.74"
		pattern = "EB00EB17536861726577617265202D20457865537465616C7468006090E8000000005D81EDC4274000B91500000083C10483C101EB05EBFE83C756EB0083E90281C178432765EB0081C11025940081E963850000B9910C0000908DBD382840008BF7AC????????????????????????????????????????????????????????????????????????????????????????????????AAE2CC"
	strings:
		$1 = { EB 00 EB 17 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 60 90 E8 00 00 00 00 5D 81 ED C4 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 91 0C 00 00 90 8D BD 38 28 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }
	condition:
		$1 at pe.entry_point
}

rule exe_stealth_275a {
	meta:
		tool = "P"
		name = "Exe Stealth"
		version = "2.75a"
		pattern = "EB585368617265776172652D56657273696F6E20457865537465616C74682C20636F6E7461637420737570706F727440776562746F6F6C6D61737465722E636F6D202D207777772E776562746F6F6C6D61737465722E636F6D00906090E8000000005D81EDF7274000B91500000083C10483C101EB05EBFE83C756EB00EB0083E90281C178432765EB0081C11025940081E963850000B9960C0000908DBD742840008BF7AC"
	strings:
		$1 = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 90 60 90 E8 00 00 00 00 5D 81 ED F7 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 74 28 40 00 8B F7 AC }
	condition:
		$1 at pe.entry_point
}

rule exe_stealth_275 {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.75"
		pattern = "906090E8000000005D81EDD1274000B915000000"
	strings:
		$1 = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule exe_stealth_276_unreg {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.76 unregistered"
		pattern = "EB??457865537465616C74682056322053686172657761726520"
	strings:
		$1 = { EB ?? 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 53 68 61 72 65 77 61 72 65 20 }
	condition:
		$1 at pe.entry_point
}

rule exe_stealth_276 {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.76"
		pattern = "EB65457865537465616C7468205632202D207777772E776562746F6F6C6D61737465722E636F6D20594F55522041442048455245215069524143592069532041"
	strings:
		$1 = { EB 65 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 59 4F 55 52 20 41 44 20 48 45 52 45 21 50 69 52 41 43 59 20 69 53 20 41 }
	condition:
		$1 at pe.entry_point
}

rule exe32pack_13x_01 {
	meta:
		tool = "P"
		name = "EXE32Pack"
		version = "1.3x"
		pattern = "3B??740281??553B??740281??533B??7401??????????0281??????????????3B??7401??5D8BD581ED????40"
	strings:
		$1 = { 3B ?? 74 02 81 ?? 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 ?? ?? ?? ?? ?? 02 81 ?? ?? ?? ?? ?? ?? ?? 3B ?? 74 01 ?? 5D 8B D5 81 ED ?? ?? 40 }
	condition:
		$1 at pe.entry_point
}

rule exe32pack_13x_02 {
	meta:
		tool = "P"
		name = "EXE32Pack"
		version = "1.3x"
		pattern = "3B??74028183553B??740281??533B??7401??????????0281????E8????????3B7401??5D8BD581ED"
	strings:
		$1 = { 3B ?? 74 02 81 83 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 ?? ?? ?? ?? ?? 02 81 ?? ?? E8 ?? ?? ?? ?? 3B 74 01 ?? 5D 8B D5 81 ED }
	condition:
		$1 at pe.entry_point
}

rule exebundle_30_small {
	meta:
		tool = "P"
		name = "ExeBundle"
		version = "3.0 small loader"
		pattern = "0000000060BE00F040008DBE0020FFFF5783CDFFEB109090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11"
	strings:
		$1 = { 00 00 00 00 60 BE 00 F0 40 00 8D BE 00 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 }
	condition:
		$1 at pe.entry_point
}

rule exebundle_30_standard {
	meta:
		tool = "P"
		name = "ExeBundle"
		version = "3.0 standard loader"
		pattern = "0000000060BE00B042008DBE0060FDFFC787B0E40200313C4BDF5783CDFFEB0E909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB"
	strings:
		$1 = { 00 00 00 00 60 BE 00 B0 42 00 8D BE 00 60 FD FF C7 87 B0 E4 02 00 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB }
	condition:
		$1 at pe.entry_point
}

rule execrypt_10 {
	meta:
		tool = "P"
		name = "EXECrypt"
		version = "1.0"
		pattern = "909060E8000000005D81EDD1274000B91500000083C10483C101EB05EBFE83C756EB00EB0083E90281C178432765EB0081C11025940081E963850000B9960C0000908DBD4E2840008BF7AC"
	strings:
		$1 = { 90 90 60 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 4E 28 40 00 8B F7 AC }
	condition:
		$1 at pe.entry_point
}

rule execryptor_uv_01 {
	meta:
		tool = "P"
		name = "EXECryptor"
		pattern = "83EC045053E801000000CC588BD8402D????????2D????5F0005????5F00803BCC7519C60300BB0010000068????????68????????5350E80A00000083C0"
	strings:
		$1 = { 83 EC 04 50 53 E8 01 00 00 00 CC 58 8B D8 40 2D ?? ?? ?? ?? 2D ?? ?? 5F 00 05 ?? ?? 5F 00 80 3B CC 75 19 C6 03 00 BB 00 10 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 50 E8 0A 00 00 00 83 C0 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_uv_02 {
	meta:
		tool = "P"
		name = "EXECryptor"
		pattern = "E8??????0005????????FFE0E8??????0005????0000FFE0E8??????00"
	strings:
		$1 = { E8 ?? ?? ?? 00 05 ?? ?? ?? ?? FF E0 E8 ?? ?? ?? 00 05 ?? ?? 00 00 FF E0 E8 ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_uv_03 {
	meta:
		tool = "P"
		name = "EXECryptor"
		pattern = "E8??????FF05????0000FFE0E8??????FF05????0000FFE0E8??????00"
	strings:
		$1 = { E8 ?? ?? ?? FF 05 ?? ?? 00 00 FF E0 E8 ?? ?? ?? FF 05 ?? ?? 00 00 FF E0 E8 ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_uv_04 {
	meta:
		tool = "P"
		name = "EXECryptor"
		pattern = "E9??????????????????????????????????????????????83EC0C535657E8"
	strings:
		$1 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 EC 0C 53 56 57 E8 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_uv_05 {
	meta:
		tool = "P"
		name = "EXECryptor"
		pattern = "E9??????????????????????????????????????????????83EC10535657E8"
	strings:
		$1 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 EC 10 53 56 57 E8 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_uv_06 {
	meta:
		tool = "P"
		name = "EXECryptor"
		pattern = "E9??????????????????????????????????????????????8A06??????470?DB75078B1E83EEFC"
	strings:
		$1 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 ?? ?? ?? 47 0? DB 75 07 8B 1E 83 EE FC }
	condition:
		$1 at pe.entry_point
}

rule execryptor_uv_07 {
	meta:
		tool = "P"
		name = "EXECryptor"
		pattern = "E9????????669C60508BD803006854BC00006A00FF50148BCC"
	strings:
		$1 = { E9 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }
	condition:
		$1 at pe.entry_point
}

rule execryptor_uv_08 {
	meta:
		tool = "P"
		name = "EXECryptor"
		pattern = "E824??????8B4C240CC70117??01??C781B8??????????????31C08941"
	strings:
		$1 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_13045 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "1.3.0.45"
		pattern = "E824??????8B4C240CC70117??01??C781??????????????31C089411489411880A1"
	strings:
		$1 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_151_153 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "1.5.1 - 1.5.3"
		pattern = "E824??????8B4C240CC70117??01??C781B8??????????????31C089411489411880A1C1??????FEC331C064FF30648920CCC3"
	strings:
		$1 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 C1 ?? ?? ?? FE C3 31 C0 64 FF 30 64 89 20 CC C3 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_20_21 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.0, 2.1"
		pattern = "558BEC83C4F4565753BE????????B80000????8945FC89C28B460C09C00F84??00000001D089C350FF1594??????09C00F850F00000053FF1598??????09C00F84??0000008945F86A008F45F48B0609C08B55FC0F85030000008B461001D00345F48B188B7E1001D7037DF409DB0F84??000000F7C3000000800F85040000008D5C130281E3FFFFFF??53FF75F8FF159C??????09C00F84??00000089078345F404E9A6FFFFFF"
	strings:
		$1 = { 55 8B EC 83 C4 F4 56 57 53 BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01 D0 03 45 F4 8B 18 8B 7E 10 01 D7 03 7D F4 09 DB 0F 84 ?? 00 00 00 F7 C3 00 00 00 80 0F 85 04 00 00 00 8D 5C 13 02 81 E3 FF FF FF ?? 53 FF 75 F8 FF 15 9C ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 07 83 45 F4 04 E9 A6 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule execryptor_20_21_iat {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.0, 2.1 protected IAT"
		pattern = "A4??????00000000FFFFFFFF3C??????94??????D8??????00000000FFFFFFFFB8??????D4??????00000000000000000000000000000000000000006B65726E656C33322E646C6C0000000000004765744D6F64756C6548616E646C6541000000004C6F61644C696272617279410000000047657450726F63416464726573730000000000004578697450726F63657373000000??????????????????????????????????????0060??????70??????84??????000000007573657233322E646C6C000000004D657373616765426F7841"
	strings:
		$1 = { A4 ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? 94 ?? ?? ?? D8 ?? ?? ?? 00 00 00 00 FF FF FF FF B8 ?? ?? ?? D4 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 60 ?? ?? ?? 70 ?? ?? ?? 84 ?? ?? ?? 00 00 00 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_2117 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.1.17"
		pattern = "BE????????B80000????8945FC89C28B460C09C00F84??00000001D089C350FF1594??????09C00F850F00000053FF1598??????09C00F84??0000008945F86A008F45F48B0609C08B55FC0F85030000008B461001D00345F48B188B7E1001D7037DF409DB0F84??000000F7C3000000800F85040000008D5C130281E3FFFFFF7F53FF75F8FF159C??????09C00F84??00000089078345F404E9A6FFFFFF"
	strings:
		$1 = { BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01 D0 03 45 F4 8B 18 8B 7E 10 01 D7 03 7D F4 09 DB 0F 84 ?? 00 00 00 F7 C3 00 00 00 80 0F 85 04 00 00 00 8D 5C 13 02 81 E3 FF FF FF 7F 53 FF 75 F8 FF 15 9C ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 07 83 45 F4 04 E9 A6 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule execryptor_21x_01 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.1.x"
		pattern = "83C6148B55FCE9??FFFFFF"
	strings:
		$1 = { 83 C6 14 8B 55 FC E9 ?? FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule execryptor_21x_02 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.1.x"
		pattern = "E9????????669C60508D88????????8D900416????8BDC8BE1"
	strings:
		$1 = { E9 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_224_01 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.2.4"
		pattern = "6B65726E656C33322E646C6C0000000000004765744D6F64756C6548616E646C6541000000004C6F61644C696272617279410000000047657450726F63416464726573730000000000004578697450726F6365737300000000005669727475616C416C6C6F63000000005669727475616C46726565000000"
	strings:
		$1 = { 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_224_02 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.2.4"
		pattern = "E8F7FEFFFF05????0000FFE0E8EBFEFFFF05????0000FFE0E8??000000"
	strings:
		$1 = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 ?? 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_226_min_prot_01 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.2.6 minimum protection"
		pattern = "5068????????5881E0????????E9??????00870C2459E8??????008945F8E9????????0F83??????00E9????????8714245A5768????????E9????????5881C0????????2B05????????81C8????????81E0????????E9??????00C3E9????????C3BF????????81CB????????BA????????52E9??????00E8??????00E9??????00E9????????8734245E668B006625????E9????????8BCD870C248BEC5189EC5D8B05????????09C0E9????????5981C1????????C1C1??230D????????81F9????????E9????????C3E9??????0013D00BF9E9????????51E8????????8B64240831C0648F05000000005AE9????????3CA40F85??????008B45FC668138????0F8405000000E9????????0F84????????E9????????873C245F31DB31C931D268????????E9????????8945FC33C08945F4837DFC00E9????????53528BD187142481C0????????0F88????????3BCB"
	strings:
		$1 = { 50 68 ?? ?? ?? ?? 58 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 E8 ?? ?? ?? 00 89 45 F8 E9 ?? ?? ?? ?? 0F 83 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 14 24 5A 57 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 58 81 C0 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? 81 C8 ?? ?? ?? ?? 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? ?? C3 BF ?? ?? ?? ?? 81 CB ?? ?? ?? ?? BA ?? ?? ?? ?? 52 E9 ?? ?? ?? 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? 00 E9 ?? ?? ?? ?? 87 34 24 5E 66 8B 00 66 25 ?? ?? E9 ?? ?? ?? ?? 8B CD 87 0C 24 8B EC 51 89 EC 5D 8B 05 ?? ?? ?? ?? 09 C0 E9 ?? ?? ?? ?? 59 81 C1 ?? ?? ?? ?? C1 C1 ?? 23 0D ?? ?? ?? ?? 81 F9 ?? ?? ?? ?? E9 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 13 D0 0B F9 E9 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 8B 64 24 08 31 C0 64 8F 05 00 00 00 00 5A E9 ?? ?? ?? ?? 3C A4 0F 85 ?? ?? ?? 00 8B 45 FC 66 81 38 ?? ?? 0F 84 05 00 00 00 E9 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 3C 24 5F 31 DB 31 C9 31 D2 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 89 45 FC 33 C0 89 45 F4 83 7D FC 00 E9 ?? ?? ?? ?? 53 52 8B D1 87 14 24 81 C0 ?? ?? ?? ?? 0F 88 ?? ?? ?? ?? 3B CB }
	condition:
		$1 at pe.entry_point
}

rule execryptor_226_min_prot_02 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.2.6 minimum protection"
		pattern = "508BC687042468????????5EE9????????85C8E9????????81C3????????0F81??????0081FA????????33D0E9??????000F8D??????0081D5????????F7D10B15????????C1C2??81C2????????9DE9????????C1E2??C1E8??81EA????????13DA81E9????????8704248BC8E9????????558BEC83C4F88945FC8B45FC8945F88B4508E9????????8B45E0C60000FF45E4E9????????FF45E4E9??????00F7D30F81????????E9????????8734245E8B45F4E8??????008B45F48BE55DC3E9"
	strings:
		$1 = { 50 8B C6 87 04 24 68 ?? ?? ?? ?? 5E E9 ?? ?? ?? ?? 85 C8 E9 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 0F 81 ?? ?? ?? 00 81 FA ?? ?? ?? ?? 33 D0 E9 ?? ?? ?? 00 0F 8D ?? ?? ?? 00 81 D5 ?? ?? ?? ?? F7 D1 0B 15 ?? ?? ?? ?? C1 C2 ?? 81 C2 ?? ?? ?? ?? 9D E9 ?? ?? ?? ?? C1 E2 ?? C1 E8 ?? 81 EA ?? ?? ?? ?? 13 DA 81 E9 ?? ?? ?? ?? 87 04 24 8B C8 E9 ?? ?? ?? ?? 55 8B EC 83 C4 F8 89 45 FC 8B 45 FC 89 45 F8 8B 45 08 E9 ?? ?? ?? ?? 8B 45 E0 C6 00 00 FF 45 E4 E9 ?? ?? ?? ?? FF 45 E4 E9 ?? ?? ?? 00 F7 D3 0F 81 ?? ?? ?? ?? E9 ?? ?? ?? ?? 87 34 24 5E 8B 45 F4 E8 ?? ?? ?? 00 8B 45 F4 8B E5 5D C3 E9 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_22_23_compressed_code {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.2, 2.3 compressed code"
		pattern = "E80000000058??????????8B1C2481EB????????B8????????506A046800100000506A00B8C4??????8B0418FFD059BA????????01DA52535089C789D6FCF3A4B9????????01D9FFD1588B1C2468008000006A0050"
	strings:
		$1 = { E8 00 00 00 00 58 ?? ?? ?? ?? ?? 8B 1C 24 81 EB ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 6A 04 68 00 10 00 00 50 6A 00 B8 C4 ?? ?? ?? 8B 04 18 FF D0 59 BA ?? ?? ?? ?? 01 DA 52 53 50 89 C7 89 D6 FC F3 A4 B9 ?? ?? ?? ?? 01 D9 FF D1 58 8B 1C 24 68 00 80 00 00 6A 00 50 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_22_23_iat {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.2, 2.3 protected IAT"
		pattern = "CC??????00000000FFFFFFFF3C??????B4??????08??????00000000FFFFFFFFE8??????04??????00000000000000000000000000000000000000006B65726E656C33322E646C6C0000000000004765744D6F64756C6548616E646C6541000000004C6F61644C696272617279410000000047657450726F63416464726573730000000000004578697450726F6365737300000000005669727475616C416C6C6F63000000005669727475616C46726565000000????????????????????????????????????????????????4C??????60??????70??????84??????94??????A4??????000000007573657233322E646C6C000000004D657373616765426F78"
	strings:
		$1 = { CC ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? B4 ?? ?? ?? 08 ?? ?? ?? 00 00 00 00 FF FF FF FF E8 ?? ?? ?? 04 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4C ?? ?? ?? 60 ?? ?? ?? 70 ?? ?? ?? 84 ?? ?? ?? 94 ?? ?? ?? A4 ?? ?? ?? 00 00 00 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 4D 65 73 73 61 67 65 42 6F 78 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_22x_24x {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.2x - 2.4x"
		pattern = "E8????????05????????FFE0E8????????05????????FFE0E804000000FFFFFFFF5EC3"
	strings:
		$1 = { E8 ?? ?? ?? ?? 05 ?? ?? ?? ?? FF E0 E8 ?? ?? ?? ?? 05 ?? ?? ?? ?? FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_22x {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.2x"
		pattern = "FFE0E804000000FFFFFFFF5EC300"
	strings:
		$1 = { FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 00 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_239_compressed_res_01 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.3.9 compressed resources"
		pattern = "5168????????5981F1123CCB98E9532C0000F7D7E9EB6000008345F802E9E3360000F645F8200F841E21000055E980620000870C248BE9????????000023C181E9????????57E9ED0000000F88????????E92C0D000081EDBB43CB79C1E01CE99E1400000B15????????81E22A707F4981C29D83123BE80C500000E9A0160000595BC364FF350000000064892500000000E841420000E99333000031DB89D8595BC3A1????????8A002C99E9823000000F8A????????B80100000031D20FA225FF0F0000E9722100000F86570B0000E9????????C1C003E8F0360000E9410A000081F7B36E85EA81C7????????873C24E9745200000F8E????????E85E37000068B17496135AE9A104000081D149C01227E9504E0000C1C81B1BC381E19636E5"
	strings:
		$1 = { 51 68 ?? ?? ?? ?? 59 81 F1 12 3C CB 98 E9 53 2C 00 00 F7 D7 E9 EB 60 00 00 83 45 F8 02 E9 E3 36 00 00 F6 45 F8 20 0F 84 1E 21 00 00 55 E9 80 62 00 00 87 0C 24 8B E9 ?? ?? ?? ?? 00 00 23 C1 81 E9 ?? ?? ?? ?? 57 E9 ED 00 00 00 0F 88 ?? ?? ?? ?? E9 2C 0D 00 00 81 ED BB 43 CB 79 C1 E0 1C E9 9E 14 00 00 0B 15 ?? ?? ?? ?? 81 E2 2A 70 7F 49 81 C2 9D 83 12 3B E8 0C 50 00 00 E9 A0 16 00 00 59 5B C3 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 41 42 00 00 E9 93 33 00 00 31 DB 89 D8 59 5B C3 A1 ?? ?? ?? ?? 8A 00 2C 99 E9 82 30 00 00 0F 8A ?? ?? ?? ?? B8 01 00 00 00 31 D2 0F A2 25 FF 0F 00 00 E9 72 21 00 00 0F 86 57 0B 00 00 E9 ?? ?? ?? ?? C1 C0 03 E8 F0 36 00 00 E9 41 0A 00 00 81 F7 B3 6E 85 EA 81 C7 ?? ?? ?? ?? 87 3C 24 E9 74 52 00 00 0F 8E ?? ?? ?? ?? E8 5E 37 00 00 68 B1 74 96 13 5A E9 A1 04 00 00 81 D1 49 C0 12 27 E9 50 4E 00 00 C1 C8 1B 1B C3 81 E1 96 36 E5 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_239_compressed_res_02 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.3.9 compressed resources"
		pattern = "5068????????58C1C00FE9??????00870424588945FCE9??????FFFF05????????E9??????00C1C318E9????????8B55080942F8E9??????FF837DF0010F85????????E9??????008734245E8B45FC33D2568BF2E9??????00BA????????E8??????00A3????????C3E9??????00C383C404C3E9??????FF64FF350000000064892500000000E8??????00E9??????FFC1C20381CA????????81C2????????03C25AE9??????FF81E7????????81EF????????81C7????????8907E9????????0F89????????8714245A50C1C810"
	strings:
		$1 = { 50 68 ?? ?? ?? ?? 58 C1 C0 0F E9 ?? ?? ?? 00 87 04 24 58 89 45 FC E9 ?? ?? ?? FF FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 18 E9 ?? ?? ?? ?? 8B 55 08 09 42 F8 E9 ?? ?? ?? FF 83 7D F0 01 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 34 24 5E 8B 45 FC 33 D2 56 8B F2 E9 ?? ?? ?? 00 BA ?? ?? ?? ?? E8 ?? ?? ?? 00 A3 ?? ?? ?? ?? C3 E9 ?? ?? ?? 00 C3 83 C4 04 C3 E9 ?? ?? ?? FF 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 ?? ?? ?? 00 E9 ?? ?? ?? FF C1 C2 03 81 CA ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 03 C2 5A E9 ?? ?? ?? FF 81 E7 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 81 C7 ?? ?? ?? ?? 89 07 E9 ?? ?? ?? ?? 0F 89 ?? ?? ?? ?? 87 14 24 5A 50 C1 C8 10 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_239_min_prot_01 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.3.9 minimum protection"
		pattern = "68????????E9??????FF50C1C8188905????????C3C1C01851E9??????FF84C00F846AF9FFFFE9??????FFC3E9??????FFE8CFE9FFFFB801000000E9??????FF2BD068A03680D45981C96498FF99E9??????FF84C00F848EECFFFFE9??????FFC3873C245F8B000345FC83C018E9??????FF870C2459B801000000D3E023D0E9021800000F8DDB000000C1E814E9CA0000009D870C2459871C2468AE73B996E9C51000000F8A????????E9??????FF81FDF5FF8F07E94F100000C3E95E120000873C24E9??????FFE8??????FF833D????????000F85????????8D55ECB8????????E9??????FFE8A71A0000E82ACBFFFFE9??????FFC3E9??????FF598945E0"
	strings:
		$1 = { 68 ?? ?? ?? ?? E9 ?? ?? ?? FF 50 C1 C8 18 89 05 ?? ?? ?? ?? C3 C1 C0 18 51 E9 ?? ?? ?? FF 84 C0 0F 84 6A F9 FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF E8 CF E9 FF FF B8 01 00 00 00 E9 ?? ?? ?? FF 2B D0 68 A0 36 80 D4 59 81 C9 64 98 FF 99 E9 ?? ?? ?? FF 84 C0 0F 84 8E EC FF FF E9 ?? ?? ?? FF C3 87 3C 24 5F 8B 00 03 45 FC 83 C0 18 E9 ?? ?? ?? FF 87 0C 24 59 B8 01 00 00 00 D3 E0 23 D0 E9 02 18 00 00 0F 8D DB 00 00 00 C1 E8 14 E9 CA 00 00 00 9D 87 0C 24 59 87 1C 24 68 AE 73 B9 96 E9 C5 10 00 00 0F 8A ?? ?? ?? ?? E9 ?? ?? ?? FF 81 FD F5 FF 8F 07 E9 4F 10 00 00 C3 E9 5E 12 00 00 87 3C 24 E9 ?? ?? ?? FF E8 ?? ?? ?? FF 83 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 8D 55 EC B8 ?? ?? ?? ?? E9 ?? ?? ?? FF E8 A7 1A 00 00 E8 2A CB FF FF E9 ?? ?? ?? FF C3 E9 ?? ?? ?? FF 59 89 45 E0 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_239_min_prot_02 {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.3.9 minimum protection"
		pattern = "5168????????872C248BCD5D81E1????????E9??????008945F85168????????5981F1????????0B0D????????81E9????????E9??????0081C2????????E8??????00870C245951648B05300000008B400C8B400CE9??????00F7D62BD5E9??????00873C248BCF5F8714241BCAE9??????0083C40868????????E9??????00C3E9??????00E9??????00508BC58704248BEC510F88??????00FF05????????E9??????00870C245999030424E9??????00C381D5????????9CE9??????0081FA????????E9??????00C1C31581CB????????81F3????????81C3????????87"
	strings:
		$1 = { 51 68 ?? ?? ?? ?? 87 2C 24 8B CD 5D 81 E1 ?? ?? ?? ?? E9 ?? ?? ?? 00 89 45 F8 51 68 ?? ?? ?? ?? 59 81 F1 ?? ?? ?? ?? 0B 0D ?? ?? ?? ?? 81 E9 ?? ?? ?? ?? E9 ?? ?? ?? 00 81 C2 ?? ?? ?? ?? E8 ?? ?? ?? 00 87 0C 24 59 51 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C E9 ?? ?? ?? 00 F7 D6 2B D5 E9 ?? ?? ?? 00 87 3C 24 8B CF 5F 87 14 24 1B CA E9 ?? ?? ?? 00 83 C4 08 68 ?? ?? ?? ?? E9 ?? ?? ?? 00 C3 E9 ?? ?? ?? 00 E9 ?? ?? ?? 00 50 8B C5 87 04 24 8B EC 51 0F 88 ?? ?? ?? 00 FF 05 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 99 03 04 24 E9 ?? ?? ?? 00 C3 81 D5 ?? ?? ?? ?? 9C E9 ?? ?? ?? 00 81 FA ?? ?? ?? ?? E9 ?? ?? ?? 00 C1 C3 15 81 CB ?? ?? ?? ?? 81 F3 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 87 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_2xx {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.x.x"
		pattern = "A4????0000000000FFFFFFFF3C????0094????00D8????0000000000FFFFFFFF"
	strings:
		$1 = { A4 ?? ?? 00 00 00 00 00 FF FF FF FF 3C ?? ?? 00 94 ?? ?? 00 D8 ?? ?? 00 00 00 00 00 FF FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule execryptor_2xx_compressed_res {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.x.x compressed resources"
		pattern = "56575331DB89C689D70FB60689C283E01FC1EA05742D4A74158D5C130246C1E00889FA0FB60E4629CA4A29C2EB32C1E3058D5C03044689FA0FB70E29CA4A83C602EB1DC1E3044689C183E10F01CBC1E80573074389F201DEEB0685DB740EEBA95689D689D9F3A431DB5EEB9D89F05B5F5EC3"
	strings:
		$1 = { 56 57 53 31 DB 89 C6 89 D7 0F B6 06 89 C2 83 E0 1F C1 EA 05 74 2D 4A 74 15 8D 5C 13 02 46 C1 E0 08 89 FA 0F B6 0E 46 29 CA 4A 29 C2 EB 32 C1 E3 05 8D 5C 03 04 46 89 FA 0F B7 0E 29 CA 4A 83 C6 02 EB 1D C1 E3 04 46 89 C1 83 E1 0F 01 CB C1 E8 05 73 07 43 89 F2 01 DE EB 06 85 DB 74 0E EB A9 56 89 D6 89 D9 F3 A4 31 DB 5E EB 9D 89 F0 5B 5F 5E C3 }
	condition:
		$1 at pe.entry_point
}

rule execryptor_2xx_max_compressed_res {
	meta:
		tool = "P"
		name = "EXECryptor"
		version = "2.x.x max. compressed resources"
		pattern = "558BEC83C4ECFC5357568945FC8955F889C689D766813E4A430F852301000083C60AC745F40800000031DBBA000000804331C0E811010000730E8B4DF0E81F0100000245EFAAEBE9E8FC0000000F8297000000E8F1000000735BB904000000E8FD0000004874DE0F89C7000000E8D7000000731B55BD00010000E8D70000008807474D75F5E8BF00000072E95DEBA2B901000000E8C800000083C0078945F0C645EF0083F8087489E8A90000008845EFE97CFFFFFFB907000000E8A200000050"
	strings:
		$1 = { 55 8B EC 83 C4 EC FC 53 57 56 89 45 FC 89 55 F8 89 C6 89 D7 66 81 3E 4A 43 0F 85 23 01 00 00 83 C6 0A C7 45 F4 08 00 00 00 31 DB BA 00 00 00 80 43 31 C0 E8 11 01 00 00 73 0E 8B 4D F0 E8 1F 01 00 00 02 45 EF AA EB E9 E8 FC 00 00 00 0F 82 97 00 00 00 E8 F1 00 00 00 73 5B B9 04 00 00 00 E8 FD 00 00 00 48 74 DE 0F 89 C7 00 00 00 E8 D7 00 00 00 73 1B 55 BD 00 01 00 00 E8 D7 00 00 00 88 07 47 4D 75 F5 E8 BF 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 C8 00 00 00 83 C0 07 89 45 F0 C6 45 EF 00 83 F8 08 74 89 E8 A9 00 00 00 88 45 EF E9 7C FF FF FF B9 07 00 00 00 E8 A2 00 00 00 50 }
	condition:
		$1 at pe.entry_point
}

rule exejoiner {
	meta:
		tool = "P"
		name = "ExeJoiner"
		pattern = "A114A14000C1E002A318A140"
	strings:
		$1 = { A1 14 A1 40 00 C1 E0 02 A3 18 A1 40 }
	condition:
		$1 at pe.entry_point
}

rule exejoiner_10_01 {
	meta:
		tool = "P"
		name = "ExeJoiner"
		version = "1.0"
		pattern = "68001040006804010000E8390300000500104000C6005C680401000068041140006A00E81A0300006A0068800000006A036A006A0168000000806804114000E8EC02000083F8FF0F8483020000A3081240006A0050E8E202000083F8FF0F846D020000A30C1240008BD883EB046A006A0053FF3508124000E8E30200006A00683C1240006A04681E124000FF3508124000E8C402000083EB046A006A0053FF3508124000E8B702"
	strings:
		$1 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50 E8 E2 02 00 00 83 F8 FF 0F 84 6D 02 00 00 A3 0C 12 40 00 8B D8 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 E8 E3 02 00 00 6A 00 68 3C 12 40 00 6A 04 68 1E 12 40 00 FF 35 08 12 40 00 E8 C4 02 00 00 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 E8 B7 02 }
	condition:
		$1 at pe.entry_point
}

rule exejoiner_10_02 {
	meta:
		tool = "P"
		name = "ExeJoiner"
		version = "1.0"
		pattern = "68001040006804010000E83903000005001040C6005C68????????68????????6A00E8"
	strings:
		$1 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8 }
	condition:
		$1 at pe.entry_point
}

rule exelock_10 {
	meta:
		tool = "P"
		name = "ExeLock"
		version = "1.0"
		pattern = "068CC88EC0BE????26????34??26????4681??????75??40B3??B3??F3"
	strings:
		$1 = { 06 8C C8 8E C0 BE ?? ?? 26 ?? ?? 34 ?? 26 ?? ?? 46 81 ?? ?? ?? 75 ?? 40 B3 ?? B3 ?? F3 }
	condition:
		$1 at pe.entry_point
}

rule exelock_15 {
	meta:
		tool = "P"
		name = "ExeLock"
		version = "1.5"
		pattern = "BA????BF????EB??EA????????79??7F??7E??1C??4878??E3??4514??5AE9"
	strings:
		$1 = { BA ?? ?? BF ?? ?? EB ?? EA ?? ?? ?? ?? 79 ?? 7F ?? 7E ?? 1C ?? 48 78 ?? E3 ?? 45 14 ?? 5A E9 }
	condition:
		$1 at pe.entry_point
}

rule exepack_531009 {
	meta:
		tool = "P"
		name = "EXEPACK"
		version = "5.31.009"
		pattern = "8BE88CC0"
	strings:
		$1 = { 8B E8 8C C0 }
	condition:
		$1 at pe.entry_point
}

rule epack_14 {
	meta:
		tool = "P"
		name = "Epack"
		version = "1.4"
		pattern = "33C08BC068????????68????????E8"
	strings:
		$1 = { 33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule exerefractor_01 {
	meta:
		tool = "P"
		name = "EXERefactor"
		version = "0.1"
		pattern = "558BEC81EC900B0000535657E9588C01005553434154494F4E"
	strings:
		$1 = { 55 8B EC 81 EC 90 0B 00 00 53 56 57 E9 58 8C 01 00 55 53 43 41 54 49 4F 4E }
	condition:
		$1 at pe.entry_point
}

rule exesafeguard_10 {
	meta:
		tool = "P"
		name = "ExeSafeguard"
		version = "1.0"
		pattern = "C05DEB4EEB47DF694E58DF5974F3EB01DF75EE9A599C81C1E2FFFFFFEB01DF9DFFE1E851E8EBFFFFFFDF223F9AC081ED19184000EB48EB47DF694E58DF5979EEEB01DF78E9DF599C81C1E5FFFFFF9DFFE1EB51E8EEFFFFFFDFBAA3223F9AC060EB4DEB47DF694E58DF5979F3EB01DF78EEDF599C81C1E5FFFFFF9DFFE1EB51E8EEFFFFFFE8BAA3223F9AC08DB5EE194000EB47EB47DF694E58DF597AEEEB01DF7BE9DF599C81C1"
	strings:
		$1 = { C0 5D EB 4E EB 47 DF 69 4E 58 DF 59 74 F3 EB 01 DF 75 EE 9A 59 9C 81 C1 E2 FF FF FF EB 01 DF 9D FF E1 E8 51 E8 EB FF FF FF DF 22 3F 9A C0 81 ED 19 18 40 00 EB 48 EB 47 DF 69 4E 58 DF 59 79 EE EB 01 DF 78 E9 DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE FF FF FF DF BA A3 22 3F 9A C0 60 EB 4D EB 47 DF 69 4E 58 DF 59 79 F3 EB 01 DF 78 EE DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE FF FF FF E8 BA A3 22 3F 9A C0 8D B5 EE 19 40 00 EB 47 EB 47 DF 69 4E 58 DF 59 7A EE EB 01 DF 7B E9 DF 59 9C 81 C1 }
	condition:
		$1 at pe.entry_point
}

rule exeshield_01b_06 {
	meta:
		tool = "P"
		name = "ExeShield"
		version = "0.1b - 0.6"
		pattern = "E8040000008360EB0C5DEB05"
	strings:
		$1 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 }
	condition:
		$1 at pe.entry_point
}

rule exeshield_01b_08 {
	meta:
		tool = "P"
		name = "ExeShield"
		version = "0.1b - 0.8"
		pattern = "E80400000083??????5DEB054555EB04??EBF9??C3E8000000005DEB01??81??????????EB02????8D??????????EB02????BA9F110000EB01??8D??????????8B09E814000000????????????????????????????????????????584050C3"
	strings:
		$1 = { E8 04 00 00 00 83 ?? ?? ?? 5D EB 05 45 55 EB 04 ?? EB F9 ?? C3 E8 00 00 00 00 5D EB 01 ?? 81 ?? ?? ?? ?? ?? EB 02 ?? ?? 8D ?? ?? ?? ?? ?? EB 02 ?? ?? BA 9F 11 00 00 EB 01 ?? 8D ?? ?? ?? ?? ?? 8B 09 E8 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58 40 50 C3 }
	condition:
		$1 at pe.entry_point
}

rule exeshield_17 {
	meta:
		tool = "P"
		name = "ExeShield"
		version = "1.7"
		pattern = "EB0668901F0600C39C60E80200000033C08BC483C004938BE38B5BFC81EB3F90"
	strings:
		$1 = { EB 06 68 90 1F 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 }
	condition:
		$1 at pe.entry_point
}

rule exeshield_27 {
	meta:
		tool = "P"
		name = "ExeShield"
		version = "2.7"
		pattern = "EB0668F4860600C39C60E8020000"
	strings:
		$1 = { EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00 }
	condition:
		$1 at pe.entry_point
}

rule exeshield_27b {
	meta:
		tool = "P"
		name = "ExeShield"
		version = "2.7b"
		pattern = "EB066840850600C39C60E80200000033C08BC483C004938BE38B5BFC81EB3F90400087DD8B85E690400001853390400066C7853090400090900185DA9040000185DE9040000185E2904000BB7B110000039DEA904000039DE6904000538BC38BFB2DAC9040008985AD9040008DB5AC904000B940040000F3A58BFBC3BD000000008BF783C65481C7FF10000056575756FF95DA9040008BC85E5F8BC1C1F902F3A503C883E103F3"
	strings:
		$1 = { EB 06 68 40 85 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 87 DD 8B 85 E6 90 40 00 01 85 33 90 40 00 66 C7 85 30 90 40 00 90 90 01 85 DA 90 40 00 01 85 DE 90 40 00 01 85 E2 90 40 00 BB 7B 11 00 00 03 9D EA 90 40 00 03 9D E6 90 40 00 53 8B C3 8B FB 2D AC 90 40 00 89 85 AD 90 40 00 8D B5 AC 90 40 00 B9 40 04 00 00 F3 A5 8B FB C3 BD 00 00 00 00 8B F7 83 C6 54 81 C7 FF 10 00 00 56 57 57 56 FF 95 DA 90 40 00 8B C8 5E 5F 8B C1 C1 F9 02 F3 A5 03 C8 83 E1 03 F3 }
	condition:
		$1 at pe.entry_point
}

rule exeshield_29 {
	meta:
		tool = "P"
		name = "ExeShield"
		version = "2.9"
		pattern = "60E8000000005D81ED0B204000B9EB0800008DBD532040008BF7AC??????F8"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC ?? ?? ?? F8 }
	condition:
		$1 at pe.entry_point
}

rule exeshield_36 {
	meta:
		tool = "P"
		name = "ExeShield"
		version = "3.6"
		pattern = "B8??????005064FF35000000006489250000000033C089085045436F6D706163743200CE1E42AFF8D6CCE9FBC84F1B227CB4C80DBD71A9C81F5FB1298F11738F00D18887A93F4D006C3CBFC080F7AD3523EB84826F8CB90AFCECE48297AE0F18D2471B65EA46A5FD3E9D752A628060F9B00DE1AC120E9D24D543CE9AD618BF22DA1F7276B0985BC264BCAED8"
	strings:
		$1 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F 8C B9 0A FC EC E4 82 97 AE 0F 18 D2 47 1B 65 EA 46 A5 FD 3E 9D 75 2A 62 80 60 F9 B0 0D E1 AC 12 0E 9D 24 D5 43 CE 9A D6 18 BF 22 DA 1F 72 76 B0 98 5B C2 64 BC AE D8 }
	condition:
		$1 at pe.entry_point
}

rule exeshield_36_protector {
	meta:
		tool = "P"
		name = "ExeShield"
		version = "3.6 Protector"
		pattern = "B8??????005064FF35000000006489250000000033C089085045436F6D706163743200CE1E42AFF8D6CC"
	strings:
		$1 = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC }
	condition:
		$1 at pe.entry_point
}

rule exeshield_uv {
	meta:
		tool = "P"
		name = "ExeShield"
		pattern = "65786573686C2E646C6CC05D00"
	strings:
		$1 = { 65 78 65 73 68 6C 2E 64 6C 6C C0 5D 00 }
	condition:
		$1 at pe.entry_point
}

rule exesmasher {
	meta:
		tool = "P"
		name = "ExeSmasher"
		pattern = "9CFE03??60BE????41??8DBE??10FFFF5783CDFFEB10"
	strings:
		$1 = { 9C FE 03 ?? 60 BE ?? ?? 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10 }
	condition:
		$1 at pe.entry_point
}

rule exesplitter_12 {
	meta:
		tool = "P"
		name = "ExeSplitter"
		version = "1.2"
		pattern = "E99502000064A1000000008338FF74048B00EBF78B4004C3558BECB8000000008B750881E60000FFFFB9060000005656E8B00000005E83F80175068BC6C9C2040081EE00000100E2E5C9C20400558BEC8B750C8BDE03763C8D76188D76608B3603F3568B762003F333D28BC68B3603F38B7D08B90E000000FCF3A60BC97502EB08"
	strings:
		$1 = { E9 95 02 00 00 64 A1 00 00 00 00 83 38 FF 74 04 8B 00 EB F7 8B 40 04 C3 55 8B EC B8 00 00 00 00 8B 75 08 81 E6 00 00 FF FF B9 06 00 00 00 56 56 E8 B0 00 00 00 5E 83 F8 01 75 06 8B C6 C9 C2 04 00 81 EE 00 00 01 00 E2 E5 C9 C2 04 00 55 8B EC 8B 75 0C 8B DE 03 76 3C 8D 76 18 8D 76 60 8B 36 03 F3 56 8B 76 20 03 F3 33 D2 8B C6 8B 36 03 F3 8B 7D 08 B9 0E 00 00 00 FC F3 A6 0B C9 75 02 EB 08 }
	condition:
		$1 at pe.entry_point
}

rule exesplitter_13_01 {
	meta:
		tool = "P"
		name = "ExeSplitter"
		version = "1.3"
		extra = "split only"
		pattern = "E8000000005D81ED08124000E866FEFFFF55508D9D81114000538D9D21114000536A08E876FFFFFF6A40680030000068000100006A00FF9589114000898561104000506800010000FF95851140008D856510400050FFB561104000FF958D1140006A0068800000006A026A00????????011F00FFB561104000FF95911140008985721040006A008D????????0050FFB5091040008D85F512400050FFB572104000FF9595114000FFB572104000FF95991140008D850D104000508D851D10400050B9070000006A00E2FC"
	strings:
		$1 = { E8 00 00 00 00 5D 81 ED 08 12 40 00 E8 66 FE FF FF 55 50 8D 9D 81 11 40 00 53 8D 9D 21 11 40 00 53 6A 08 E8 76 FF FF FF 6A 40 68 00 30 00 00 68 00 01 00 00 6A 00 FF 95 89 11 40 00 89 85 61 10 40 00 50 68 00 01 00 00 FF 95 85 11 40 00 8D 85 65 10 40 00 50 FF B5 61 10 40 00 FF 95 8D 11 40 00 6A 00 68 80 00 00 00 6A 02 6A 00 ?? ?? ?? ?? 01 1F 00 FF B5 61 10 40 00 FF 95 91 11 40 00 89 85 72 10 40 00 6A 00 8D ?? ?? ?? ?? 00 50 FF B5 09 10 40 00 8D 85 F5 12 40 00 50 FF B5 72 10 40 00 FF 95 95 11 40 00 FF B5 72 10 40 00 FF 95 99 11 40 00 8D 85 0D 10 40 00 50 8D 85 1D 10 40 00 50 B9 07 00 00 00 6A 00 E2 FC }
	condition:
		$1 at pe.entry_point
}

rule exesplitter_13_02 {
	meta:
		tool = "P"
		name = "ExeSplitter"
		version = "1.3"
		extra = "split only"
		pattern = "E9FE010000??????????????000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000073766345723031312E746D7000000000000000000064A1300000008B400C8B400C8B0085C00F845F0200008B483080396B740780394B7402EBE780790C337402EBDF8B4018C3"
	strings:
		$1 = { E9 FE 01 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 73 76 63 45 72 30 31 31 2E 74 6D 70 00 00 00 00 00 00 00 00 00 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 85 C0 0F 84 5F 02 00 00 8B 48 30 80 39 6B 74 07 80 39 4B 74 02 EB E7 80 79 0C 33 74 02 EB DF 8B 40 18 C3 }
	condition:
		$1 at pe.entry_point
}

rule exesplitter_13_03 {
	meta:
		tool = "P"
		name = "ExeSplitter"
		version = "1.3"
		extra = "split + crypt"
		pattern = "151005231456575748120B1666666666666666666602C756666666ED266AED266AED66E3A669E239646666ED2E56E65F0D1261E65F2D12648D81E61F6A5512648DB9ED267EA533ED8A8D69210312361409052702021403151527ED2B6AED136EEDB865105AEB107EEB1006ED50659530ED1046659555B4EDA0ED50659537ED2B6AEBDFAB7626663FDF686666669A95C06DAF1364"
	strings:
		$1 = { 15 10 05 23 14 56 57 57 48 12 0B 16 66 66 66 66 66 66 66 66 66 02 C7 56 66 66 66 ED 26 6A ED 26 6A ED 66 E3 A6 69 E2 39 64 66 66 ED 2E 56 E6 5F 0D 12 61 E6 5F 2D 12 64 8D 81 E6 1F 6A 55 12 64 8D B9 ED 26 7E A5 33 ED 8A 8D 69 21 03 12 36 14 09 05 27 02 02 14 03 15 15 27 ED 2B 6A ED 13 6E ED B8 65 10 5A EB 10 7E EB 10 06 ED 50 65 95 30 ED 10 46 65 95 55 B4 ED A0 ED 50 65 95 37 ED 2B 6A EB DF AB 76 26 66 3F DF 68 66 66 66 9A 95 C0 6D AF 13 64 }
	condition:
		$1 at pe.entry_point
}

rule exesplitter_13_04 {
	meta:
		tool = "P"
		name = "ExeSplitter"
		version = "1.3"
		extra = "split + crypt"
		pattern = "E8000000005D81ED05104000B9????????8D851D10400080306640E2FA8F98676666??????????????66"
	strings:
		$1 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 B9 ?? ?? ?? ?? 8D 85 1D 10 40 00 80 30 66 40 E2 FA 8F 98 67 66 66 ?? ?? ?? ?? ?? ?? ?? 66 }
	condition:
		$1 at pe.entry_point
}

rule expressor_10 {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.0"
		pattern = "E935140000E931130000E998120000E9EF0C0000E942130000E9E9020000E9EF0B0000E91B0D0000"
	strings:
		$1 = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00 }
	condition:
		$1 at pe.entry_point
}

rule expressor_11_01 {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.1"
		pattern = "E9????0000E9????0000E9??120000E9??0C0000E9????0000E9????0000E9????0000"
	strings:
		$1 = { E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 E9 ?? ?? 00 00 }
	condition:
		$1 at pe.entry_point
}

rule expressor_11_02 {
	meta:
		tool = "P"
		name = "eXpressor"
		version = "1.1"
		pattern = "E915130000E9F0120000E958120000E9AF0C0000E9AE020000E9B40B0000E9E00C0000"
	strings:
		$1 = { E9 15 13 00 00 E9 F0 12 00 00 E9 58 12 00 00 E9 AF 0C 00 00 E9 AE 02 00 00 E9 B4 0B 00 00 E9 E0 0C 00 00 }
	condition:
		$1 at pe.entry_point
}

rule expressor_12_01 {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.2"
		pattern = "457850722D762E312E322E"
	strings:
		$1 = { 45 78 50 72 2D 76 2E 31 2E 32 2E }
	condition:
		$1 at pe.entry_point
}

rule expressor_12_02 {
	meta:
		tool = "P"
		name = "eXpressor"
		version = "1.2"
		pattern = "558BEC81EC????????535657EB??457850722D76"
	strings:
		$1 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 EB ?? 45 78 50 72 2D 76 }
	condition:
		$1 at pe.entry_point
}

rule expressor_13_01 {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.3"
		pattern = "457850722D762E312E332E"
	strings:
		$1 = { 45 78 50 72 2D 76 2E 31 2E 33 2E }
	condition:
		$1 at pe.entry_point
}

rule expressor_13_02 {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.3"
		pattern = "558BEC83EC??535657EB0C457850722D762E312E332E2EB8????????2B05????????A3????????833D????????007413A1????????0305????????89????E9????0000C705"
	strings:
		$1 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E 2E B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 13 A1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 89 ?? ?? E9 ?? ?? 00 00 C7 05 }
	condition:
		$1 at pe.entry_point
}

rule expressor_13_03 {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.3"
		pattern = "558BEC83EC??535657EB0C45"
	strings:
		$1 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 }
	condition:
		$1 at pe.entry_point
}

rule expressor_14_01 {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.4"
		pattern = "558BEC83EC??535657EB0C457850722D762E312E342E2EB8"
	strings:
		$1 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 34 2E 2E B8 }
	condition:
		$1 at pe.entry_point
}

rule expressor_14_02 {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.4"
		pattern = "655850722D762E312E342E"
	strings:
		$1 = { 65 58 50 72 2D 76 2E 31 2E 34 2E }
	condition:
		$1 at pe.entry_point
}

rule expressor_145 {
	meta:
		tool = "P"
		name = "eXpressor"
		version = "1.4.5"
		pattern = "558BEC83EC585356578365DC00F3EB0C"
	strings:
		$1 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C }
	condition:
		$1 at pe.entry_point
}

rule expressor_1451_01 {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.4.5.1"
		pattern = "558BEC83EC585356578365DC00F3EB0C655850722D762E312E342E00A100??????0500??????A308??????A108??????B981??????2B4818890D0C??????833D10??????007416A108??????8B0D0C??????034814"
	strings:
		$1 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? ?? 05 00 ?? ?? ?? A3 08 ?? ?? ?? A1 08 ?? ?? ?? B9 81 ?? ?? ?? 2B 48 18 89 0D 0C ?? ?? ?? 83 3D 10 ?? ?? ?? 00 74 16 A1 08 ?? ?? ?? 8B 0D 0C ?? ?? ?? 03 48 14 }
	condition:
		$1 at pe.entry_point
}

rule expressor_1451_02 {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.4.5.1"
		pattern = "558BEC83EC585356578365DC00F3EB0C655850722D762E312E342E00A100????000500????00A308????00A108????00B981????002B4818890D0C????00833D"
	strings:
		$1 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 ?? ?? 00 05 00 ?? ?? 00 A3 08 ?? ?? 00 A1 08 ?? ?? 00 B9 81 ?? ?? 00 2B 48 18 89 0D 0C ?? ?? 00 83 3D }
	condition:
		$1 at pe.entry_point
}

rule expressor_150x_pack {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.5.0.x .Pack"
		pattern = "558BEC81EC????????53565783A5??????????F3EB0C655850722D762E312E352E00837D0C??75238B4508A3????????6A04680010000068200300006A00FF15????????A3????????EB04"
	strings:
		$1 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C ?? 75 23 8B 45 08 A3 ?? ?? ?? ?? 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? EB 04 }
	condition:
		$1 at pe.entry_point
}

rule expressor_150x_protection {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.5.0.x .Protection"
		pattern = "EB0168EB01????????83EC0C535657EB01??833D????????007408EB01E9E956010000EB02E8E9C705????????01000000EB01C2E8E2050000EB02DA9F68????????68????????B8????????FFD05959EB01C8EB0266F068????????E80E05000059EB01DD8365F400EB078B45F4408945F4837DF461731FEB02DA1A8B45F40F????????????3345F48B4DF488??????????EB01EBEB"
	strings:
		$1 = { EB 01 68 EB 01 ?? ?? ?? ?? 83 EC 0C 53 56 57 EB 01 ?? 83 3D ?? ?? ?? ?? 00 74 08 EB 01 E9 E9 56 01 00 00 EB 02 E8 E9 C7 05 ?? ?? ?? ?? 01 00 00 00 EB 01 C2 E8 E2 05 00 00 EB 02 DA 9F 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D0 59 59 EB 01 C8 EB 02 66 F0 68 ?? ?? ?? ?? E8 0E 05 00 00 59 EB 01 DD 83 65 F4 00 EB 07 8B 45 F4 40 89 45 F4 83 7D F4 61 73 1F EB 02 DA 1A 8B 45 F4 0F ?? ?? ?? ?? ?? ?? 33 45 F4 8B 4D F4 88 ?? ?? ?? ?? ?? EB 01 EB EB }
	condition:
		$1 at pe.entry_point
}

rule expressor_1601_full {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.6.0.1 .Full Support"
		pattern = "558BEC81EC7402000053565783A5C8FDFFFF00F3EB0C????????????????????????A1????????05????????A3????????A1????????8B400425????????85C0745C837D0C01752A8B4508A3????????833D??????????75196A04680010000068200300006A00FF??????????A3????????837D0C00750E833D??????????7405E9F40A0000833D??????????7405E9BB090000C705????????????????A1????????83786000751C6A106A00E8E819000059506A01E8DF19000059506A00FF15????????E827FFFFFFA3????????6A04680010000068800000006A00FF15????????8985E8FDFFFF68040100008D85F0FDFFFF50FF35????????FF15????????8D8405EFFDFFFF8985D4FDFFFF8B85D4FDFFFF0FBE0083F85C740F8B85D4FDFFFF488985D4FDFFFFEBE38B85D4FDFFFF408985D4FDFFFF8B85D4FDFFFF8D8DF0FDFFFF2BC18985ACFDFFFF8B8DACFDFFFF8DB5F0FDFFFF8DBDFCFEFFFF8BC1C1E902F3A58BC883E103F3A48B85ACFDFFFF80A405FDFEFFFF0083A5D8FDFFFF00A1????????8B400425????????85C07511A1????????8B400425????????85C07443E8110C00008985D8FDFFFFA1????????8B400425????????85C0742783BDD8FDFFFF00741E6A10FFB5D4FDFFFF6A18E8C318000059506A00FF15????????E98F090000"
	strings:
		$1 = { 55 8B EC 81 EC 74 02 00 00 53 56 57 83 A5 C8 FD FF FF 00 F3 EB 0C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 74 5C 83 7D 0C 01 75 2A 8B 45 08 A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 75 19 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF ?? ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 7D 0C 00 75 0E 83 3D ?? ?? ?? ?? ?? 74 05 E9 F4 0A 00 00 83 3D ?? ?? ?? ?? ?? 74 05 E9 BB 09 00 00 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 78 60 00 75 1C 6A 10 6A 00 E8 E8 19 00 00 59 50 6A 01 E8 DF 19 00 00 59 50 6A 00 FF 15 ?? ?? ?? ?? E8 27 FF FF FF A3 ?? ?? ?? ?? 6A 04 68 00 10 00 00 68 80 00 00 00 6A 00 FF 15 ?? ?? ?? ?? 89 85 E8 FD FF FF 68 04 01 00 00 8D 85 F0 FD FF FF 50 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D 84 05 EF FD FF FF 89 85 D4 FD FF FF 8B 85 D4 FD FF FF 0F BE 00 83 F8 5C 74 0F 8B 85 D4 FD FF FF 48 89 85 D4 FD FF FF EB E3 8B 85 D4 FD FF FF 40 89 85 D4 FD FF FF 8B 85 D4 FD FF FF 8D 8D F0 FD FF FF 2B C1 89 85 AC FD FF FF 8B 8D AC FD FF FF 8D B5 F0 FD FF FF 8D BD FC FE FF FF 8B C1 C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 85 AC FD FF FF 80 A4 05 FD FE FF FF 00 83 A5 D8 FD FF FF 00 A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 75 11 A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 74 43 E8 11 0C 00 00 89 85 D8 FD FF FF A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 74 27 83 BD D8 FD FF FF 00 74 1E 6A 10 FF B5 D4 FD FF FF 6A 18 E8 C3 18 00 00 59 50 6A 00 FF 15 ?? ?? ?? ?? E9 8F 09 00 00 }
	condition:
		$1 at pe.entry_point
}

rule expressor_1601_light {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.6.0.1 .Light"
		pattern = "558BEC81EC6802000053565783A5D0FDFFFF00F3EB0C????????????????????????A1????????05????????A3????????A1????????8378600075146A1068????????68????????6A00FF15????????E89CFFFFFFA3????????68040100008D85F0FDFFFF50FF35????????FF15????????8D8405EFFDFFFF8985DCFDFFFF8B85DCFDFFFF0FBE0083F85C740F8B85DCFDFFFF488985DCFDFFFFEBE38B85DCFDFFFF408985DCFDFFFF8B85DCFDFFFF8D8DF0FDFFFF2BC18985B4FDFFFF8B8DB4FDFFFF8DB5F0FDFFFF8DBDFCFEFFFF8BC1C1E902F3A58BC883E103F3A48B85B4FDFFFF80A405FDFEFFFF0083A5E0FDFFFF00A1????????8B400425????????85C07511A1????????8B4004250000000285C0742AE85B0600008985E0FDFFFFA1????????8B400425????????85C0740E83BDE0FDFFFF007405E934060000"
	strings:
		$1 = { 55 8B EC 81 EC 68 02 00 00 53 56 57 83 A5 D0 FD FF FF 00 F3 EB 0C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 78 60 00 75 14 6A 10 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? E8 9C FF FF FF A3 ?? ?? ?? ?? 68 04 01 00 00 8D 85 F0 FD FF FF 50 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D 84 05 EF FD FF FF 89 85 DC FD FF FF 8B 85 DC FD FF FF 0F BE 00 83 F8 5C 74 0F 8B 85 DC FD FF FF 48 89 85 DC FD FF FF EB E3 8B 85 DC FD FF FF 40 89 85 DC FD FF FF 8B 85 DC FD FF FF 8D 8D F0 FD FF FF 2B C1 89 85 B4 FD FF FF 8B 8D B4 FD FF FF 8D B5 F0 FD FF FF 8D BD FC FE FF FF 8B C1 C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 85 B4 FD FF FF 80 A4 05 FD FE FF FF 00 83 A5 E0 FD FF FF 00 A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 75 11 A1 ?? ?? ?? ?? 8B 40 04 25 00 00 00 02 85 C0 74 2A E8 5B 06 00 00 89 85 E0 FD FF FF A1 ?? ?? ?? ?? 8B 40 04 25 ?? ?? ?? ?? 85 C0 74 0E 83 BD E0 FD FF FF 00 74 05 E9 34 06 00 00 }
	condition:
		$1 at pe.entry_point
}

rule expressor_1601_protection {
	meta:
		tool = "P"
		name = "eXPressor"
		version = "1.6.0.1 .Protection "
		pattern = "EB01??EB01??558BEC83EC0C535657EB01??833D??????????7408EB01??E956010000EB02????C705????????????????EB01??E8E2050000EB02????68????????68????????B8????????FFD05959EB01??EB02????68????????E80E05000059EB01??8365F400EB078B45F4408945F4837DF461731FEB02????8B45F40FB6??????????3345F48B4DF48881????????EB01??EBD468????????68????????68????????FF35????????B8????????FFD083C4108945FCEB02????837DFC00750A6A00A1????????FF5014EB01??F3E8A0050000A1????????05????????8945F868????????68????????FF75FCE801000000??83042406C3"
	strings:
		$1 = { EB 01 ?? EB 01 ?? 55 8B EC 83 EC 0C 53 56 57 EB 01 ?? 83 3D ?? ?? ?? ?? ?? 74 08 EB 01 ?? E9 56 01 00 00 EB 02 ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? EB 01 ?? E8 E2 05 00 00 EB 02 ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D0 59 59 EB 01 ?? EB 02 ?? ?? 68 ?? ?? ?? ?? E8 0E 05 00 00 59 EB 01 ?? 83 65 F4 00 EB 07 8B 45 F4 40 89 45 F4 83 7D F4 61 73 1F EB 02 ?? ?? 8B 45 F4 0F B6 ?? ?? ?? ?? ?? 33 45 F4 8B 4D F4 88 81 ?? ?? ?? ?? EB 01 ?? EB D4 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF D0 83 C4 10 89 45 FC EB 02 ?? ?? 83 7D FC 00 75 0A 6A 00 A1 ?? ?? ?? ?? FF 50 14 EB 01 ?? F3 E8 A0 05 00 00 A1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 89 45 F8 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 75 FC E8 01 00 00 00 ?? 83 04 24 06 C3 }
	condition:
		$1 at pe.entry_point
}

rule ezip_10 {
	meta:
		tool = "P"
		name = "EZIP"
		version = "1.0"
		pattern = "E919320000E97C2A0000E919240000E9FF230000E91E2E0000E9882E0000E92C"
	strings:
		$1 = { E9 19 32 00 00 E9 7C 2A 00 00 E9 19 24 00 00 E9 FF 23 00 00 E9 1E 2E 00 00 E9 88 2E 00 00 E9 2C }
	condition:
		$1 at pe.entry_point
}

rule fakeninja_28_ad {
	meta:
		tool = "P"
		name = "FakeNinja"
		version = "2.8 anti debug"
		pattern = "64A118000000EB02C3118B4030EB010F0FB6400283F80174FEEB01E890C0FFFFEB03BDF4B564A1300000000FB640027401BA74E0500064A13000000083C0688B00EB0083F87074CFEB02EBFE9090900F3133C903C80F312BC13DFF0F000073EAE808000000C13DFF0F000074AAEB07E88B4030EB08EA64A118000000EBF2909090BA????????FFE264114000FF3584114000E8401100006A006A00FF3570114000FF3584114000E825110000FF"
	strings:
		$1 = { 64 A1 18 00 00 00 EB 02 C3 11 8B 40 30 EB 01 0F 0F B6 40 02 83 F8 01 74 FE EB 01 E8 90 C0 FF FF EB 03 BD F4 B5 64 A1 30 00 00 00 0F B6 40 02 74 01 BA 74 E0 50 00 64 A1 30 00 00 00 83 C0 68 8B 00 EB 00 83 F8 70 74 CF EB 02 EB FE 90 90 90 0F 31 33 C9 03 C8 0F 31 2B C1 3D FF 0F 00 00 73 EA E8 08 00 00 00 C1 3D FF 0F 00 00 74 AA EB 07 E8 8B 40 30 EB 08 EA 64 A1 18 00 00 00 EB F2 90 90 90 BA ?? ?? ?? ?? FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 11 00 00 6A 00 6A 00 FF 35 70 11 40 00 FF 35 84 11 40 00 E8 25 11 00 00 FF }
	condition:
		$1 at pe.entry_point
}

rule fakeninja_28_private {
	meta:
		tool = "P"
		name = "FakeNinja"
		version = "2.8 private"
		pattern = "400000C0????????????????????????????????????????????????000000000000000000000000400000C0??????????????????000000??????????000000????????00000000000000000000000017E5FF60"
	strings:
		$1 = { 40 00 00 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 17 E5 FF 60 }
	condition:
		$1 at pe.entry_point
}

rule fakeninja_28 {
	meta:
		tool = "P"
		name = "FakeNinja"
		version = "2.8"
		pattern = "BA????????FFE264114000FF3584114000E840"
	strings:
		$1 = { BA ?? ?? ?? ?? FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 }
	condition:
		$1 at pe.entry_point
}

rule feokt {
	meta:
		tool = "P"
		name = "Feokt"
		pattern = "8925A8114000BF??????0031C0B9??????0029F9FCF3AA??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????E8????0000BE????4000BF"
	strings:
		$1 = { 89 25 A8 11 40 00 BF ?? ?? ?? 00 31 C0 B9 ?? ?? ?? 00 29 F9 FC F3 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 BE ?? ?? 40 00 BF }
	condition:
		$1 at pe.entry_point
}

rule fileshield {
	meta:
		tool = "P"
		name = "FileShield"
		pattern = "501EEB??9000008BD8"
	strings:
		$1 = { 50 1E EB ?? 90 00 00 8B D8 }
	condition:
		$1 at pe.entry_point
}

rule flash_player {
	meta:
		tool = "P"
		name = "Flash Player"
		pattern = "83????56FF15????????8BF08A063C??75??8A????463C??74??84C074??8A????463C??75??80????75??46EB??3C??7E??8A"
	strings:
		$1 = { 83 ?? ?? 56 FF 15 ?? ?? ?? ?? 8B F0 8A 06 3C ?? 75 ?? 8A ?? ?? 46 3C ?? 74 ?? 84 C0 74 ?? 8A ?? ?? 46 3C ?? 75 ?? 80 ?? ?? 75 ?? 46 EB ?? 3C ?? 7E ?? 8A }
	condition:
		$1 at pe.entry_point
}

rule flash_player_80 {
	meta:
		tool = "P"
		name = "Flash Player"
		version = "8.0"
		pattern = "83????56FF15????????8BF08A063C??75??8A????463C??74??84C075??3C??75??46EB??3C??76??8DA4"
	strings:
		$1 = { 83 ?? ?? 56 FF 15 ?? ?? ?? ?? 8B F0 8A 06 3C ?? 75 ?? 8A ?? ?? 46 3C ?? 74 ?? 84 C0 75 ?? 3C ?? 75 ?? 46 EB ?? 3C ?? 76 ?? 8D A4 }
	condition:
		$1 at pe.entry_point
}

rule fishpe_101_shield_01 {
	meta:
		tool = "P"
		name = "FishPE"
		version = "1.01 shield"
		pattern = "558BEC83C4D05356578B451083C00C8B008945DC837DDC007508E8ADFFFFFF8945DCE8C1FEFFFF8B100355DC8955E483C0048B108955FC83C0048B108955F483C0048B108955F883C0048B108955F083C0048B108955EC83C0048B008945E88B45E48B5804035DE48BFB8B45E48B304E85F6722B46C745E000000000837B04007414"
	strings:
		$1 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 AD FF FF FF 89 45 DC E8 C1 FE FF FF 8B 10 03 55 DC 89 55 E4 83 C0 04 8B 10 89 55 FC 83 C0 04 8B 10 89 55 F4 83 C0 04 8B 10 89 55 F8 83 C0 04 8B 10 89 55 F0 83 C0 04 8B 10 89 55 EC 83 C0 04 8B 00 89 45 E8 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B 46 C7 45 E0 00 00 00 00 83 7B 04 00 74 14 }
	condition:
		$1 at pe.entry_point
}

rule fishpe_101_shield_02 {
	meta:
		tool = "P"
		name = "FishPE"
		version = "1.01 shield"
		pattern = "60E812FEFFFFC390090000002C000000????????C4030000BCA0000000400100????????0000000000000000000000000000000099000000008A0000001000002888000040??4B00000002000000A000001801000040??4C0000000C000000B00000380A000040??4E00000000000000C000004039000040??4E00000008000000000100C806000040"
	strings:
		$1 = { 60 E8 12 FE FF FF C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 28 88 00 00 40 ?? 4B 00 00 00 02 00 00 00 A0 00 00 18 01 00 00 40 ?? 4C 00 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 40 ?? 4E 00 00 00 00 00 00 00 C0 00 00 40 39 00 00 40 ?? 4E 00 00 00 08 00 00 00 00 01 00 C8 06 00 00 40 }
	condition:
		$1 at pe.entry_point
}

rule fishpe_102_packer {
	meta:
		tool = "P"
		name = "FishPE"
		version = "1.02 packer"
		pattern = "60E8070000006168????????C35E568B5602??????AD01D05B36894302663EC743FAEB0553AD01D089C3C743FC00100000C743F8008000008953F4AD01D08943F0AD01D0894310526A04FF73FCAD506A003EFF530889C56A04FF73FCAD506A003EFF530889C15A83EE08AD5055ADAD50AD01D0506A026A006A??5189CFFF531083C420FF73F86A0057FF530C"
	strings:
		$1 = { 60 E8 07 00 00 00 61 68 ?? ?? ?? ?? C3 5E 56 8B 56 02 ?? ?? ?? AD 01 D0 5B 36 89 43 02 66 3E C7 43 FA EB 05 53 AD 01 D0 89 C3 C7 43 FC 00 10 00 00 C7 43 F8 00 80 00 00 89 53 F4 AD 01 D0 89 43 F0 AD 01 D0 89 43 10 52 6A 04 FF 73 FC AD 50 6A 00 3E FF 53 08 89 C5 6A 04 FF 73 FC AD 50 6A 00 3E FF 53 08 89 C1 5A 83 EE 08 AD 50 55 AD AD 50 AD 01 D0 50 6A 02 6A 00 6A ?? 51 89 CF FF 53 10 83 C4 20 FF 73 F8 6A 00 57 FF 53 0C }
	condition:
		$1 at pe.entry_point
}

rule fishpe_10x_packer_01 {
	meta:
		tool = "P"
		name = "FishPE"
		version = "1.0x packer"
		pattern = "60E821000000EB18??????????????????????????????????????????????????????????????5E568B561C89F3"
	strings:
		$1 = { 60 E8 21 00 00 00 EB 18 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5E 56 8B 56 1C 89 F3 }
	condition:
		$1 at pe.entry_point
}

rule fishpe_10x_packer_02 {
	meta:
		tool = "P"
		name = "FishPE"
		version = "1.0x"
		pattern = "60E8????????C390090000002C000000????????C4030000BCA0000000400100????????0000000000000000000000000000000099000000008A000000100000????0000????????000002000000A0000018010000????????00000C000000B00000380A0000????????000000000000C0000040390000????????000008000000000100C8060000"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 ?? ?? 00 00 ?? ?? ?? ?? 00 00 02 00 00 00 A0 00 00 18 01 00 00 ?? ?? ?? ?? 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 C0 00 00 40 39 00 00 ?? ?? ?? ?? 00 00 08 00 00 00 00 01 00 C8 06 00 00 }
	condition:
		$1 at pe.entry_point
}

rule fishpe_104_10x_packer {
	meta:
		tool = "P"
		name = "FishPE"
		version = "1.04 - 1.0x packer"
		pattern = "60B8????????FFD05A0000????????0000000000????????????????000000005756535589E58B452001452450FC8B751801751C568B7514AD92528A4EFE83C8FFD3E0F7D05088F183C8FFD3E0F7D05000D189F783EC0C29C040505050505057AD89C1AD29F65683CBFFF3AB6A0559E89C020000E2F98D368D3F8B7DFC8B45F02B7D2021F88945E8"
	strings:
		$1 = { 60 B8 ?? ?? ?? ?? FF D0 5A 00 00 ?? ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 57 56 53 55 89 E5 8B 45 20 01 45 24 50 FC 8B 75 18 01 75 1C 56 8B 75 14 AD 92 52 8A 4E FE 83 C8 FF D3 E0 F7 D0 50 88 F1 83 C8 FF D3 E0 F7 D0 50 00 D1 89 F7 83 EC 0C 29 C0 40 50 50 50 50 50 57 AD 89 C1 AD 29 F6 56 83 CB FF F3 AB 6A 05 59 E8 9C 02 00 00 E2 F9 8D 36 8D 3F 8B 7D FC 8B 45 F0 2B 7D 20 21 F8 89 45 E8 }
	condition:
		$1 at pe.entry_point
}

rule fishpe_112_116_shield_01 {
	meta:
		tool = "P"
		name = "FishPE"
		version = "1.12, 1.16 shield"
		pattern = "558BEC83C4D05356578B451083C00C8B008945DC837DDC007508E8BDFEFFFF8945DCE8E1FDFFFF8B000345DC8945E4E8DCFEFFFF8BD8BA8E4E0EEC8BC3E82EFFFFFF8945F4BA044932D38BC3E81FFFFFFF8945F8BA54CAAF918BC3E810FFFFFF8945F0BAAC3306038BC3E801FFFFFF8945ECBA1BC646798BC3E8F2FEFFFF8945E8BAAAFC0D7C8BC3E8E3FEFFFF8945FC8B45E48B5804035DE48BFB8B45E48B304E85F6722B"
	strings:
		$1 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 BD FE FF FF 89 45 DC E8 E1 FD FF FF 8B 00 03 45 DC 89 45 E4 E8 DC FE FF FF 8B D8 BA 8E 4E 0E EC 8B C3 E8 2E FF FF FF 89 45 F4 BA 04 49 32 D3 8B C3 E8 1F FF FF FF 89 45 F8 BA 54 CA AF 91 8B C3 E8 10 FF FF FF 89 45 F0 BA AC 33 06 03 8B C3 E8 01 FF FF FF 89 45 EC BA 1B C6 46 79 8B C3 E8 F2 FE FF FF 89 45 E8 BA AA FC 0D 7C 8B C3 E8 E3 FE FF FF 89 45 FC 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B }
	condition:
		$1 at pe.entry_point
}

rule fishpe_112_116_shield_02 {
	meta:
		tool = "P"
		name = "FishPE"
		version = "1.12, 1.16 shield"
		pattern = "60E8EAFDFFFFFFD0C38D4000??0000002C000000??????00????0000??????0000????00??????00??????00??00000000????00????0000??00000000????0000100000??????0040??????0000????0000????00??????0040??????0000??000000????00????000040"
	strings:
		$1 = { 60 E8 EA FD FF FF FF D0 C3 8D 40 00 ?? 00 00 00 2C 00 00 00 ?? ?? ?? 00 ?? ?? 00 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 ?? ?? 00 ?? ?? 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 00 00 ?? ?? ?? 00 40 ?? ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 40 ?? ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 ?? ?? 00 00 40 }
	condition:
		$1 at pe.entry_point
}

rule fishpe_11x {
	meta:
		tool = "P"
		name = "FishPE"
		version = "1.1x"
		pattern = "504500004C010A00195E422A0000000000000000E0008E810B010219????????????????00000000????????????????????????????????001000000002000004000000000000000400000000000000????????000400000000000002000000000010000040000000001000001000000000000010000000????????????????????????????????????????????????00000000000000000000000000000000????????????????000000000000000000000000000000000000000000000000????????180000000000000000000000????????????????????????????????000000000000000000000000000000000000000000000000????????????????????????????????0000000000000000000000000000000000000000200000E0????????????????????????????????0000000000000000000000000000000000000000200000E0????????????????????????????????0000000000000000000000000000000000000000400000C0????????????????????????????????0000000000000000000000000000000000000000000000C0????????????????????????????????0000000000000000000000000000000000000000400000C0????????????????????????????????0000000000000000000000000000000000000000000000C0????????????????????????????????0000000000000000000000000000000000000000400000C0????????????????????????????????0000000000000000000000000000000000000000400000C2????????????????????????????????0000000000000000000000000000000000000000400000C0????????????????????????????????????????00040000000000000000000000000000E00000E0"
	strings:
		$1 = { 50 45 00 00 4C 01 0A 00 19 5E 42 2A 00 00 00 00 00 00 00 00 E0 00 8E 81 0B 01 02 19 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 04 00 00 00 00 00 00 02 00 00 00 00 00 10 00 00 40 00 00 00 00 10 00 00 10 00 00 00 00 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 18 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 00 E0 }
	condition:
		$1 at pe.entry_point
}

rule fixuppak_120_01 {
	meta:
		tool = "P"
		name = "FixupPak"
		version = "1.20"
		pattern = "55E8000000005D81ED????0000BE00??000003F5BA0000????2BD58BDD33C0AC3C00743D3C01740E3C02740E3C03740D03D82913EBE766ADEBF6ADEBF3AC0FB6C83C0074063C017409EB0A66AD0FB7C8EB03AD8BC8"
	strings:
		$1 = { 55 E8 00 00 00 00 5D 81 ED ?? ?? 00 00 BE 00 ?? 00 00 03 F5 BA 00 00 ?? ?? 2B D5 8B DD 33 C0 AC 3C 00 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F B6 C8 3C 00 74 06 3C 01 74 09 EB 0A 66 AD 0F B7 C8 EB 03 AD 8B C8 }
	condition:
		$1 at pe.entry_point
}

rule fixuppak_120_02 {
	meta:
		tool = "P"
		name = "FixupPak"
		version = "1.20"
		pattern = "55E8000000005D81ED????0000BE00??000003F5BA0000????2BD58BDD33C0AC3C00743D3C01740E3C02740E3C03740D03D82913EBE766ADEBF6ADEBF3AC0FB6C83C0074063C017409EB0A66AD0FB7C8EB03AD8BC8AC0FB6C003D82913E2FAEBBC8D85????00005DFFE000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	strings:
		$1 = { 55 E8 00 00 00 00 5D 81 ED ?? ?? 00 00 BE 00 ?? 00 00 03 F5 BA 00 00 ?? ?? 2B D5 8B DD 33 C0 AC 3C 00 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F B6 C8 3C 00 74 06 3C 01 74 09 EB 0A 66 AD 0F B7 C8 EB 03 AD 8B C8 AC 0F B6 C0 03 D8 29 13 E2 FA EB BC 8D 85 ?? ?? 00 00 5D FF E0 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule flash_projector {
	meta:
		tool = "P"
		name = "Flash Projector"
		pattern = "83EC4456FF15????????8BF08A063C22751C8A4601463C22740C84C074088A4601463C2275F4803E22750F46EB0C3C207E088A4601463C207FF88A0684C0740C3C207F088A46014684C075F48D442404C74424300000000050FF15"
	strings:
		$1 = { 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74 0C 3C 20 7F 08 8A 46 01 46 84 C0 75 F4 8D 44 24 04 C7 44 24 30 00 00 00 00 50 FF 15 }
	condition:
		$1 at pe.entry_point
}

rule flash_projector_30 {
	meta:
		tool = "P"
		name = "Flash Projector"
		version = "3.0"
		pattern = "558BEC83EC4456FF15941342008BF0B1228A063AC175138A4601463AC1740484C075F4380E750D46EB0A3C207E06"
	strings:
		$1 = { 55 8B EC 83 EC 44 56 FF 15 94 13 42 00 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E 06 }
	condition:
		$1 at pe.entry_point
}

rule flycrypter_10_01 {
	meta:
		tool = "P"
		name = "Fly-Crypter"
		version = "1.0"
		pattern = "53565755BB2C????44BE00304444BF20????44807B28007516833F0074118B1789D033D289178BE8FFD5833F0075EF833D04304444007406FF1558304444807B2802750A833E00750533C089430CFF1520304444807B28017605833E0074228B431085C0741BFF15183044448B53108B42103B4204740A85C0740650E82FFAFFFFFF1524304444807B28017503FF5324807B28007405E835FFFFFF833B007517833D10????44007406FF1510????448B0650E851FAFFFF8B03568BF08BFBB90B000000F3A55EE973FFFFFF5D5F5E5BC3A300304444E826FFFFFFC3"
	strings:
		$1 = { 53 56 57 55 BB 2C ?? ?? 44 BE 00 30 44 44 BF 20 ?? ?? 44 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 44 44 00 74 06 FF 15 58 30 44 44 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 20 30 44 44 80 7B 28 01 76 05 83 3E 00 74 22 8B 43 10 85 C0 74 1B FF 15 18 30 44 44 8B 53 10 8B 42 10 3B 42 04 74 0A 85 C0 74 06 50 E8 2F FA FF FF FF 15 24 30 44 44 80 7B 28 01 75 03 FF 53 24 80 7B 28 00 74 05 E8 35 FF FF FF 83 3B 00 75 17 83 3D 10 ?? ?? 44 00 74 06 FF 15 10 ?? ?? 44 8B 06 50 E8 51 FA FF FF 8B 03 56 8B F0 8B FB B9 0B 00 00 00 F3 A5 5E E9 73 FF FF FF 5D 5F 5E 5B C3 A3 00 30 44 44 E8 26 FF FF FF C3 }
	condition:
		$1 at pe.entry_point
}

rule flycrypter_10_02 {
	meta:
		tool = "P"
		name = "Fly-Crypter"
		version = "1.0"
		pattern = "558BEC83C4F053B818224444E87FF7FFFFE80AF1FFFFB809000000E85CF1FFFF8BD885DB7505E885FDFFFF83FB017505E87BFDFFFF83FB027505E8D1FDFFFF83FB037505E887FEFFFF83FB047505E85DFDFFFF83FB057505E8B3FDFFFF83FB067505E869FEFFFF83FB077505E85FFEFFFF83FB087505E895FDFFFF83FB097505E84BFEFFFF5BE89DF2FFFF90"
	strings:
		$1 = { 55 8B EC 83 C4 F0 53 B8 18 22 44 44 E8 7F F7 FF FF E8 0A F1 FF FF B8 09 00 00 00 E8 5C F1 FF FF 8B D8 85 DB 75 05 E8 85 FD FF FF 83 FB 01 75 05 E8 7B FD FF FF 83 FB 02 75 05 E8 D1 FD FF FF 83 FB 03 75 05 E8 87 FE FF FF 83 FB 04 75 05 E8 5D FD FF FF 83 FB 05 75 05 E8 B3 FD FF FF 83 FB 06 75 05 E8 69 FE FF FF 83 FB 07 75 05 E8 5F FE FF FF 83 FB 08 75 05 E8 95 FD FF FF 83 FB 09 75 05 E8 4B FE FF FF 5B E8 9D F2 FF FF 90 }
	condition:
		$1 at pe.entry_point
}

rule freecryptor_01001 {
	meta:
		tool = "P"
		name = "FreeCryptor"
		version = "0.1.001"
		pattern = "8B0424409083C007803890907402EBFF6826????0064FF350000000064892500000000FFE4908B042464A3000000008B6424089083C408"
	strings:
		$1 = { 8B 04 24 40 90 83 C0 07 80 38 90 90 74 02 EB FF 68 26 ?? ?? 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 FF E4 90 8B 04 24 64 A3 00 00 00 00 8B 64 24 08 90 83 C4 08 }
	condition:
		$1 at pe.entry_point
}

rule freecryptor_01002 {
	meta:
		tool = "P"
		name = "FreeCryptor"
		version = "0.1.002"
		pattern = "8B0424409083C007803890907402EBFF906827????0064FF350000000064892500000000FFE4908B042464A3000000008B6424089083C408"
	strings:
		$1 = { 8B 04 24 40 90 83 C0 07 80 38 90 90 74 02 EB FF 90 68 27 ?? ?? 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 FF E4 90 8B 04 24 64 A3 00 00 00 00 8B 64 24 08 90 83 C4 08 }
	condition:
		$1 at pe.entry_point
}

rule freecryptor_02002 {
	meta:
		tool = "P"
		name = "FreeCryptor"
		version = "0.2.002"
		pattern = "33D2901E681B??????0FA01F8B029050548F0290908E642408FFE2585033D25283F8019B408A1089142490D9042490D9FAD95C24FC8B5C24FC81F3C2FC1D1C75E3740162FFD0905A33C08B54240890648F009083C208525C5A"
	strings:
		$1 = { 33 D2 90 1E 68 1B ?? ?? ?? 0F A0 1F 8B 02 90 50 54 8F 02 90 90 8E 64 24 08 FF E2 58 50 33 D2 52 83 F8 01 9B 40 8A 10 89 14 24 90 D9 04 24 90 D9 FA D9 5C 24 FC 8B 5C 24 FC 81 F3 C2 FC 1D 1C 75 E3 74 01 62 FF D0 90 5A 33 C0 8B 54 24 08 90 64 8F 00 90 83 C2 08 52 5C 5A }
	condition:
		$1 at pe.entry_point
}

rule freejoiner_151 {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "1.5.1"
		pattern = "9087FF9090B92B000000BA0710400083C2039087FF9090B9040000009087FF9033C9C7050930400000000000680001000068213040006A00E8B70200006A0068800000006A036A006A0068000000806821304000E88F020000A3193040009087FF908B150930400081C204010000F7DA6A026A0052"
	strings:
		$1 = { 90 87 FF 90 90 B9 2B 00 00 00 BA 07 10 40 00 83 C2 03 90 87 FF 90 90 B9 04 00 00 00 90 87 FF 90 33 C9 C7 05 09 30 40 00 00 00 00 00 68 00 01 00 00 68 21 30 40 00 6A 00 E8 B7 02 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 68 21 30 40 00 E8 8F 02 00 00 A3 19 30 40 00 90 87 FF 90 8B 15 09 30 40 00 81 C2 04 01 00 00 F7 DA 6A 02 6A 00 52 }
	condition:
		$1 at pe.entry_point
}

rule freejoiner_152 {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "1.5.2 stub engine 1.6"
		pattern = "E846FDFFFF50E80C000000FF2508204000FF250C204000FF2510204000FF2514204000FF2518204000FF251C204000FF2520204000FF2524204000FF2528204000FF2500204000"
	strings:
		$1 = { E8 46 FD FF FF 50 E8 0C 00 00 00 FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00 }
	condition:
		$1 at pe.entry_point
}

rule freejoiner_153_17 {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "1.5.3 stub engine 1.7"
		pattern = "E833FDFFFF50E80D000000CCFF2508204000FF250C204000FF2510204000FF2514204000FF2518204000FF251C204000FF2520204000FF2524204000FF2528204000FF2500204000"
	strings:
		$1 = { E8 33 FD FF FF 50 E8 0D 00 00 00 CC FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00 }
	condition:
		$1 at pe.entry_point
}

rule freejoiner_153_171 {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "1.5.3 stub engine 1.7.1"
		pattern = "E802FDFFFF6A00E80D000000CCFF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A8104000"
	strings:
		$1 = { E8 02 FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A8 10 40 00 }
	condition:
		$1 at pe.entry_point
}

rule freejoiner_small_014_021 {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 014 - 021"
		pattern = "E8????FFFF6A00E80D000000CCFF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { E8 ?? ?? FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		$1 at pe.entry_point
}

rule freejoiner_small_023 {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 023"
		pattern = "E8E1FDFFFF6A00E80C000000FF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { E8 E1 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		$1 at pe.entry_point
}

rule freejoiner_small_029 {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 029"
		pattern = "5032C48AC358E8DEFDFFFF6A00E80D000000CCFF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { 50 32 C4 8A C3 58 E8 DE FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		$1 at pe.entry_point
}

rule freejoiner_small_031_032 {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 031, 032"
		pattern = "5032??668BC358E8??FDFFFF6A00E80D000000CCFF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { 50 32 ?? 66 8B C3 58 E8 ?? FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		$1 at pe.entry_point
}

rule freejoiner_small_033 {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 033"
		pattern = "506633C3668BC158E8ACFDFFFF6A00E80D000000CCFF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { 50 66 33 C3 66 8B C1 58 E8 AC FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		$1 at pe.entry_point
}

rule freejoiner_small_035 {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 035"
		pattern = "5133CB86C959E89EFDFFFF6687DB6A00E80C000000FF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { 51 33 CB 86 C9 59 E8 9E FD FF FF 66 87 DB 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		$1 at pe.entry_point
}

rule freshbind_20 {
	meta:
		tool = "P"
		name = "Freshbind"
		version = "2.0"
		pattern = "64A1000000005589E56AFF681CA04100"
	strings:
		$1 = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 1C A0 41 00 }
	condition:
		$1 at pe.entry_point
}

rule frusion {
	meta:
		tool = "P"
		name = "Frusion"
		pattern = "83EC0C535556576804010000C7442414"
	strings:
		$1 = { 83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14 }
	condition:
		$1 at pe.entry_point
}

rule fsg_uv_01 {
	meta:
		tool = "P"
		name = "FSG"
		pattern = "??????????81C2F14F5305525281C2FC04000089D15AE81200000005443467552902C1020883C20439D175EAC3"
	strings:
		$1 = { ?? ?? ?? ?? ?? 81 C2 F1 4F 53 05 52 52 81 C2 FC 04 00 00 89 D1 5A E8 12 00 00 00 05 44 34 67 55 29 02 C1 02 08 83 C2 04 39 D1 75 EA C3 }
	condition:
		$1 at pe.entry_point
}

rule fsg_uv_02 {
	meta:
		tool = "P"
		name = "FSG"
		pattern = "8D????????0000BA????????81C2????????525281C21C05000089D15A6A??6A??6A??E8??00000005????????3102C102"
	strings:
		$1 = { 8D ?? ?? ?? ?? 00 00 BA ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 52 52 81 C2 1C 05 00 00 89 D1 5A 6A ?? 6A ?? 6A ?? E8 ?? 00 00 00 05 ?? ?? ?? ?? 31 02 C1 02 }
	condition:
		$1 at pe.entry_point
}

rule fsg_100 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.00"
		pattern = "BBD0014000BF00104000BE????????53E80A00000002D275058A164612D2C3FCB280A46A025BFF142473F733C9FF1424731833C0FF14247321B30241B010FF142412C073F9753FAAEBDCE8430000002BCB7510E838"
	strings:
		$1 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_asm {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MASM32, TASM32"
		pattern = "03F723FE33FBEB02CD20BB80??4000EB0186EB0190B8F400000083EE052BF281F6EE000000EB02CD208A0BE802000000A9545EC1EE07F7D7EB01DE81E9B796A0C4EB016BEB02CD2080E94BC1CF08EB017180E91CEB"
	strings:
		$1 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_bdelhpi_msvc_01 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland Delphi, MSVC"
		pattern = "C1C810EB010FBF03746677C1E91D6883????77EB02CD205EEB02CD202BF7"
	strings:
		$1 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_bdelhpi_msvc_02 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland Delphi, MSVC"
		pattern = "1BDBE8020000001A0D5B6880????00E801000000EA5A58EB02CD2068F4000000EB02CD205E0FB6D080CA5C8B38EB0135EB02DC9781EFF7651743E80200000097CB5B81C7B28BA10C8BD183EF17EB020C6583EF4313"
	strings:
		$1 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_borland_cpp {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland C++"
		pattern = "23CAEB025A0DE8020000006A3558C1C910BE80????000FB6C9EB02CD20BBF4000000EB0204FAEB01FAEB015FEB02CD208A16EB02113180E931EB023011C1E91180EA04EB02F0EA33CB81EAABAB190804D503C280EA"
	strings:
		$1 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_borland_cpp_1999 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland C++ 1999"
		pattern = "EB02CD202BC86880????00EB021EBB5EEB02CD2068B12B6E37405B0FB6C9"
	strings:
		$1 = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_borland_01 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland Delphi or C++"
		pattern = "2BC2E802000000954A598D3D52F12AE8C1C81CBE2E????18EB02ABA003F7EB02CD2068F40000000BC75B03CB8A068A16E8020000008D4659EB01A402D3EB02CD2002D3E80200000057AB5881C2AA87ACB90FBEC980"
	strings:
		$1 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_borland_02 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland Delphi or C++"
		pattern = "EB012EEB02A555BB80????0087FE8D05AACEE063EB0175BA5ECEE063EB02"
	strings:
		$1 = { EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_lcc {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 4.x, LCC Win32 1.x"
		pattern = "2C711BCAEB012AEB01658D3580????0080C98480C968BBF4000000EB01EB"
	strings:
		$1 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_50_60 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 5.0, 6.0"
		pattern = "33D20FBED2EB01C7EB01D88D0580??????EB02CD20EB01F8BEF4000000EB"
	strings:
		$1 = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_01 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "C1CE10C1F60F6800????002BFA5B23F98D1580????00E801000000B65E0B"
	strings:
		$1 = { C1 CE 10 C1 F6 0F 68 00 ?? ?? 00 2B FA 5B 23 F9 8D 15 80 ?? ?? 00 E8 01 00 00 00 B6 5E 0B }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_02 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "D1E903C06880????00EB02CD205E40BBF400000033CA2BC70FB616EB013E"
	strings:
		$1 = { D1 E9 03 C0 68 80 ?? ?? 00 EB 02 CD 20 5E 40 BB F4 00 00 00 33 CA 2B C7 0F B6 16 EB 01 3E }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_03 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "E8010000000E59E8010000005858BE80????00EB0261E968F4000000C1C8"
	strings:
		$1 = { E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE 80 ?? ?? 00 EB 02 61 E9 68 F4 00 00 00 C1 C8 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_04 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "03DEEB01F8B880??4200EB02CD206817A0B3ABEB01E8590FB6DB680BA1B3ABEB02CD205E80CBAA2BF1EB02CD20430FBE3813D680C3472BFEEB01F403FEEB024F4E81EF93537C3C80C32981F78A8F678B80C3C72BFE"
	strings:
		$1 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_05 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "EB014D83F64C6880????00EB02CD205BEB012368481C2B3AE80200000038"
	strings:
		$1 = { EB 01 4D 83 F6 4C 68 80 ?? ?? 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_06 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "EB02AB35EB02B5C68D0580????00C1C211BEF4000000F7DBF7DB0FBE38E8"
	strings:
		$1 = { EB 02 AB 35 EB 02 B5 C6 8D 05 80 ?? ?? 00 C1 C2 11 BE F4 00 00 00 F7 DB F7 DB 0F BE 38 E8 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_07 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "EB02CD20??CF????80????00????????????????00"
	strings:
		$1 = { EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_08 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "91EB02CD20BF50BC046F91BED0????6FEB02CD202BF7EB02F0468D1DF400"
	strings:
		$1 = { 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 ?? ?? 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_09 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "F7D0EB02CD20BEBB741CFBEB02CD20BF3B????FBC1C10333F7EB02CD2068"
	strings:
		$1 = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_70_01 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0, 7.0"
		pattern = "F7D84049EB02E00A8D3580??????0FB6C2EB019C8D1DF4000000EB013C80"
	strings:
		$1 = { F7 D8 40 49 EB 02 E0 0A 8D 35 80 ?? ?? ?? 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_70_02 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0, 7.0"
		pattern = "87FEE80200000098CC5FBB80????00EB02CD2068F4000000E801000000E3"
	strings:
		$1 = { 87 FE E8 02 00 00 00 98 CC 5F BB 80 ?? ?? 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_70_03 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0, 7.0"
		pattern = "F7DB80EABFB92F4067BAEB010168AF????BA80EA9D58C1C2092BC18BD768"
	strings:
		$1 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? ?? BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvc_60_70_04 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0, 7.0"
		pattern = "0BD08BDAE80200000040A05AEB019DB880????00EB02CD2003D38D35F4000000EB0135EB018880CA7C80F3748B38EB02ACBA03DBE801000000A55BC1C20B81C7DA100A4EEB01082BD183EF14EB02CD2033D383EF27"
	strings:
		$1 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27 }
	condition:
		$1 at pe.entry_point
}

rule fsg_msvc_60_70_03 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0, 7.0"
		pattern = "E8010000005A5EE802000000BADD5E03F2EB0164BB80????008BFAEB01A8"
	strings:
		$1 = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_winrar_sfx_01 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "WinRAR SFX"
		pattern = "80E9A1C1C11368E4167546C1C1055EEB019D6864863746EB028CE05FF7D0"
	strings:
		$1 = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_winrar_sfx_02 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "WinRAR SFX"
		pattern = "EB0102EB02CD20B880??4200EB0155BEF400000013DF13D80FB638D1F3F7"
	strings:
		$1 = { EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_msvb_50_60 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Microsoft Visual Basic 5.0, 6.0"
		pattern = "C1CB10EB010FB90374F6EE0FB6D38D0583????EF80F3F62BC1EB01DE6877"
	strings:
		$1 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_borland_delphi_20 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland Delphi 2.0"
		pattern = "EB0156E802000000B2D9596880??4100E8020000006532595EEB02CD20BB"
	strings:
		$1 = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_masm32 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MASM32"
		pattern = "EB01DBE80200000086435E8D1DD075CF83C1EE1D6850??8F83EB023D0F5A"
	strings:
		$1 = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_mvb_masm32 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Microsoft Visual Basic, MASM32"
		pattern = "EB0209940FB7FF6880????0081F68E0000005BEB0211C28D05F400000047"
	strings:
		$1 = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_watcom {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Watcom C/C++"
		pattern = "EB02CD2003??8D??80????00??????????????????EB02"
	strings:
		$1 = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_01 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		pattern = "BBD00140??BF??1040??BE????????FCB2808A064688074702D275058A16"
	strings:
		$1 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_02 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		pattern = "EB02CD20EB02CD20EB02CD20C1E618BB80????00EB0282B8EB01108D05F4"
	strings:
		$1 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }
	condition:
		$1 at pe.entry_point
}

rule fsg_110_03 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		pattern = "F7D80FBEC2BE80????000FBEC9BF083B6507EB02D829BBECC59AF8EB0194"
	strings:
		$1 = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }
	condition:
		$1 at pe.entry_point
}

rule fsg_120_delphi_msvc {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "Borland Delphi, MSVC"
		pattern = "0FB6D0E8010000000C5AB880????00EB0200DE8D35F4000000F7D2EB020EEA8B38EB01A0C1F31181EF8488F44CEB02CD2083F72287D333FEC1C31983F726E802000000BCDE5A81EFF7EF6F18EB02CD2083EF7FEB01F72BFEEB017F81EFDF30901EEB02CD2087FA881080EA0340EB01204EEB013D83FE0075A2EB02CD20EB01C3787342F7356C2D3FED3397??????5DF0452955575571630272E91F2D67B1C091FD1058A390716C"
	strings:
		$1 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 F7 2B FE EB 01 7F 81 EF DF 30 90 1E EB 02 CD 20 87 FA 88 10 80 EA 03 40 EB 01 20 4E EB 01 3D 83 FE 00 75 A2 EB 02 CD 20 EB 01 C3 78 73 42 F7 35 6C 2D 3F ED 33 97 ?? ?? ?? 5D F0 45 29 55 57 55 71 63 02 72 E9 1F 2D 67 B1 C0 91 FD 10 58 A3 90 71 6C }
	condition:
		$1 at pe.entry_point
}

rule fsg_120_borland {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "Borland Delphi or C++"
		pattern = "0FBEC1EB010E8D35C3BEB622F7D16843????22EB02B5155FC1F11533F780E9F9BBF4000000EB028FD0EB0208AD8A162BC71BC780C27A4180EA10EB013C81EACFAEF1AAEB01EC81EABBC6ABEE2CE332D30BCB81EAABEE90142C772AD3EB01872AD3E80100000092598816EB02520846EB02CD204B80F1C285DB75AEC1E004EB00DAB2825C9BC789984F8AF7??????B14DDFB8ADACABD40727D450CF9AD51CECF2277718404EA4A8"
	strings:
		$1 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB EE 90 14 2C 77 2A D3 EB 01 87 2A D3 E8 01 00 00 00 92 59 88 16 EB 02 52 08 46 EB 02 CD 20 4B 80 F1 C2 85 DB 75 AE C1 E0 04 EB 00 DA B2 82 5C 9B C7 89 98 4F 8A F7 ?? ?? ?? B1 4D DF B8 AD AC AB D4 07 27 D4 50 CF 9A D5 1C EC F2 27 77 18 40 4E A4 A8 }
	condition:
		$1 at pe.entry_point
}

rule fsg_120_borland_cpp {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "Borland C++"
		pattern = "C1F007EB02CD20BE80????001BC68D1DF40000000FB606EB02CD208A160FB6C3E801000000DC5980EA37EB02CD202AD3EB02CD2080EA731BCF32D3C1C80E80EA230FB6C902D3EB01B502D3EB02DB5B81C2F6567BF6EB02567B2AD3E801000000ED58881613C346EB02CD204BEB02CD202BC93BD975A1E802000000D76B58EB009E966A2867AB6954033E7F??????310D634435383718879F108C37C641804C5E8BDB604C3A2808"
	strings:
		$1 = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 EB 02 56 7B 2A D3 E8 01 00 00 00 ED 58 88 16 13 C3 46 EB 02 CD 20 4B EB 02 CD 20 2B C9 3B D9 75 A1 E8 02 00 00 00 D7 6B 58 EB 00 9E 96 6A 28 67 AB 69 54 03 3E 7F ?? ?? ?? 31 0D 63 44 35 38 37 18 87 9F 10 8C 37 C6 41 80 4C 5E 8B DB 60 4C 3A 28 08 }
	condition:
		$1 at pe.entry_point
}

rule fsg_120_asm {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "MASM32, TASM32"
		pattern = "33C22CFB8D3D7E45B480E8020000008A45586802??8C7FEB02CD205E80C91603F7EB0240B068F400000080F12C5BC1E9050FB6C98A160FB6C90FBFC72AD3E802000000994C5880EA53C1C9162AD3E8020000009DCE5880EA33C1E11232D34880C226EB02CD208816F7D846EB01C04B408D0D000000003BD975B7EB0114EB010ACFC5935390DA9667548DCC????518E18745382838047B4D241FB64316AAF7D89BC0A91D7833739"
	strings:
		$1 = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE 58 80 EA 33 C1 E1 12 32 D3 48 80 C2 26 EB 02 CD 20 88 16 F7 D8 46 EB 01 C0 4B 40 8D 0D 00 00 00 00 3B D9 75 B7 EB 01 14 EB 01 0A CF C5 93 53 90 DA 96 67 54 8D CC ?? ?? 51 8E 18 74 53 82 83 80 47 B4 D2 41 FB 64 31 6A AF 7D 89 BC 0A 91 D7 83 37 39 }
	condition:
		$1 at pe.entry_point
}

rule fsg_120_msvc_60 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "MSVC 6.0"
		pattern = "C1E006EB02CD20EB0127EB0124BE80??420049EB01998D1DF4000000EB015CF7D81BCAEB01318A1680E941EB01C2C1E00AEB01A181EAA88C18A13446E801000000625932D3C1C902EB016880F21A0FBEC9F7D12AD3"
	strings:
		$1 = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 }
	condition:
		$1 at pe.entry_point
}

rule fsg_120_msvc_60_70 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "MSVC 6.0, 7.0"
		pattern = "EB02CD20EB01918D3580????0033C26883937E7D0CA45B23C36877937E7DEB01FA5FE802000000F7FB5833DFEB013FE8020000001188580FB616EB02CD20EB02862F2AD3EB02CD2080EA2FEB015232D380E9CD80EA738BCF81C29644EB04EB02CD208816E80200000044A25946E801000000AD594B80C11383FB0075B2F7D9968F804D0C4C91501C0C508A??????50E93416504C4C0E7E9B49C632023E7E7B5E8CC56B503F0E0F"
	strings:
		$1 = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA 73 8B CF 81 C2 96 44 EB 04 EB 02 CD 20 88 16 E8 02 00 00 00 44 A2 59 46 E8 01 00 00 00 AD 59 4B 80 C1 13 83 FB 00 75 B2 F7 D9 96 8F 80 4D 0C 4C 91 50 1C 0C 50 8A ?? ?? ?? 50 E9 34 16 50 4C 4C 0E 7E 9B 49 C6 32 02 3E 7E 7B 5E 8C C5 6B 50 3F 0E 0F }
	condition:
		$1 at pe.entry_point
}

rule fsg_120 {
	meta:
		tool = "P"
		name = "FSG"
		extra = "1.20"
		pattern = "4B45524E454C33322E646C6C00004C6F61644C69627261727941000047657450726F634164647265737300??0000000000"
	strings:
		$1 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule fsg_130 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.30"
		pattern = "BBD0014000BF00104000BE????????53E80A00000002D275058A164612D2C3B280A46A025BFF142473F733C9FF1424731833C0FF14247321B30241B010FF142412C073F9753FAAEBDCE8430000002BCB7510E838000000EB28ACD1E8744113C9EB1C9148C1E008ACE8220000003D007D0000730A80FC05730683F87F77024141958BC5B301568BF72BF0F3A45EEB9633C941FF54240413C9FF54240472F4C35F5B0FB73B4F7408"
	strings:
		$1 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 }
	condition:
		$1 at pe.entry_point
}

rule fsg_131_01 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.31"
		pattern = "BBD0014000BF00104000BE????????53BB????????B280A4B680FFD373F933C9FFD3731633C0FFD37323B68041B010FFD312C073FA7542AAEBE0E84600000002F683D9017510E838000000EB28ACD1E8744813C9EB1C9148C1E008ACE8220000003D007D0000730A80FC05730683F87F77024141958BC5B600568BF72BF0F3A45EEB9733C941FFD313C9FFD372F8C302D275058A164612D2C35B5B0FB73B4F74084F7413C1E70C"
	strings:
		$1 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 97 33 C9 41 FF D3 13 C9 FF D3 72 F8 C3 02 D2 75 05 8A 16 46 12 D2 C3 5B 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C }
	condition:
		$1 at pe.entry_point
}

rule fsg_131_02 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.31"
		pattern = "BE??????00BF??????00BB??????0053BB??????00B280"
	strings:
		$1 = { BE ?? ?? ?? 00 BF ?? ?? ?? 00 BB ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 }
	condition:
		$1 at pe.entry_point
}

rule fsg_133 {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.33"
		pattern = "BEA4014000AD93AD97AD5696B280A4B680FF1373F933C9FF13731633C0FF13731FB68041B010FF1312C073FA753CAAEBE0FF530802F683D901750EFF5304EB26ACD1E8742F13C9EB1A9148C1E008ACFF53043D007D"
	strings:
		$1 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D }
	condition:
		$1 at pe.entry_point
}

rule fsg_200 {
	meta:
		tool = "P"
		name = "FSG"
		version = "2.00"
		pattern = "8725??????00619455A4B680FF1373F933C9FF13731633C0FF13731FB68041B010FF1312C073FA753AAAEBE0"
	strings:
		$1 = { 87 25 ?? ?? ?? 00 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3A AA EB E0 }
	condition:
		$1 at pe.entry_point
}

rule fucknjoy_10c {
	meta:
		tool = "P"
		name = "Fuck'n'Joy"
		version = "1.0c"
		pattern = "60E8000000005D81EDD8054000FF742420E88C0200000BC00F842C01000089856C0840008D852F08400050FFB56C084000E8EF0200000BC00F840C01000089853B0840008D853F08400050FFB56C084000E8CF0200"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 }
	condition:
		$1 at pe.entry_point
}

rule fusion_10 {
	meta:
		tool = "P"
		name = "Fusion"
		version = "1.0"
		pattern = "68043040006804304000E8090300006804304000E8C7020000"
	strings:
		$1 = { 68 04 30 40 00 68 04 30 40 00 E8 09 03 00 00 68 04 30 40 00 E8 C7 02 00 00 }
	condition:
		$1 at pe.entry_point
}

rule gameguard_20065xx_01 {
	meta:
		tool = "P"
		name = "GameGuard"
		version = "2006.5.x.x"
		pattern = "31FF740661E94A4D5030BA4C000000807C2408010F85??01000060BE00"
	strings:
		$1 = { 31 FF 74 06 61 E9 4A 4D 50 30 BA 4C 00 00 00 80 7C 24 08 01 0F 85 ?? 01 00 00 60 BE 00 }
	condition:
		$1 at pe.entry_point
}

rule gameguard_20065xx_02 {
	meta:
		tool = "P"
		name = "GameGuard"
		version = "2006.5.x.x"
		pattern = "31FF740661E94A4D50305ABA7D000000807C240801E90000000060BE00"
	strings:
		$1 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }
	condition:
		$1 at pe.entry_point
}

rule gamehouse_media_protector {
	meta:
		tool = "P"
		name = "Gamehouse Media Protector"
		pattern = "68????????6A00FF15????????50FF15??????0000000000000000"
	strings:
		$1 = { 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule ghf_protector_01 {
	meta:
		tool = "P"
		name = "GHF Protector"
		pattern = "6068????????B8????????FF1068????????50B8????????FF106800A000006A40FFD08905????????89C7BE????????60FCB28031DBA4B302E86D00000073F6"
	strings:
		$1 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 00 A0 00 00 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 }
	condition:
		$1 at pe.entry_point
}

rule ghf_protector_02 {
	meta:
		tool = "P"
		name = "GHF Protector"
		pattern = "6068????????B8????????FF1068????????50B8????????FF1068000000006A40FFD08905????????89C7BE????????60FCB28031DBA4B302E86D00000073F631C9E864000000731C31C0E85B0000007323B30241"
	strings:
		$1 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 00 00 00 00 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 }
	condition:
		$1 at pe.entry_point
}

rule goatrs_pe_mutilator_16 {
	meta:
		tool = "P"
		name = "Goat's PE Mutilator"
		version = "1.6"
		pattern = "E8EA0B0000??????8B1C79F663D88D22B0BFF64908C302BD3B6C294613285D00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000F530FDE0F550F60000000000000000000000000000000000000000000000000000000"
	strings:
		$1 = { E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0F 53 0F DE 0F 55 0F 60 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule gix_protector_12 {
	meta:
		tool = "P"
		name = "G!X Protector"
		version = "1.2"
		pattern = "60EB05E8EB044000EBFAE80A000000"
	strings:
		$1 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule hardlock_dongle {
	meta:
		tool = "P"
		name = "Hardlock dongle"
		pattern = "5C5C2E5C484152444C4F434B2E565844000000005C5C2E5C46456E7465446576"
	strings:
		$1 = { 5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 00 00 00 00 5C 5C 2E 5C 46 45 6E 74 65 44 65 76 }
	condition:
		$1 at pe.entry_point
}

rule hasp_dongle {
	meta:
		tool = "P"
		name = "HASP Dongle"
		pattern = "5053515257568B751C8B3E??????????8B5D088AFB????035D108B450C8B4D148B551880FF32"
	strings:
		$1 = { 50 53 51 52 57 56 8B 75 1C 8B 3E ?? ?? ?? ?? ?? 8B 5D 08 8A FB ?? ?? 03 5D 10 8B 45 0C 8B 4D 14 8B 55 18 80 FF 32 }
	condition:
		$1 at pe.entry_point
}

rule hasp_protection_01 {
	meta:
		tool = "P"
		name = "HASP Protection"
		pattern = "6A??602EFF35????????2EFF35????????68????????E8????????6683C4??2EFF35????????2EFF35????????B8????????83C0??50"
	strings:
		$1 = { 6A ?? 60 2E FF 35 ?? ?? ?? ?? 2E FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 83 C4 ?? 2E FF 35 ?? ?? ?? ?? 2E FF 35 ?? ?? ?? ?? B8 ?? ?? ?? ?? 83 C0 ?? 50 }
	condition:
		$1 at pe.entry_point
}

rule hasp_protection_02 {
	meta:
		tool = "P"
		name = "HASP Protection"
		pattern = "558BEC535657608BC4A350??????B890??????2B05B0??????A3B0??????833D4C??????000F8411000000A150??????50FF154C??????E969000000C70570"
	strings:
		$1 = { 55 8B EC 53 56 57 60 8B C4 A3 50 ?? ?? ?? B8 90 ?? ?? ?? 2B 05 B0 ?? ?? ?? A3 B0 ?? ?? ?? 83 3D 4C ?? ?? ?? 00 0F 84 11 00 00 00 A1 50 ?? ?? ?? 50 FF 15 4C ?? ?? ?? E9 69 00 00 00 C7 05 70 }
	condition:
		$1 at pe.entry_point
}

rule hasp_protection_1x {
	meta:
		tool = "P"
		name = "HASP Protection"
		version = "1.x"
		pattern = "558BEC535657608BC4A3????????B8????????2B05????????A3????????833D????????0074158B0D????????51FF15????????83C404E9A500000068"
	strings:
		$1 = { 55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? 00 74 15 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 83 C4 04 E9 A5 00 00 00 68 }
	condition:
		$1 at pe.entry_point
}

rule hide_pe_101 {
	meta:
		tool = "P"
		name = "Hide PE"
		version = "1.01"
		pattern = "??BA??????00B8????????890283C204B8????????890283C204B8????????890283C2F8FFE20D0A2D3D5B20486964655045206279204247436F7270205D3D2D"
	strings:
		$1 = { ?? BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 F8 FF E2 0D 0A 2D 3D 5B 20 48 69 64 65 50 45 20 62 79 20 42 47 43 6F 72 70 20 5D 3D 2D }
	condition:
		$1 at pe.entry_point
}

rule hide_protect_1016c {
	meta:
		tool = "P"
		name = "Hide&Protect"
		version = "1.016C"
		pattern = "909090E9D8"
	strings:
		$1 = { 90 90 90 E9 D8 }
	condition:
		$1 at pe.entry_point
}

rule hmimys_protect_10 {
	meta:
		tool = "P"
		name = "hmimys Protect"
		version = "1.0"
		pattern = "E8BA000000??00000000????0000104000??????00??????0000????00??????00??????00??????00??????00??????00??00000000000000??????000000000000000000??????00??????000000000000000000000000000000000000000000??????00??????00??????00??????00000000004B65726E656C33322E646C6C0000004C6F61644C6962726172794100000047657450726F6341646472657373000000566972"
	strings:
		$1 = { E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 00 10 40 00 ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 }
	condition:
		$1 at pe.entry_point
}

rule hmimys_pepack_01 {
	meta:
		tool = "P"
		name = "hmimys's PE-Pack"
		version = "0.1"
		pattern = "E8000000005D83ED056A00FF95E10E00008985850E00008B583C03D881C3F800000080AD890E000001899D630F00008B4B0C038D850E00008B530880BD890E000000750C038D910E00002B95910E0000898D570F000089955B0F00008B5B10899D5F0F00008B9D5F0F00008B85570F00005350E8B70B00008985730F00006A046800100000506A00FF95E90E000089856B0F00006A04680010000068D87C00006A00FF95E90E000089856F0F00008D85670F00008B9D730F00008B8D6B0F00008B955B0F000083EA0E8BB5570F000083C60E8BBD6F0F0000505351525668D87C000057E8010100008B9D570F00008B033C0175"
	strings:
		$1 = { E8 00 00 00 00 5D 83 ED 05 6A 00 FF 95 E1 0E 00 00 89 85 85 0E 00 00 8B 58 3C 03 D8 81 C3 F8 00 00 00 80 AD 89 0E 00 00 01 89 9D 63 0F 00 00 8B 4B 0C 03 8D 85 0E 00 00 8B 53 08 80 BD 89 0E 00 00 00 75 0C 03 8D 91 0E 00 00 2B 95 91 0E 00 00 89 8D 57 0F 00 00 89 95 5B 0F 00 00 8B 5B 10 89 9D 5F 0F 00 00 8B 9D 5F 0F 00 00 8B 85 57 0F 00 00 53 50 E8 B7 0B 00 00 89 85 73 0F 00 00 6A 04 68 00 10 00 00 50 6A 00 FF 95 E9 0E 00 00 89 85 6B 0F 00 00 6A 04 68 00 10 00 00 68 D8 7C 00 00 6A 00 FF 95 E9 0E 00 00 89 85 6F 0F 00 00 8D 85 67 0F 00 00 8B 9D 73 0F 00 00 8B 8D 6B 0F 00 00 8B 95 5B 0F 00 00 83 EA 0E 8B B5 57 0F 00 00 83 C6 0E 8B BD 6F 0F 00 00 50 53 51 52 56 68 D8 7C 00 00 57 E8 01 01 00 00 8B 9D 57 0F 00 00 8B 03 3C 01 75 }
	condition:
		$1 at pe.entry_point
}

rule hmimys_packer_10 {
	meta:
		tool = "P"
		name = "hmimys's Packer"
		version = "1.0"
		pattern = "5E83C664AD50AD5083EE6CAD50AD50AD50AD50AD50E8E707"
	strings:
		$1 = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 }
	condition:
		$1 at pe.entry_point
}

rule hmimys_packer_12 {
	meta:
		tool = "P"
		name = "hmimys's Packer"
		version = "1.2"
		pattern = "E895000000??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????5EAD50AD5097AD50AD50AD50E8C0010000AD50AD9387DEB9????????E31D8A074704??3C??73F78B073C??75F3B0000FC805????????2BC7ABE2E3AD85C0742B9756FF138BE8AC84C075FB66AD6685C074E9AC83EE0384C074085655FF5304ABEBE4AD5055FF5304ABEBE0C38B0A3B4A04750AC74210010000000CFFC3"
	strings:
		$1 = { E8 95 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5E AD 50 AD 50 97 AD 50 AD 50 AD 50 E8 C0 01 00 00 AD 50 AD 93 87 DE B9 ?? ?? ?? ?? E3 1D 8A 07 47 04 ?? 3C ?? 73 F7 8B 07 3C ?? 75 F3 B0 00 0F C8 05 ?? ?? ?? ?? 2B C7 AB E2 E3 AD 85 C0 74 2B 97 56 FF 13 8B E8 AC 84 C0 75 FB 66 AD 66 85 C0 74 E9 AC 83 EE 03 84 C0 74 08 56 55 FF 53 04 AB EB E4 AD 50 55 FF 53 04 AB EB E0 C3 8B 0A 3B 4A 04 75 0A C7 42 10 01 00 00 00 0C FF C3 }
	condition:
		$1 at pe.entry_point
}

rule hpa {
	meta:
		tool = "P"
		name = "HPA"
		pattern = "E8????5E8BD683????83????060E1E0E1F33FF8CD3"
	strings:
		$1 = { E8 ?? ?? 5E 8B D6 83 ?? ?? 83 ?? ?? 06 0E 1E 0E 1F 33 FF 8C D3 }
	condition:
		$1 at pe.entry_point
}

rule icebergLock_protector_3101x {
	meta:
		tool = "P"
		name = "IcebergLock Protector"
		version = "3.10.1.36, 3.10.1.41"
		pattern = "E8D7FFFFFF??????????????????????????????????????????????????????????????????????558BEC33C055??????????64FF3064892033C05A5959648910??????????C3E9????????EBF85DC3??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????8BEC83????B8????????E8????FDFFE8????FFFFB8????????E871FEFFFFE8????FDFF"
	strings:
		$1 = { E8 D7 FF FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 8B EC 33 C0 55 ?? ?? ?? ?? ?? 64 FF 30 64 89 20 33 C0 5A 59 59 64 89 10 ?? ?? ?? ?? ?? C3 E9 ?? ?? ?? ?? EB F8 5D C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B EC 83 ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? FD FF E8 ?? ?? FF FF B8 ?? ?? ?? ?? E8 71 FE FF FF E8 ?? ?? FD FF }
	condition:
		$1 at pe.entry_point
}

rule icrypt_10 {
	meta:
		tool = "P"
		name = "ICrypt"
		version = "1.0"
		pattern = "558BEC83C4EC53565733C08945ECB8703B0010E83CFAFFFF33C055686C3C001064FF306489206A0A687C3C0010A15056001050E8D8FAFFFF8BD853A15056001050E80AFBFFFF8BF853A15056001050E8D4FAFFFF8BD853E8D4FAFFFF8BF085F674268BD74AB864560010E825F6FFFFB864560010E813F6FFFF8BCF8BD6E8E6FAFFFF53E890FAFFFF8D4DECBA8C3C0010A164560010E816FBFFFF8B55ECB864560010E8C5F4FFFFB864560010E8DBF5FFFFE856FCFFFF33C05A595964891068733C00108D45ECE84DF4FFFFC3E9E3EEFFFFEBF05F5E5BE84DF3FFFF00534554????????00FFFFFFFF08000000766F747265636C65"
	strings:
		$1 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 70 3B 00 10 E8 3C FA FF FF 33 C0 55 68 6C 3C 00 10 64 FF 30 64 89 20 6A 0A 68 7C 3C 00 10 A1 50 56 00 10 50 E8 D8 FA FF FF 8B D8 53 A1 50 56 00 10 50 E8 0A FB FF FF 8B F8 53 A1 50 56 00 10 50 E8 D4 FA FF FF 8B D8 53 E8 D4 FA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 64 56 00 10 E8 25 F6 FF FF B8 64 56 00 10 E8 13 F6 FF FF 8B CF 8B D6 E8 E6 FA FF FF 53 E8 90 FA FF FF 8D 4D EC BA 8C 3C 00 10 A1 64 56 00 10 E8 16 FB FF FF 8B 55 EC B8 64 56 00 10 E8 C5 F4 FF FF B8 64 56 00 10 E8 DB F5 FF FF E8 56 FC FF FF 33 C0 5A 59 59 64 89 10 68 73 3C 00 10 8D 45 EC E8 4D F4 FF FF C3 E9 E3 EE FF FF EB F0 5F 5E 5B E8 4D F3 FF FF 00 53 45 54 ?? ?? ?? ?? 00 FF FF FF FF 08 00 00 00 76 6F 74 72 65 63 6C 65 }
	condition:
		$1 at pe.entry_point
}

rule id_application_protector_12 {
	meta:
		tool = "P"
		name = "ID Application Protector"
		version = "1.2"
		pattern = "60E8000000005D81EDF20B4700B91922470081E9EA0E470089EA81C2EA0E47008D3A89FE31C0E9D3020000CCCCCCCCE9CA020000433A5C57696E646F77735C536F66745761726550726F746563746F725C"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED F2 0B 47 00 B9 19 22 47 00 81 E9 EA 0E 47 00 89 EA 81 C2 EA 0E 47 00 8D 3A 89 FE 31 C0 E9 D3 02 00 00 CC CC CC CC E9 CA 02 00 00 43 3A 5C 57 69 6E 64 6F 77 73 5C 53 6F 66 74 57 61 72 65 50 72 6F 74 65 63 74 6F 72 5C }
	condition:
		$1 at pe.entry_point
}

rule ilucrypt_4015 {
	meta:
		tool = "P"
		name = "iLUCRYPT"
		version = "4.015"
		pattern = "8BECFAC746F7????4281FA????75F9FF66F7"
	strings:
		$1 = { 8B EC FA C7 46 F7 ?? ?? 42 81 FA ?? ?? 75 F9 FF 66 F7 }
	condition:
		$1 at pe.entry_point
}

rule imp_packer_10 {
	meta:
		tool = "P"
		name = "IMP-Packer"
		version = "1.0"
		pattern = "28??????000000000000000040??????34??????00000000000000000000000000000000000000004C??????5C??????00000000????????????????000000004B45524E454C33322E646C6C000047657450726F634164647265737300004C6F61644C69627261727941"
	strings:
		$1 = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }
	condition:
		$1 at pe.entry_point
}

rule imploder_104 {
	meta:
		tool = "P"
		name = "Imploder"
		version = "1.04"
		pattern = "60E8A000000000000000000000000000000036??????2E??????000000000000000000000000000000000000000001000080000000004B65726E656C33322E44"
	strings:
		$1 = { 60 E8 A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
	condition:
		$1 at pe.entry_point
}

rule impostor_pack_10 {
	meta:
		tool = "P"
		name = "IMPostor Pack"
		version = "1.0"
		pattern = "BE??????0083C601FFE600000000????000000000000000000??????00??02????00100000000200"
	strings:
		$1 = { BE ?? ?? ?? 00 83 C6 01 FF E6 00 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? 02 ?? ?? 00 10 00 00 00 02 00 }
	condition:
		$1 at pe.entry_point
}

rule inbuild_10_hard {
	meta:
		tool = "P"
		name = "Inbuild"
		version = "1.0 hard"
		pattern = "B9????BB????2E????2E????43E2"
	strings:
		$1 = { B9 ?? ?? BB ?? ?? 2E ?? ?? 2E ?? ?? 43 E2 }
	condition:
		$1 at pe.entry_point
}

rule incrypter_03 {
	meta:
		tool = "P"
		name = "INCrypter"
		version = "0.3 INinY"
		pattern = "6064A1300000008B400C8B400C8D5820C70300000000E8000000005D81ED4D1640008B9D0E17400064A1180000008B40300FB6400283F801750503DBC1CB108B8D121740008BB50617400051813E2E72737274658B8516174000E8230000008B851A174000E8180000008B851E174000E80D0000008B8522174000E802000000EB188BD63B460C720A83F901740B3B46347206BA00000000C35883FA00751A8B4E108B7E0C03BD0217400083F9007409F617310F311F47E2F75983C6284983F90075888B850A1740008944241C6150C3"
	strings:
		$1 = { 60 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8D 58 20 C7 03 00 00 00 00 E8 00 00 00 00 5D 81 ED 4D 16 40 00 8B 9D 0E 17 40 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 83 F8 01 75 05 03 DB C1 CB 10 8B 8D 12 17 40 00 8B B5 06 17 40 00 51 81 3E 2E 72 73 72 74 65 8B 85 16 17 40 00 E8 23 00 00 00 8B 85 1A 17 40 00 E8 18 00 00 00 8B 85 1E 17 40 00 E8 0D 00 00 00 8B 85 22 17 40 00 E8 02 00 00 00 EB 18 8B D6 3B 46 0C 72 0A 83 F9 01 74 0B 3B 46 34 72 06 BA 00 00 00 00 C3 58 83 FA 00 75 1A 8B 4E 10 8B 7E 0C 03 BD 02 17 40 00 83 F9 00 74 09 F6 17 31 0F 31 1F 47 E2 F7 59 83 C6 28 49 83 F9 00 75 88 8B 85 0A 17 40 00 89 44 24 1C 61 50 C3 }
	condition:
		$1 at pe.entry_point
}

rule interlok_551 {
	meta:
		tool = "P"
		name = "InterLok"
		version = "5.51"
		pattern = "EB03??????55EB03??????EB04??EB06??8BECEBF9??EB02????81ECA8000000EB02????EB01??53EB03??????EB05????EB15??EB03??????56EB04??EBF2??EB01??EBF8??????EB0F??33F6EB10??????EBF7????EBFA??EB01??EBF8??EB01??57EB03??????EB11??????EB03??????????????????EB08??EBF0??EB07????EBFA??????EB02????BB????????EB03??????0F85????????EB07"
	strings:
		$1 = { EB 03 ?? ?? ?? 55 EB 03 ?? ?? ?? EB 04 ?? EB 06 ?? 8B EC EB F9 ?? EB 02 ?? ?? 81 EC A8 00 00 00 EB 02 ?? ?? EB 01 ?? 53 EB 03 ?? ?? ?? EB 05 ?? ?? EB 15 ?? EB 03 ?? ?? ?? 56 EB 04 ?? EB F2 ?? EB 01 ?? EB F8 ?? ?? ?? EB 0F ?? 33 F6 EB 10 ?? ?? ?? EB F7 ?? ?? EB FA ?? EB 01 ?? EB F8 ?? EB 01 ?? 57 EB 03 ?? ?? ?? EB 11 ?? ?? ?? EB 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 08 ?? EB F0 ?? EB 07 ?? ?? EB FA ?? ?? ?? EB 02 ?? ?? BB ?? ?? ?? ?? EB 03 ?? ?? ?? 0F 85 ?? ?? ?? ?? EB 07 }
	condition:
		$1 at pe.entry_point
}

rule interlok_5xx {
	meta:
		tool = "P"
		name = "InterLok"
		version = "5.xx"
		pattern = "558BEC81ECA4000000535633F6573935????????75538D45DC6A1C5068????????FF15????????85C074058B45E0EB228B7D086A0257FF15????????85C0750B66813F4D5A75048BC7EB0756FF15????????A3????????A3????????8B483C03C889??????????EB068B??????????668B5916C1EB0D83E301740A837D0C010F85380100008D45F8508D45FC50E8470100008BF8593BFE597552837DFCFFFF75F875178D855CFFFFFF68????????50FF15????????83C40CEB18FF75FC8D855CFFFFFF68????????50FF15????????83C4106A308D855CFFFFFF68????????5056FF15????????E9BB00000068????????FF35????????FF35????????57FFD7576A018BF0FF15????????50FF15????????85F60F849600000083FEF67F32742983FE97747583FEF3741883FEF4740C83FEF5752BB8????????EB4FB8????????EB48B8????????EB41B8????????EB3A83FEFA743083FEFC742483FEFD7418568D45E068????????50FF15????????83C40C8D45E0EB13B8????????EB0CB8????????EB05B8????????6A3068????????506A00FF15????????85DB75086A01FF15????????33C05F5E5BC9C20C00"
	strings:
		$1 = { 55 8B EC 81 EC A4 00 00 00 53 56 33 F6 57 39 35 ?? ?? ?? ?? 75 53 8D 45 DC 6A 1C 50 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 05 8B 45 E0 EB 22 8B 7D 08 6A 02 57 FF 15 ?? ?? ?? ?? 85 C0 75 0B 66 81 3F 4D 5A 75 04 8B C7 EB 07 56 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? A3 ?? ?? ?? ?? 8B 48 3C 03 C8 89 ?? ?? ?? ?? ?? EB 06 8B ?? ?? ?? ?? ?? 66 8B 59 16 C1 EB 0D 83 E3 01 74 0A 83 7D 0C 01 0F 85 38 01 00 00 8D 45 F8 50 8D 45 FC 50 E8 47 01 00 00 8B F8 59 3B FE 59 75 52 83 7D FC FF FF 75 F8 75 17 8D 85 5C FF FF FF 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4 0C EB 18 FF 75 FC 8D 85 5C FF FF FF 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4 10 6A 30 8D 85 5C FF FF FF 68 ?? ?? ?? ?? 50 56 FF 15 ?? ?? ?? ?? E9 BB 00 00 00 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 57 FF D7 57 6A 01 8B F0 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 F6 0F 84 96 00 00 00 83 FE F6 7F 32 74 29 83 FE 97 74 75 83 FE F3 74 18 83 FE F4 74 0C 83 FE F5 75 2B B8 ?? ?? ?? ?? EB 4F B8 ?? ?? ?? ?? EB 48 B8 ?? ?? ?? ?? EB 41 B8 ?? ?? ?? ?? EB 3A 83 FE FA 74 30 83 FE FC 74 24 83 FE FD 74 18 56 8D 45 E0 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 C4 0C 8D 45 E0 EB 13 B8 ?? ?? ?? ?? EB 0C B8 ?? ?? ?? ?? EB 05 B8 ?? ?? ?? ?? 6A 30 68 ?? ?? ?? ?? 50 6A 00 FF 15 ?? ?? ?? ?? 85 DB 75 08 6A 01 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 5B C9 C2 0C 00 }
	condition:
		$1 at pe.entry_point
}

rule ionic_wind_sw {
	meta:
		tool = "P"
		name = "Ionic Wind Software"
		pattern = "9BDBE39BDBE2D92D00????005589E5E8"
	strings:
		$1 = { 9B DB E3 9B DB E2 D9 2D 00 ?? ?? 00 55 89 E5 E8 }
	condition:
		$1 at pe.entry_point
}

rule ipbprotect_013_017 {
	meta:
		tool = "P"
		name = "iPBProtect"
		version = "0.1.3 - 0.1.7"
		pattern = "558BEC6AFF684B435546685449485364A100000000"
	strings:
		$1 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule ipbprotect_013 {
	meta:
		tool = "P"
		name = "iPBProtect"
		version = "0.1.3"
		pattern = "558BEC6AFF684B435546685449485364A100000000506489250000000083EC685356578965FA33DB895DF86A02EB01F8585F5E5B648B2500000000648F05000000005858585D689F6F56B650E85D000000EBFF7178C25000EBD35BF368895C24485C2458FF8D5C24585B83C34C75F45A8D7178750981F3EBFF52BA010083EBFC4AFF710F75198B5C240000813350538B1B0FFFC6751B81F3EB871C248B8B042483ECFCEB01E883"
	strings:
		$1 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 FA 33 DB 89 5D F8 6A 02 EB 01 F8 58 5F 5E 5B 64 8B 25 00 00 00 00 64 8F 05 00 00 00 00 58 58 58 5D 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 C2 50 00 EB D3 5B F3 68 89 5C 24 48 5C 24 58 FF 8D 5C 24 58 5B 83 C3 4C 75 F4 5A 8D 71 78 75 09 81 F3 EB FF 52 BA 01 00 83 EB FC 4A FF 71 0F 75 19 8B 5C 24 00 00 81 33 50 53 8B 1B 0F FF C6 75 1B 81 F3 EB 87 1C 24 8B 8B 04 24 83 EC FC EB 01 E8 83 }
	condition:
		$1 at pe.entry_point
}

rule iprotect_10_fxlib {
	meta:
		tool = "P"
		name = "IProtect"
		version = "1.0 fxlib.dll mode"
		pattern = "EB332E4655584C6F61644C696272617279410046784C69622E646C6C000000000000000000000000000000000000000000??????0060E8000000005D81ED71104000FF742420E8400000000BC0742F8985631040008D853C10400050FFB563104000E8920000000BC0741389855F1040008D854910400050FF955F1040008B85671040008944241C61FFE08B7C24048D85001040005064FF35000000008D855310400089208968048D9D0A1140008958086489250000000081E70000FFFF66813F4D5A750F8BF703763C813E504500007502EB1781EF0000010081FF000000707307BF0000F7BFEB02EBD397648F050000000083C404C204008D85001040005064FF35000000008D855310400089208968048D9D0A114000895808648925000000008B74240C66813E4D5A7405E98A00000003763C813E504500007402EB7D8B7C2410B99600000032C0F2AE8BCF2B4C24108B56780354240C8B5A20035C240C33C08B3B037C240C8B74241051F3A6750583C404EB0A5983C304403B421875E23B42187502EB358B72240374240C52BB0200000033D2F7E35A03C633C9668B088B7A1C33D2BB040000008BC1F7E30344240C03C78B000344240CEB0233C0648F050000000083C404C20800E8FAFDFFFF"
	strings:
		$1 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 4C 69 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 60 E8 00 00 00 00 5D 81 ED 71 10 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 63 10 40 00 8D 85 3C 10 40 00 50 FF B5 63 10 40 00 E8 92 00 00 00 0B C0 74 13 89 85 5F 10 40 00 8D 85 49 10 40 00 50 FF 95 5F 10 40 00 8B 85 67 10 40 00 89 44 24 1C 61 FF E0 8B 7C 24 04 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 53 10 40 00 89 20 89 68 04 8D 9D 0A 11 40 00 89 58 08 64 89 25 00 00 00 00 81 E7 00 00 FF FF 66 81 3F 4D 5A 75 0F 8B F7 03 76 3C 81 3E 50 45 00 00 75 02 EB 17 81 EF 00 00 01 00 81 FF 00 00 00 70 73 07 BF 00 00 F7 BF EB 02 EB D3 97 64 8F 05 00 00 00 00 83 C4 04 C2 04 00 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 53 10 40 00 89 20 89 68 04 8D 9D 0A 11 40 00 89 58 08 64 89 25 00 00 00 00 8B 74 24 0C 66 81 3E 4D 5A 74 05 E9 8A 00 00 00 03 76 3C 81 3E 50 45 00 00 74 02 EB 7D 8B 7C 24 10 B9 96 00 00 00 32 C0 F2 AE 8B CF 2B 4C 24 10 8B 56 78 03 54 24 0C 8B 5A 20 03 5C 24 0C 33 C0 8B 3B 03 7C 24 0C 8B 74 24 10 51 F3 A6 75 05 83 C4 04 EB 0A 59 83 C3 04 40 3B 42 18 75 E2 3B 42 18 75 02 EB 35 8B 72 24 03 74 24 0C 52 BB 02 00 00 00 33 D2 F7 E3 5A 03 C6 33 C9 66 8B 08 8B 7A 1C 33 D2 BB 04 00 00 00 8B C1 F7 E3 03 44 24 0C 03 C7 8B 00 03 44 24 0C EB 02 33 C0 64 8F 05 00 00 00 00 83 C4 04 C2 08 00 E8 FA FD FF FF }
	condition:
		$1 at pe.entry_point
}

rule iprotect_10_fxsub {
	meta:
		tool = "P"
		name = "IProtect"
		version = "1.0 fxsub.dll mode"
		pattern = "EB332E4655584C6F61644C696272617279410046785375622E646C6C000000000000000000000000000000000000000000??????0060E8000000005D81EDB6134000FF742420E8400000000BC0742F8985A81340008D858113400050FFB5A8134000E8920000000BC074138985A41340008D858E13400050FF95A41340008B85AC1340008944241C61FFE08B7C24048D85001040005064FF35000000008D859813400089208968048D9D4F1440008958086489250000000081E70000FFFF66813F4D5A750F8BF703763C813E504500007502EB1781EF0000010081FF000000707307BF0000F7BFEB02EBD397648F050000000083C404C204008D85001040005064FF35000000008D859813400089208968048D9D4F144000895808648925000000008B74240C66813E4D5A7405E98A00000003763C813E504500007402EB7D8B7C2410B99600000032C0F2AE8BCF2B4C24108B56780354240C8B5A20035C240C33C08B3B037C240C8B74241051F3A6750583C404EB0A5983C304403B421875E23B42187502EB358B72240374240C52BB0200000033D2F7E35A03C633C9668B088B7A1C33D2BB040000008BC1F7E30344240C03C78B000344240CEB0233C0648F050000000083C404C20800E8B5FAFFFF"
	strings:
		$1 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 53 75 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 60 E8 00 00 00 00 5D 81 ED B6 13 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 A8 13 40 00 8D 85 81 13 40 00 50 FF B5 A8 13 40 00 E8 92 00 00 00 0B C0 74 13 89 85 A4 13 40 00 8D 85 8E 13 40 00 50 FF 95 A4 13 40 00 8B 85 AC 13 40 00 89 44 24 1C 61 FF E0 8B 7C 24 04 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 98 13 40 00 89 20 89 68 04 8D 9D 4F 14 40 00 89 58 08 64 89 25 00 00 00 00 81 E7 00 00 FF FF 66 81 3F 4D 5A 75 0F 8B F7 03 76 3C 81 3E 50 45 00 00 75 02 EB 17 81 EF 00 00 01 00 81 FF 00 00 00 70 73 07 BF 00 00 F7 BF EB 02 EB D3 97 64 8F 05 00 00 00 00 83 C4 04 C2 04 00 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 98 13 40 00 89 20 89 68 04 8D 9D 4F 14 40 00 89 58 08 64 89 25 00 00 00 00 8B 74 24 0C 66 81 3E 4D 5A 74 05 E9 8A 00 00 00 03 76 3C 81 3E 50 45 00 00 74 02 EB 7D 8B 7C 24 10 B9 96 00 00 00 32 C0 F2 AE 8B CF 2B 4C 24 10 8B 56 78 03 54 24 0C 8B 5A 20 03 5C 24 0C 33 C0 8B 3B 03 7C 24 0C 8B 74 24 10 51 F3 A6 75 05 83 C4 04 EB 0A 59 83 C3 04 40 3B 42 18 75 E2 3B 42 18 75 02 EB 35 8B 72 24 03 74 24 0C 52 BB 02 00 00 00 33 D2 F7 E3 5A 03 C6 33 C9 66 8B 08 8B 7A 1C 33 D2 BB 04 00 00 00 8B C1 F7 E3 03 44 24 0C 03 C7 8B 00 03 44 24 0C EB 02 33 C0 64 8F 05 00 00 00 00 83 C4 04 C2 08 00 E8 B5 FA FF FF }
	condition:
		$1 at pe.entry_point
}

rule java_loader_uv_01 {
	meta:
		tool = "P"
		name = "JAVA Loader"
		pattern = "60E8000000005D81ED4824050164A1300000008B400C8B701CAD8B40088985762E05018D9D7E2E050153FFB5762E0501E8040200008985212F05018D9D8B2E05"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 48 24 05 01 64 A1 30 00 00 00 8B 40 0C 8B 70 1C AD 8B 40 08 89 85 76 2E 05 01 8D 9D 7E 2E 05 01 53 FF B5 76 2E 05 01 E8 04 02 00 00 89 85 21 2F 05 01 8D 9D 8B 2E 05 }
	condition:
		$1 at pe.entry_point
}

rule java_loader_uv_02 {
	meta:
		tool = "P"
		name = "JAVA Loader"
		pattern = "E8????????85C075106A01E8????????596A01FF15????????33C050505050E8D2F8FFFFC3"
	strings:
		$1 = { E8 ?? ?? ?? ?? 85 C0 75 10 6A 01 E8 ?? ?? ?? ?? 59 6A 01 FF 15 ?? ?? ?? ?? 33 C0 50 50 50 50 E8 D2 F8 FF FF C3 }
	condition:
		$1 at pe.entry_point
}

rule java_loader_uv_03 {
	meta:
		tool = "P"
		name = "JAVA Loader"
		pattern = "E8????????85C075106A01E8????????596A01FF15????????FF35????????FF35????????E8D9F8FFFF5959C3"
	strings:
		$1 = { E8 ?? ?? ?? ?? 85 C0 75 10 6A 01 E8 ?? ?? ?? ?? 59 6A 01 FF 15 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? E8 D9 F8 FF FF 59 59 C3 }
	condition:
		$1 at pe.entry_point
}

rule jcpack_uv {
	meta:
		tool = "P"
		name = "JDPack"
		pattern = "60E8????????5D8BD581ED????????2B95????????81EA06??????8995????????83BD45"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 06 ?? ?? ?? 89 95 ?? ?? ?? ?? 83 BD 45 }
	condition:
		$1 at pe.entry_point
}

rule jdpack_20 {
	meta:
		tool = "P"
		name = "JDPack"
		version = "2.0"
		pattern = "558BEC6AFF68????????68????????64A1000000005064892500000000??????E801000000????????????050000000083C40C5D60E8000000005D8BD564FF3500000000EB"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 ?? ?? ?? E8 01 00 00 00 ?? ?? ?? ?? ?? ?? 05 00 00 00 00 83 C4 0C 5D 60 E8 00 00 00 00 5D 8B D5 64 FF 35 00 00 00 00 EB }
	condition:
		$1 at pe.entry_point
}

rule jdpack_2x {
	meta:
		tool = "P"
		name = "JDPack"
		version = "2.x"
		pattern = "558BEC6AFF6868514000680425400064A100000000"
	strings:
		$1 = { 55 8B EC 6A FF 68 68 51 40 00 68 04 25 40 00 64 A1 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule jexecompressor_10 {
	meta:
		tool = "P"
		name = "JExeCompressor"
		version = "1.0"
		pattern = "8D2DD34AE5140FBBF70FBAE5730FAFD58D0D0C9FE611C0F8EFF6DE80DC5BF6DA0FA5C10FC1F11CF34A81E18C1F66910FBEC611EE0FC0E733D964F2C0DC730FC0D5558BECBAC01F41008BC2B99700000080327950B802000000500314245858512BC9B90100000083EA01E2FB59E2E1FFE0"
	strings:
		$1 = { 8D 2D D3 4A E5 14 0F BB F7 0F BA E5 73 0F AF D5 8D 0D 0C 9F E6 11 C0 F8 EF F6 DE 80 DC 5B F6 DA 0F A5 C1 0F C1 F1 1C F3 4A 81 E1 8C 1F 66 91 0F BE C6 11 EE 0F C0 E7 33 D9 64 F2 C0 DC 73 0F C0 D5 55 8B EC BA C0 1F 41 00 8B C2 B9 97 00 00 00 80 32 79 50 B8 02 00 00 00 50 03 14 24 58 58 51 2B C9 B9 01 00 00 00 83 EA 01 E2 FB 59 E2 E1 FF E0 }
	condition:
		$1 at pe.entry_point
}

rule joiner {
	meta:
		tool = "P"
		name = "Joiner"
		pattern = "81EC040100008BF46804010000566A00E87C01000033C06A0068800000006A036A006A00680000008056E8500100008BD86A006A006A006A026A0053E84401"
	strings:
		$1 = { 81 EC 04 01 00 00 8B F4 68 04 01 00 00 56 6A 00 E8 7C 01 00 00 33 C0 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 56 E8 50 01 00 00 8B D8 6A 00 6A 00 6A 00 6A 02 6A 00 53 E8 44 01 }
	condition:
		$1 at pe.entry_point
}

rule kbys_022 {
	meta:
		tool = "P"
		name = "KByS"
		version = "0.22"
		pattern = "68????????E801000000C3C31155078BECB8????????E8"
	strings:
		$1 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 ?? ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule kbys_028b_01 {
	meta:
		tool = "P"
		name = "KBys"
		version = "0.28b"
		pattern = "6885AE0101E801000000C3C3608B7424248B7C2428FCB28033DBA4B302E86D00000073F633C9E864000000731C33C0E85B0000007323B30241B010E84F000000"
	strings:
		$1 = { 68 85 AE 01 01 E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule kbys_028b_02 {
	meta:
		tool = "P"
		name = "KBys"
		version = "0.28b"
		pattern = "60E8000000005E83EE0A8B0603C28B08894EF383EE0F56528BF0ADAD03C28BD86A04BF0010000057576A00FF53085A59BD00800000556A00505152508906ADAD03C250AD03C2FFD06A0457AD506A00FF53"
	strings:
		$1 = { 60 E8 00 00 00 00 5E 83 EE 0A 8B 06 03 C2 8B 08 89 4E F3 83 EE 0F 56 52 8B F0 AD AD 03 C2 8B D8 6A 04 BF 00 10 00 00 57 57 6A 00 FF 53 08 5A 59 BD 00 80 00 00 55 6A 00 50 51 52 50 89 06 AD AD 03 C2 50 AD 03 C2 FF D0 6A 04 57 AD 50 6A 00 FF 53 }
	condition:
		$1 at pe.entry_point
}

rule kbys_028 {
	meta:
		tool = "P"
		name = "KByS"
		version = "0.28"
		pattern = "B8????????BA????????03C2FFE0????????60E800000000"
	strings:
		$1 = { B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 03 C2 FF E0 ?? ?? ?? ?? 60 E8 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule kenpack_03 {
	meta:
		tool = "P"
		name = "KenPack"
		version = "0.3"
		pattern = "6A18E814000000588D4A18518D92????????648B08FF31892189105AFFE2728B44240C8B??A80000008D8A????????60"
	strings:
		$1 = { 6A 18 E8 14 00 00 00 58 8D 4A 18 51 8D 92 ?? ?? ?? ?? 64 8B 08 FF 31 89 21 89 10 5A FF E2 72 8B 44 24 0C 8B ?? A8 00 00 00 8D 8A ?? ?? ?? ?? 60 }
	condition:
		$1 at pe.entry_point
}

rule kgcrypt {
	meta:
		tool = "P"
		name = "KGCrypt"
		pattern = "E8????????5D81ED????????64A130??????84C074??64A120??????0BC074"
	strings:
		$1 = { E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 64 A1 30 ?? ?? ?? 84 C0 74 ?? 64 A1 20 ?? ?? ?? 0B C0 74 }
	condition:
		$1 at pe.entry_point
}

rule kkrunchy_uv {
	meta:
		tool = "P"
		name = "kkrunchy"
		pattern = "BD08????00C74500??????00FF4D08C6450C058D7D1431C0B40489C1F3ABBF??????0057BE??????0031C941FF4D0C8D9C8DA0000000FFD6"
	strings:
		$1 = { BD 08 ?? ?? 00 C7 45 00 ?? ?? ?? 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? 00 57 BE ?? ?? ?? 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 }
	condition:
		$1 at pe.entry_point
}

rule kkrunchy_017 {
	meta:
		tool = "P"
		name = "kkrunchy"
		version = "0.17"
		pattern = "FCFF4D0831D28D7D30BE"
	strings:
		$1 = { FC FF 4D 08 31 D2 8D 7D 30 BE }
	condition:
		$1 at pe.entry_point
}

rule kkrunchy_023a2 {
	meta:
		tool = "P"
		name = "kkrunchy"
		version = "0.23a2"
		pattern = "BD????????C74500??????00B8??????0089450489455450C74510??????00FF4D0CFF4514FF4558C6451C08B8000800008D7D30ABABABABBB0000D800BF"
	strings:
		$1 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF }
	condition:
		$1 at pe.entry_point
}

rule krypton_02 {
	meta:
		tool = "P"
		name = "Krypton"
		version = "0.2"
		pattern = "8B0C24E90A7C01??AD4240BDBE9D7A04"
	strings:
		$1 = { 8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04 }
	condition:
		$1 at pe.entry_point
}

rule krypton_03 {
	meta:
		tool = "P"
		name = "Krypton"
		version = "0.3"
		pattern = "8B0C24E9C08D01??C13A6ECA5D7E796DB3645A71EA"
	strings:
		$1 = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA }
	condition:
		$1 at pe.entry_point
}

rule krypton_04 {
	meta:
		tool = "P"
		name = "Krypton"
		version = "0.4"
		pattern = "54E8????????5D8BC581ED6134????2B856037????83E806"
	strings:
		$1 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06 }
	condition:
		$1 at pe.entry_point
}

rule krypton_05 {
	meta:
		tool = "P"
		name = "Krypton"
		version = "0.5"
		pattern = "54E8????????5D8BC581ED7144????2B856460????EB43DF"
	strings:
		$1 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF }
	condition:
		$1 at pe.entry_point
}

rule kryptor_uv_01 {
	meta:
		tool = "P"
		name = "kryptor"
		pattern = "EB6687DB"
	strings:
		$1 = { EB 66 87 DB }
	condition:
		$1 at pe.entry_point
}
rule kryptor_uv_02 {
	meta:
		tool = "P"
		name = "kryptor"
		pattern = "EB6A87DB"
	strings:
		$1 = { EB 6A 87 DB }
	condition:
		$1 at pe.entry_point
}

rule kryptor_5 {
	meta:
		tool = "P"
		name = "kryptor"
		version = "5"
		pattern = "E803??????E9EB6C5840FFE0"
	strings:
		$1 = { E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0 }
	condition:
		$1 at pe.entry_point
}

rule kryptor_6 {
	meta:
		tool = "P"
		name = "kryptor"
		version = "6"
		pattern = "E803??????E9EB685833D27402E9E940427502"
	strings:
		$1 = { E8 03 ?? ?? ?? E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }
	condition:
		$1 at pe.entry_point
}

rule kryptor_9 {
	meta:
		tool = "P"
		name = "kryptor"
		version = "9"
		pattern = "60E8????????5EB9????????2BC002040ED3C04979F8418D7E2C3346??66B9"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }
	condition:
		$1 at pe.entry_point
}

rule lamecrypt_10 {
	meta:
		tool = "P"
		name = "LameCrypt"
		version = "1.0"
		pattern = "60669CBB????????80B300104000904B83FBFF75F3669D61"
	strings:
		$1 = { 60 66 9C BB ?? ?? ?? ?? 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 }
	condition:
		$1 at pe.entry_point
}

rule larp_20 {
	meta:
		tool = "P"
		name = "LARP"
		version = "2.0"
		pattern = "E80100000081E8020000008184E8EF0100008184E80100000064E802000000E881E881000000C38184E80400000001310000506823314000E8A10100008168D71740003BD10F87320400000F8652280000818468F117400085C90F85842800000F844204000081E8D4180000685B50E8760100008184681418400068B32C400085C00F84272800000F85FA0300008184588304240183C4040BE47404FF6424FC81E84B01000081E80100000084E8060000008184740081840BE474????????????000BE47402FFE081E80000000068????????E80200000075BAF872027302??????????????????????00E8FA00000081840BE47427E8EF0000008184E80100000050E80200000081840BE4E8D900000081847408????????????FFE2"
	strings:
		$1 = { E8 01 00 00 00 81 E8 02 00 00 00 81 84 E8 EF 01 00 00 81 84 E8 01 00 00 00 64 E8 02 00 00 00 E8 81 E8 81 00 00 00 C3 81 84 E8 04 00 00 00 01 31 00 00 50 68 23 31 40 00 E8 A1 01 00 00 81 68 D7 17 40 00 3B D1 0F 87 32 04 00 00 0F 86 52 28 00 00 81 84 68 F1 17 40 00 85 C9 0F 85 84 28 00 00 0F 84 42 04 00 00 81 E8 D4 18 00 00 68 5B 50 E8 76 01 00 00 81 84 68 14 18 40 00 68 B3 2C 40 00 85 C0 0F 84 27 28 00 00 0F 85 FA 03 00 00 81 84 58 83 04 24 01 83 C4 04 0B E4 74 04 FF 64 24 FC 81 E8 4B 01 00 00 81 E8 01 00 00 00 84 E8 06 00 00 00 81 84 74 00 81 84 0B E4 74 ?? ?? ?? ?? ?? ?? 00 0B E4 74 02 FF E0 81 E8 00 00 00 00 68 ?? ?? ?? ?? E8 02 00 00 00 75 BA F8 72 02 73 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 E8 FA 00 00 00 81 84 0B E4 74 27 E8 EF 00 00 00 81 84 E8 01 00 00 00 50 E8 02 00 00 00 81 84 0B E4 E8 D9 00 00 00 81 84 74 08 ?? ?? ?? ?? ?? ?? FF E2 }
	condition:
		$1 at pe.entry_point
}

rule launch_anywhere_4001 {
	meta:
		tool = "P"
		name = "LaunchAnywhere"
		version = "4.0.0.1"
		pattern = "55589E55383EC4855B8FFFFFFFF505068E03E420064FF35000000006489250000000068C0694400E8E480FFFF59E84E290000E8C90D000085C075086AFFE86E2B000059E8A82C0000E8232E0000FF154CC2440089C3EB193C22751489C08D4000438A0384C074043C2275F53C227501438A0384C0740B3C2074073C0975D9EB01438A0384C074043C207EF58D45B850FF15E4C144008B45E4250100000074060FB745E8EB05B80A?"
	strings:
		$1 = { 55 58 9E 55 38 3E C4 85 5B 8F FF FF FF F5 05 06 8E 03 E4 20 06 4F F3 50 00 00 00 06 48 92 50 00 00 00 06 8C 06 94 40 0E 8E 48 0F FF F5 9E 84 E2 90 00 0E 8C 90 D0 00 08 5C 07 50 86 AF FE 86 E2 B0 00 05 9E 8A 82 C0 00 0E 82 32 E0 00 0F F1 54 CC 24 40 08 9C 3E B1 93 C2 27 51 48 9C 08 D4 00 04 38 A0 38 4C 07 40 43 C2 27 5F 53 C2 27 50 14 38 A0 38 4C 07 40 B3 C2 07 40 73 C0 97 5D 9E B0 14 38 A0 38 4C 07 40 43 C2 07 EF 58 D4 5B 85 0F F1 5E 4C 14 40 08 B4 5E 42 50 10 00 00 07 40 60 FB 74 5E 8E B0 5B 80 A? }
	condition:
		$1 at pe.entry_point
}

rule launcher_generator_103 {
	meta:
		tool = "P"
		name = "Launcher Generator"
		version = "1.03"
		pattern = "680020400068102040006A006A006A206A006A006A0068F02240006A00E89300000085C00F847E000000B8000000003B056820400074136A??686023400068202340006A00E883000000A1582040003B056C2040007451C1E002A35C204000BB7021400003C38B18686020400053B8F021400003055C2040008BD88B03057020400050B87022400003055C204000FF30FF3500204000E826000000A15820400040A358204000EB"
	strings:
		$1 = { 68 00 20 40 00 68 10 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 68 F0 22 40 00 6A 00 E8 93 00 00 00 85 C0 0F 84 7E 00 00 00 B8 00 00 00 00 3B 05 68 20 40 00 74 13 6A ?? 68 60 23 40 00 68 20 23 40 00 6A 00 E8 83 00 00 00 A1 58 20 40 00 3B 05 6C 20 40 00 74 51 C1 E0 02 A3 5C 20 40 00 BB 70 21 40 00 03 C3 8B 18 68 60 20 40 00 53 B8 F0 21 40 00 03 05 5C 20 40 00 8B D8 8B 03 05 70 20 40 00 50 B8 70 22 40 00 03 05 5C 20 40 00 FF 30 FF 35 00 20 40 00 E8 26 00 00 00 A1 58 20 40 00 40 A3 58 20 40 00 EB }
	condition:
		$1 at pe.entry_point
}

rule lock98_10028 {
	meta:
		tool = "P"
		name = "LOCK98"
		version = "1.00.28"
		pattern = "55E8000000005D81??????????EB05E9????????EB08"
	strings:
		$1 = { 55 E8 00 00 00 00 5D 81 ?? ?? ?? ?? ?? EB 05 E9 ?? ?? ?? ?? EB 08 }
	condition:
		$1 at pe.entry_point
}

rule locked_uv {
	meta:
		tool = "P"
		name = "LOCKED?"
		pattern = "2923BE84E16CD6AE529049F1F1BBE9EBB3A6DB3C870C3E99245E0D1C06B747DEB3124DC843BB8BA61F035A7D0938251F"
	strings:
		$1 = { 29 23 BE 84 E1 6C D6 AE 52 90 49 F1 F1 BB E9 EB B3 A6 DB 3C 87 0C 3E 99 24 5E 0D 1C 06 B7 47 DE B3 12 4D C8 43 BB 8B A6 1F 03 5A 7D 09 38 25 1F }
	condition:
		$1 at pe.entry_point
}

rule lockless_intro_pack_uv {
	meta:
		tool = "P"
		name = "Lockless Intro Pack"
		pattern = "2CE8????????5D8BC581EDF673????2B85????????83E8068985"
	strings:
		$1 = { 2C E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 06 89 85 }
	condition:
		$1 at pe.entry_point
}

rule ltc_13 {
	meta:
		tool = "P"
		name = "LTC"
		version = "1.3"
		pattern = "54E8000000005D8BC581EDF67340002B858775400083E806"
	strings:
		$1 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 }
	condition:
		$1 at pe.entry_point
}

rule ly_wgkx_uv {
	meta:
		tool = "P"
		name = "LY_WGKX"
		pattern = "4D7946756E006273"
	strings:
		$1 = { 4D 79 46 75 6E 00 62 73 }
	condition:
		$1 at pe.entry_point
}

rule ly_wgkx_2x {
	meta:
		tool = "P"
		name = "LY_WGKX"
		version = "2.x"
		pattern = "00000000????????0000000000000000????????????????00000000000000000000000000000000000000004C59????????????????????00000000????????000000000000000000000000????????00000000000000000000000001004D7946756E0062730000"
	strings:
		$1 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C 59 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 01 00 4D 79 46 75 6E 00 62 73 00 00 }
	condition:
		$1 at pe.entry_point
}

rule macromedia_windows {
	meta:
		tool = "P"
		name = "Macromedia Windows"
		version = "6.0"
		pattern = "83EC4456FF15248149008BF08A063C22751C8A4601463C22740C84C074088A4601463C2275F4803E22750F46EB0C"
	strings:
		$1 = { 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }
	condition:
		$1 at pe.entry_point
}

rule macromedia_windows_flash_projector_40 {
	meta:
		tool = "P"
		name = "Macromedia Windows Flash Projector"
		version = "4.0"
		pattern = "83EC4456FF15244143008BF08A063C22751C8A4601463C22740C84C074088A4601463C2275F4803E22750F46EB0C"
	strings:
		$1 = { 83 EC 44 56 FF 15 24 41 43 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }
	condition:
		$1 at pe.entry_point
}

rule macromedia_windows_flash_projector_50 {
	meta:
		tool = "P"
		name = "Macromedia Windows Flash Projector"
		version = "5.0"
		pattern = "83EC4456FF15706144008BF08A063C22751C8A4601463C22740C84C074088A4601463C2275F4803E22750F46EB0C3C207E088A4601463C207FF88A0684C0740C3C207F088A46014684C075F48D442404C74424300000000050FF1580614400F644243001740B8B44243425FFFF0000EB05B80A00000050566A006A00FF157461440050E81800000050FF15786144005E83C444C3909090909090"
	strings:
		$1 = { 83 EC 44 56 FF 15 70 61 44 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74 0C 3C 20 7F 08 8A 46 01 46 84 C0 75 F4 8D 44 24 04 C7 44 24 30 00 00 00 00 50 FF 15 80 61 44 00 F6 44 24 30 01 74 0B 8B 44 24 34 25 FF FF 00 00 EB 05 B8 0A 00 00 00 50 56 6A 00 6A 00 FF 15 74 61 44 00 50 E8 18 00 00 00 50 FF 15 78 61 44 00 5E 83 C4 44 C3 90 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule marjinz_exescrambler_se {
	meta:
		tool = "P"
		name = "MarjinZ EXE-Scrambler SE"
		pattern = "E8A3020000E935FDFFFFFF25C82000106A1468C0210010E8E4010000FF357C3300108B358C200010FFD6598945E483F8FF750CFF7508FF158820001059EB616A08E802030000598365FC00FF357C330010FFD68945E4FF3578330010FFD68945E08D45E0508D45E450FF7508E8D10200008945DCFF75E48B3574200010FFD6A37C330010FF75E0FFD683C41CA378330010C745FCFEFFFFFFE8090000008B45DCE8A0010000C3"
	strings:
		$1 = { E8 A3 02 00 00 E9 35 FD FF FF FF 25 C8 20 00 10 6A 14 68 C0 21 00 10 E8 E4 01 00 00 FF 35 7C 33 00 10 8B 35 8C 20 00 10 FF D6 59 89 45 E4 83 F8 FF 75 0C FF 75 08 FF 15 88 20 00 10 59 EB 61 6A 08 E8 02 03 00 00 59 83 65 FC 00 FF 35 7C 33 00 10 FF D6 89 45 E4 FF 35 78 33 00 10 FF D6 89 45 E0 8D 45 E0 50 8D 45 E4 50 FF 75 08 E8 D1 02 00 00 89 45 DC FF 75 E4 8B 35 74 20 00 10 FF D6 A3 7C 33 00 10 FF 75 E0 FF D6 83 C4 1C A3 78 33 00 10 C7 45 FC FE FF FF FF E8 09 00 00 00 8B 45 DC E8 A0 01 00 00 C3 }
	condition:
		$1 at pe.entry_point
}

rule maskpe_16 {
	meta:
		tool = "P"
		name = "MaskPE"
		version = "1.6"
		pattern = "36812C24??????00C360"
	strings:
		$1 = { 36 81 2C 24 ?? ?? ?? 00 C3 60 }
	condition:
		$1 at pe.entry_point
}

rule maskpe_20 {
	meta:
		tool = "P"
		name = "MaskPE"
		version = "2.0"
		pattern = "B818000000648B1883C330C3403E0FB600C1E0??83C0??36010424C3"
	strings:
		$1 = { B8 18 00 00 00 64 8B 18 83 C3 30 C3 40 3E 0F B6 00 C1 E0 ?? 83 C0 ?? 36 01 04 24 C3 }
	condition:
		$1 at pe.entry_point
}

rule matrix_dongle_uv_01 {
	meta:
		tool = "P"
		name = "Matrix Dongle"
		pattern = "000000000000000000000000????????????????0000000000000000000000000000000000000000????????????????0000000000004C6F61644C6962726172794100000047657450726F6341646472657373004B45524E454C33322E444C4C00E8B6000000000000000000????????????E8000000005B2BD98BF88B4C242C33C02BCFF2AA8B3C248B0A2BCF895C24208037A2474975F98D642404FF6424FC60C74208????????E8C5FFFFFFC3C2F7294E295A29E6868A89635CA265E2A3A2"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 E8 B6 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? E8 00 00 00 00 5B 2B D9 8B F8 8B 4C 24 2C 33 C0 2B CF F2 AA 8B 3C 24 8B 0A 2B CF 89 5C 24 20 80 37 A2 47 49 75 F9 8D 64 24 04 FF 64 24 FC 60 C7 42 08 ?? ?? ?? ?? E8 C5 FF FF FF C3 C2 F7 29 4E 29 5A 29 E6 86 8A 89 63 5C A2 65 E2 A3 A2 }
	condition:
		$1 at pe.entry_point
}

rule matrix_dongle_uv_02 {
	meta:
		tool = "P"
		name = "Matrix Dongle"
		pattern = "E800000000E800000000595A2BCA2BD1E81AFFFFFF"
	strings:
		$1 = { E8 00 00 00 00 E8 00 00 00 00 59 5A 2B CA 2B D1 E8 1A FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule mew_10_10 {
	meta:
		tool = "P"
		name = "MEW"
		version = "10 1.0"
		pattern = "33C0E9???0??FF"
	strings:
		$1 = { 33 C0 E9 ?? ?0 ?? FF }
	condition:
		$1 at pe.entry_point
}

rule mew_11_se_10 {
	meta:
		tool = "P"
		name = "MEW"
		version = "11 SE 1.0"
		pattern = "E9????????000000020000000C?0"
	strings:
		$1 = { E9 ?? ?? ?? ?? 00 00 00 02 00 00 00 0C ?0 }
	condition:
		$1 at pe.entry_point
}

rule mew_11_se_12 {
	meta:
		tool = "P"
		name = "MEW"
		version = "11 SE 1.2"
		pattern = "EB02FA04E84900000069E84900000095E84F00000068E81F00000049E8E9FFFFFF67E81F00000093E83100000078E8DDFFFFFF38E8E3FFFFFF66E80D00000004E8E3FFFFFF70E8CBFFFFFF69E8DDFFFFFF58E8DDFFFFFF69E8E3FFFFFF79E8BFFFFFFF6983C440E8000000005D81ED9D1140008D95B411"
    start = 48
	strings:
		$1 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 9D 11 40 00 8D 95 B4 11 }
	condition:
		$1 at pe.entry_point + 48
}

rule mew_11_se_10_12 {
	meta:
		tool = "P"
		name = "MEW"
		version = "11 SE 1.0 - 1.2"
		pattern = "E9??????FF0??0??0?0000000??0??00??????????0??0"
	strings:
		$1 = { E9 ?? ?? ?? FF 0? ?0 ?? 0? 00 00 00 0? ?0 ?? 00 ?? ?? ?? ?? ?? 0? ?0 }
	condition:
		$1 at pe.entry_point
}

rule mew_5xx {
	meta:
		tool = "P"
		name = "MEW"
		version = "5.x.x"
		pattern = "BE5B004000AD91AD9353AD96565FACC0C0"
	strings:
		$1 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 }
	condition:
		$1 at pe.entry_point
}

rule mew_501 {
	meta:
		tool = "P"
		name = "MEW"
		version = "5.0.1"
		pattern = "BE5B004000AD91AD9353AD96565FACC0C0??04??C0C8??AAE2F4C300????00??????00001040004D455720302E31206279204E6F727468666F78004D455720302E31206279204E6F727468666F78004D455720302E31206279204E6F727468666F78004D455720302E31206279204E6F727468666F78004D"
	strings:
		$1 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 00 ?? ?? 00 ?? ?? ?? 00 00 10 40 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D }
	condition:
		$1 at pe.entry_point
}

rule microdog_win32shell_4093 {
	meta:
		tool = "P"
		name = "MicroDog Win32Shell"
		version = "4.0.9.3"
		pattern = "807C2408010F8519FFFFFFE9AFECFFFF9090909090558BEC83EC185356578B45088B00C1E8108945FC8B45088B0025FFFF00008945F8C745F45A010000C745EC354E00008B45F40FAF45F825FFFF00008945F0837DFC00740F8B45EC0FAF45FC25FFFF00000145F08B45EC0FAF45F88B4DF0C1E11081E10000FFFF03C1408945E88B45E88B4D088901C16DE8108165E8FF7F0000668B45E8EB005F5E5BC9C3"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 19 FF FF FF E9 AF EC FF FF 90 90 90 90 90 55 8B EC 83 EC 18 53 56 57 8B 45 08 8B 00 C1 E8 10 89 45 FC 8B 45 08 8B 00 25 FF FF 00 00 89 45 F8 C7 45 F4 5A 01 00 00 C7 45 EC 35 4E 00 00 8B 45 F4 0F AF 45 F8 25 FF FF 00 00 89 45 F0 83 7D FC 00 74 0F 8B 45 EC 0F AF 45 FC 25 FF FF 00 00 01 45 F0 8B 45 EC 0F AF 45 F8 8B 4D F0 C1 E1 10 81 E1 00 00 FF FF 03 C1 40 89 45 E8 8B 45 E8 8B 4D 08 89 01 C1 6D E8 10 81 65 E8 FF 7F 00 00 66 8B 45 E8 EB 00 5F 5E 5B C9 C3 }
	condition:
		$1 at pe.entry_point
}

rule microdog_win32shell_4x {
	meta:
		tool = "P"
		name = "MicroDog Win32Shell"
		version = "4.x"
		pattern = "60558BEC81EC????????535657C685??????????C685??????????C685??????????C685??????????8DBD????????33C0B93F??????F3ABC685??????????C685??????????C685??????????C685??????????8DBD????????33C0B93F??????F3ABC785????????????????66C7??????????????E913090000??68????????E8????????83????89????83??????7505E9C111000068????????A1????????508B????50E8????????83????A1????????33??????????89??????????8B??????????89????E9CE0E0000E936110000E93D110000E93811000066??????????EB0466??????8B????25FFFF000083????0F8DDF0000008B????25FFFF00008B????81E1FFFF00000FAFC18B????81E1FFFF00000FAFC18B????81E1FFFF00000FAFC183????89??????????EB7E"
	strings:
		$1 = { 60 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 33 C0 B9 3F ?? ?? ?? F3 AB C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 33 C0 B9 3F ?? ?? ?? F3 AB C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 66 C7 ?? ?? ?? ?? ?? ?? ?? E9 13 09 00 00 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? 83 ?? ?? ?? 75 05 E9 C1 11 00 00 68 ?? ?? ?? ?? A1 ?? ?? ?? ?? 50 8B ?? ?? 50 E8 ?? ?? ?? ?? 83 ?? ?? A1 ?? ?? ?? ?? 33 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? E9 CE 0E 00 00 E9 36 11 00 00 E9 3D 11 00 00 E9 38 11 00 00 66 ?? ?? ?? ?? ?? EB 04 66 ?? ?? ?? 8B ?? ?? 25 FF FF 00 00 83 ?? ?? 0F 8D DF 00 00 00 8B ?? ?? 25 FF FF 00 00 8B ?? ?? 81 E1 FF FF 00 00 0F AF C1 8B ?? ?? 81 E1 FF FF 00 00 0F AF C1 8B ?? ?? 81 E1 FF FF 00 00 0F AF C1 83 ?? ?? 89 ?? ?? ?? ?? ?? EB 7E }
	condition:
		$1 at pe.entry_point
}

rule microjoiner_11 {
	meta:
		tool = "P"
		name = "MicroJoiner"
		version = "1.1"
		pattern = "BE0C704000BBF811400033ED83EE04392E7411"
	strings:
		$1 = { BE 0C 70 40 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }
	condition:
		$1 at pe.entry_point
}

rule microjoiner_15 {
	meta:
		tool = "P"
		name = "MicroJoiner"
		version = "1.5"
		pattern = "BF0510400083EC308BECE8C8FFFFFFE8C3FFFFFF"
	strings:
		$1 = { BF 05 10 40 00 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule microjoiner_16 {
	meta:
		tool = "P"
		name = "MicroJoiner"
		version = "1.6"
		pattern = "33C0648B38488BC8F2AFAF8B1F6633DB66813B"
	strings:
		$1 = { 33 C0 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B }
	condition:
		$1 at pe.entry_point
}

rule microjoiner_17 {
	meta:
		tool = "P"
		name = "MicroJoiner"
		version = "1.7"
		pattern = "BF001040008D5F216A0A586A04596057E88E000000"
	strings:
		$1 = { BF 00 10 40 00 8D 5F 21 6A 0A 58 6A 04 59 60 57 E8 8E 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule minke_101_01 {
	meta:
		tool = "P"
		name = "Minke"
		version = "1.0.1"
		pattern = "263D4F38C28237B8F3244203179B3A83010000CC000000000600000001645374756200105554797065730000C753797374656D000081537973496E6974000C4B57696E646F777300008A7546756E6374696F6E73"
	strings:
		$1 = { 26 3D 4F 38 C2 82 37 B8 F3 24 42 03 17 9B 3A 83 01 00 00 CC 00 00 00 00 06 00 00 00 01 64 53 74 75 62 00 10 55 54 79 70 65 73 00 00 C7 53 79 73 74 65 6D 00 00 81 53 79 73 49 6E 69 74 00 0C 4B 57 69 6E 64 6F 77 73 00 00 8A 75 46 75 6E 63 74 69 6F 6E 73 }
	condition:
		$1 at pe.entry_point
}

rule minke_101_02 {
	meta:
		tool = "P"
		name = "Minke"
		version = "1.0.1"
		pattern = "558BEC83C4F053??????????10E87AF6FFFFBE6866001033C05568DB40001064FF30648920E8FAF8FFFFBAEC4000108BC6E8F2FAFFFF8BD8B86C6600108B16E888F2FFFFB86C660010E876F2FFFF8BD08BC38B0EE8E3E4FFFFE82AF9FFFFE8C1F8FFFFB86C6600108B16E86DFAFFFFE814F9FFFFE8ABF8FFFF8B06E8B8E3FFFF8BD8B86C660010E838F2FFFF8BD38B0EE8A7E4FF????????C4FBFFFFE8E7F8FFFF8BC3E8B0E3FFFFE8DBF8FFFF33C05A595964891068E2400010C3E950EBFFFFEBF85E5BE8BBEFFFFF00000043413138"
	strings:
		$1 = { 55 8B EC 83 C4 F0 53 ?? ?? ?? ?? ?? 10 E8 7A F6 FF FF BE 68 66 00 10 33 C0 55 68 DB 40 00 10 64 FF 30 64 89 20 E8 FA F8 FF FF BA EC 40 00 10 8B C6 E8 F2 FA FF FF 8B D8 B8 6C 66 00 10 8B 16 E8 88 F2 FF FF B8 6C 66 00 10 E8 76 F2 FF FF 8B D0 8B C3 8B 0E E8 E3 E4 FF FF E8 2A F9 FF FF E8 C1 F8 FF FF B8 6C 66 00 10 8B 16 E8 6D FA FF FF E8 14 F9 FF FF E8 AB F8 FF FF 8B 06 E8 B8 E3 FF FF 8B D8 B8 6C 66 00 10 E8 38 F2 FF FF 8B D3 8B 0E E8 A7 E4 FF ?? ?? ?? ?? C4 FB FF FF E8 E7 F8 FF FF 8B C3 E8 B0 E3 FF FF E8 DB F8 FF FF 33 C0 5A 59 59 64 89 10 68 E2 40 00 10 C3 E9 50 EB FF FF EB F8 5E 5B E8 BB EF FF FF 00 00 00 43 41 31 38 }
	condition:
		$1 at pe.entry_point
}

rule mkfpack_uv {
	meta:
		tool = "P"
		name = "mkfpack"
		pattern = "E8000000005B81EB050000008B939F080000536A??68????????526A00FF93320800005B8BF08BBB9B08000003FB5657E88608000083C4088D93BB0800005253FFE6"
	strings:
		$1 = { E8 00 00 00 00 5B 81 EB 05 00 00 00 8B 93 9F 08 00 00 53 6A ?? 68 ?? ?? ?? ?? 52 6A 00 FF 93 32 08 00 00 5B 8B F0 8B BB 9B 08 00 00 03 FB 56 57 E8 86 08 00 00 83 C4 08 8D 93 BB 08 00 00 52 53 FF E6 }
	condition:
		$1 at pe.entry_point
}

rule molebox_uv {
	meta:
		tool = "P"
		name = "MoleBox"
		pattern = "60E84F000000"
	strings:
		$1 = { 60 E8 4F 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule molebox_20 {
	meta:
		tool = "P"
		name = "MoleBox"
		version = "2.0"
		pattern = "E8????????60E8"
	strings:
		$1 = { E8 ?? ?? ?? ?? 60 E8 }
	condition:
		$1 at pe.entry_point
}

rule molebox_230 {
	meta:
		tool = "P"
		name = "MoleBox"
		version = "2.3.0"
		pattern = "4204E8????0000A3??????008B4DF08B118915??????00??45FCA3??????005F5E8BE55DC3CCCCCCCCCCCCCCCCCCCCCCE8EBFBFFFF58E8??07000058894424206158FFD0E8????0000CCCCCCCCCCCCCC"
	strings:
		$1 = { 42 04 E8 ?? ?? 00 00 A3 ?? ?? ?? 00 8B 4D F0 8B 11 89 15 ?? ?? ?? 00 ?? 45 FC A3 ?? ?? ?? 00 5F 5E 8B E5 5D C3 CC CC CC CC CC CC CC CC CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 20 61 58 FF D0 E8 ?? ?? 00 00 CC CC CC CC CC CC CC }
	condition:
		$1 at pe.entry_point
}

rule molebox_23x {
	meta:
		tool = "P"
		name = "MoleBox"
		version = "2.3.x"
		pattern = "E80000000060E84F000000"
	strings:
		$1 = { E8 00 00 00 00 60 E8 4F 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule molebox_254 {
	meta:
		tool = "P"
		name = "MoleBox"
		version = "2.5.4"
		pattern = "??????008B4DF08B118915??????008B45FCA3??????005F5E8BE55DC3CCCCCCE8EBFBFFFF58E8??0700005889442424615858FFD0E8????00006A00FF15??????00CCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	strings:
		$1 = { ?? ?? ?? 00 8B 4D F0 8B 11 89 15 ?? ?? ?? 00 8B 45 FC A3 ?? ?? ?? 00 5F 5E 8B E5 5D C3 CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 24 61 58 58 FF D0 E8 ?? ?? 00 00 6A 00 FF 15 ?? ?? ?? 00 CC CC CC CC CC CC CC CC CC CC CC CC CC CC }
	condition:
		$1 at pe.entry_point
}

rule molebox_pro_255 {
	meta:
		tool = "P"
		name = "MoleBox Pro"
		version = "2.5.5"
		pattern = "E80000000060E84F000000????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????E9CA690000E9DE690000E9D9690000E85EFBFFFF3EF40000"
	strings:
		$1 = { E8 00 00 00 00 60 E8 4F 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9 CA 69 00 00 E9 DE 69 00 00 E9 D9 69 00 00 E8 5E FB FF FF 3E F4 00 00 }
	condition:
		$1 at pe.entry_point
}

rule molebox_pro_43018 {
	meta:
		tool = "P"
		name = "MoleBoxPro"
		version = "4.3018"
		pattern = "5589E5???C0???0?????????????????????00???????????0??????0000??0???????????0?????????????????????????????????????????????????0?0???????B????000?????????????4???????????????????????????????0??????89"
	strings:
		$1 = { 55 89 E5 ?? ?C 0? ?? 0? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?0 ?? ?? ?? 00 00 ?? 0? ?? ?? ?? ?? ?? 0? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0? 0? ?? ?? ?? B? ?? ?0 00 ?? ?? ?? ?? ?? ?? ?4 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?0 ?? ?? ?? 89 }
	condition:
		$1 at pe.entry_point
}

rule kaos_pe_exe_undetecter_uv {
	meta:
		tool = "P"
		name = "KaOs PE eXecutable Undetecter"
		pattern = "60FC0FB605????????????7531B8????????2B05??????????????????????????????05????????A3????????E89A000000A3"
	strings:
		$1 = { 60 FC 0F B6 05 ?? ?? ?? ?? ?? ?? 75 31 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9A 00 00 00 A3 }
	condition:
		$1 at pe.entry_point
}

rule k_kryptor_011 {
	meta:
		tool = "P"
		name = "K!Cryptor"
		version = "0.11"
		pattern = "558BEC83EC??53565733DB53FF15????????8B3D????????8945??B8????????FF30BE????????56E8????????68????????6A??E8????????83C4??6A??68????????5753FFD0"
	strings:
		$1 = { 55 8B EC 83 EC ?? 53 56 57 33 DB 53 FF 15 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 89 45 ?? B8 ?? ?? ?? ?? FF 30 BE ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 68 ?? ?? ?? ?? 57 53 FF D0 }
	condition:
		$1 at pe.entry_point
}

rule morphnah_beta {
	meta:
		tool = "P"
		name = "Morphnah"
		version = "Beta"
		pattern = "2E6E616800000000????????????????????????????????000000000000000000000000A00000E0"
	strings:
		$1 = { 2E 6E 61 68 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 A0 00 00 E0 }
	condition:
		$1 at pe.entry_point
}

rule mpack_002 {
	meta:
		tool = "P"
		name = "mPack"
		version = "0.0.2"
		pattern = "E90000000060E8140000005D81ED000000006A45E8A30000006800000000E85861E8AA0000004E"
	strings:
		$1 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 E8 AA 00 00 00 4E }
	condition:
		$1 at pe.entry_point
}
rule mpack_003_01 {
	meta:
		tool = "P"
		name = "mPack"
		version = "0.0.3"
		pattern = "558BEC83C4F033C08945F0B8A8760010E867C4FFFF33C05568C278001064FF306489208D55F033C0E893C8FFFF8B45F0E887CBFFFFA308A5001033C05568A578001064FF30648920A108A50010E8FAC9FFFF83F8FF750AE888B2FFFFE91B010000C70514A5001032000000A108A500108B1514A50010E8C9C9FFFFBA14A50010A108A50010B904000000E8C5C9FFFF833D14A5001032770AE847B2FFFFE9DA000000A108A500108B1514A50010E892C9FFFFBA18A5"
	strings:
		$1 = { 55 8B EC 83 C4 F0 33 C0 89 45 F0 B8 A8 76 00 10 E8 67 C4 FF FF 33 C0 55 68 C2 78 00 10 64 FF 30 64 89 20 8D 55 F0 33 C0 E8 93 C8 FF FF 8B 45 F0 E8 87 CB FF FF A3 08 A5 00 10 33 C0 55 68 A5 78 00 10 64 FF 30 64 89 20 A1 08 A5 00 10 E8 FA C9 FF FF 83 F8 FF 75 0A E8 88 B2 FF FF E9 1B 01 00 00 C7 05 14 A5 00 10 32 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 C9 C9 FF FF BA 14 A5 00 10 A1 08 A5 00 10 B9 04 00 00 00 E8 C5 C9 FF FF 83 3D 14 A5 00 10 32 77 0A E8 47 B2 FF FF E9 DA 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 92 C9 FF FF BA 18 A5 }
	condition:
		$1 at pe.entry_point
}

rule mpack_003_02 {
	meta:
		tool = "P"
		name = "mPack"
		version = "0.0.3"
		pattern = "558BEC83????33C08945F0B8????????E867C4FFFF33C05568????????64FF306489208D55F033C0E893C8FFFF8B45F0E887CBFFFFA3????????33C05568????????64FF30648920A1????????E8FAC9FFFF83F8FF750AE888B2FFFFE91B010000C705????????32000000A1????????8B15????????E8C9C9FFFFBA????????A1????????B904000000E8C5C9FFFF833D????????32770AE847B2FFFFE9DA000000A1????????8B15????????E892C9FFFFBA18A50010A1????????B904000000E88EC9FFFF83F804740AE814B2FFFFE9A7000000E80ACBFFFFA3????????A1????????E863C9FFFF83F8FF750AE8F1B1FFFFE9840000006A006A00B8????????8B15????????E8D4CDFFFF84C07507E8CFB1FFFFEB658B0D????????8B15????????A1????????E80FFAFFFF3B05????????750DA1????????8B403CE86EFBFFFF6A03E807C4FFFFA1????????E8C1C6FFFF33C05A595964891068????????A1????????E8AAC6FFFFA1????????E8A0C6FFFFC3E9AEB0FFFFEBE433C05A595964891068????????8D45F0E8A7B5FFFFC3E991B0FFFFEBF0E862B4FFFF"
	strings:
		$1 = { 55 8B EC 83 ?? ?? 33 C0 89 45 F0 B8 ?? ?? ?? ?? E8 67 C4 FF FF 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 F0 33 C0 E8 93 C8 FF FF 8B 45 F0 E8 87 CB FF FF A3 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 A1 ?? ?? ?? ?? E8 FA C9 FF FF 83 F8 FF 75 0A E8 88 B2 FF FF E9 1B 01 00 00 C7 05 ?? ?? ?? ?? 32 00 00 00 A1 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 C9 C9 FF FF BA ?? ?? ?? ?? A1 ?? ?? ?? ?? B9 04 00 00 00 E8 C5 C9 FF FF 83 3D ?? ?? ?? ?? 32 77 0A E8 47 B2 FF FF E9 DA 00 00 00 A1 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 92 C9 FF FF BA 18 A5 00 10 A1 ?? ?? ?? ?? B9 04 00 00 00 E8 8E C9 FF FF 83 F8 04 74 0A E8 14 B2 FF FF E9 A7 00 00 00 E8 0A CB FF FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 63 C9 FF FF 83 F8 FF 75 0A E8 F1 B1 FF FF E9 84 00 00 00 6A 00 6A 00 B8 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? E8 D4 CD FF FF 84 C0 75 07 E8 CF B1 FF FF EB 65 8B 0D ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 0F FA FF FF 3B 05 ?? ?? ?? ?? 75 0D A1 ?? ?? ?? ?? 8B 40 3C E8 6E FB FF FF 6A 03 E8 07 C4 FF FF A1 ?? ?? ?? ?? E8 C1 C6 FF FF 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? A1 ?? ?? ?? ?? E8 AA C6 FF FF A1 ?? ?? ?? ?? E8 A0 C6 FF FF C3 E9 AE B0 FF FF EB E4 33 C0 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 F0 E8 A7 B5 FF FF C3 E9 91 B0 FF FF EB F0 E8 62 B4 FF FF }
	condition:
		$1 at pe.entry_point
}

rule mpress_071a_075b {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "0.71a - 0.75b"
		pattern = "575653515255E810000000E87A0000005D5A595B5E5FE984010000E8000000005805840100008B3003F02BC08BFE66ADC1E00C8BC8AD2BC803F18BC8498A4439067405880431EBF48804312BC0AC0AC074378AC8243F80E1C0C1E01066AD80F9C0741EF6C140750A8BC82BC0F3AA75FCEBD98BD68BCF03F0E88F00000003F8EBCA8BC8F3A475FCEBC2C3E8000000005F81C771FFFFFFB0E9AAB89A010000AB2BFFE8000000005805FE0000008B78088BD78B78040BFF74538B3003F02BF28BEE8BC28B453C03C58B48342BCD743DE8000000005805DD0000008B1003F203FE2BC0AD3BF773258BD8AD3BF7731E8BD083EA0803D666AD0AE4740B25FF0F000003C303C529083BF273D8EBE9C3"
	strings:
		$1 = { 57 56 53 51 52 55 E8 10 00 00 00 E8 7A 00 00 00 5D 5A 59 5B 5E 5F E9 84 01 00 00 E8 00 00 00 00 58 05 84 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 AD 2B C8 03 F1 8B C8 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 AC 0A C0 74 37 8A C8 24 3F 80 E1 C0 C1 E0 10 66 AD 80 F9 C0 74 1E F6 C1 40 75 0A 8B C8 2B C0 F3 AA 75 FC EB D9 8B D6 8B CF 03 F0 E8 8F 00 00 00 03 F8 EB CA 8B C8 F3 A4 75 FC EB C2 C3 E8 00 00 00 00 5F 81 C7 71 FF FF FF B0 E9 AA B8 9A 01 00 00 AB 2B FF E8 00 00 00 00 58 05 FE 00 00 00 8B 78 08 8B D7 8B 78 04 0B FF 74 53 8B 30 03 F0 2B F2 8B EE 8B C2 8B 45 3C 03 C5 8B 48 34 2B CD 74 3D E8 00 00 00 00 58 05 DD 00 00 00 8B 10 03 F2 03 FE 2B C0 AD 3B F7 73 25 8B D8 AD 3B F7 73 1E 8B D0 83 EA 08 03 D6 66 AD 0A E4 74 0B 25 FF 0F 00 00 03 C3 03 C5 29 08 3B F2 73 D8 EB E9 C3 }
	condition:
		$1 at pe.entry_point
}

rule mpress_077b {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "0.77b"
		pattern = "60E80B000000E87700000061E975010000E8000000005805750100008B3003F02BC08BFE66ADC1E00C8BC8AD2BC803F18BC8498A4439067405880431EBF48804312BC03BFE733AAC0AC074358AC8243F80E1C0C1E01066AD80F9C0741CF6C14075088BC82BC0F3AAEBD78BD68BCF03F0E87E00000003F8EBC88BC8F3A475FCEBC0C3E8000000005F81C779FFFFFFB0E9AAB881010000AB2BFFE8000000005805ED0000008B78088BD78B78040BFF74428B3003F02BF28BEE8B48102BCD74338B500C03F203FE2BC0AD3BF773258BD8AD3BF7731E8BD083EA0803D666AD0AE4740B25FF0F000003C303C529083BF273D8EBE9C3"
	strings:
		$1 = { 60 E8 0B 00 00 00 E8 77 00 00 00 61 E9 75 01 00 00 E8 00 00 00 00 58 05 75 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 AD 2B C8 03 F1 8B C8 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 3A AC 0A C0 74 35 8A C8 24 3F 80 E1 C0 C1 E0 10 66 AD 80 F9 C0 74 1C F6 C1 40 75 08 8B C8 2B C0 F3 AA EB D7 8B D6 8B CF 03 F0 E8 7E 00 00 00 03 F8 EB C8 8B C8 F3 A4 75 FC EB C0 C3 E8 00 00 00 00 5F 81 C7 79 FF FF FF B0 E9 AA B8 81 01 00 00 AB 2B FF E8 00 00 00 00 58 05 ED 00 00 00 8B 78 08 8B D7 8B 78 04 0B FF 74 42 8B 30 03 F0 2B F2 8B EE 8B 48 10 2B CD 74 33 8B 50 0C 03 F2 03 FE 2B C0 AD 3B F7 73 25 8B D8 AD 3B F7 73 1E 8B D0 83 EA 08 03 D6 66 AD 0A E4 74 0B 25 FF 0F 00 00 03 C3 03 C5 29 08 3B F2 73 D8 EB E9 C3 }
	condition:
		$1 at pe.entry_point
}

rule mpress_085_092 {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "0.85 - 0.92"
		pattern = "60E8000000005805480100008B3003F02BC08BFE66ADC1E00C8BC850AD2BC803F18BC857498A4439067405880431EBF48804312BC03BFE7328AC0AC074238AC8243FC1E01066AD80E140740F8BD68BCF03F0E85F00000003F8EBD88BC8F3A4EBD25E5A83EA052BC93BCA73258BD9AC4124FE3CE875F283C104AD0BC078063BC273E6EB0603C378E003C22BC38946FCEBD7E8000000005F81C76AFFFFFFB0E9AAB844010000ABE8000000005805A3000000E9930000005356578BF98BF28BDA03D8515533C08BEB8BDE2BD22BC9EB4F3BDD736C2BC9668B038D5B028ACC80E40F0BC07502B410C0E90480C10380F91272198A0B6683C112436681F91101720B668B0B81C11101000043438BF72BF0F3A412D2740A72B98A0343880747EBF23BDD731D0A13F9740343EBE68B430189078B43058947048D5B098D7F0833C0EBDF5D8BC7592BC15F5E5BC3E9"
	strings:
		$1 = { 60 E8 00 00 00 00 58 05 48 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 28 AC 0A C0 74 23 8A C8 24 3F C1 E0 10 66 AD 80 E1 40 74 0F 8B D6 8B CF 03 F0 E8 5F 00 00 00 03 F8 EB D8 8B C8 F3 A4 EB D2 5E 5A 83 EA 05 2B C9 3B CA 73 25 8B D9 AC 41 24 FE 3C E8 75 F2 83 C1 04 AD 0B C0 78 06 3B C2 73 E6 EB 06 03 C3 78 E0 03 C2 2B C3 89 46 FC EB D7 E8 00 00 00 00 5F 81 C7 6A FF FF FF B0 E9 AA B8 44 01 00 00 AB E8 00 00 00 00 58 05 A3 00 00 00 E9 93 00 00 00 53 56 57 8B F9 8B F2 8B DA 03 D8 51 55 33 C0 8B EB 8B DE 2B D2 2B C9 EB 4F 3B DD 73 6C 2B C9 66 8B 03 8D 5B 02 8A CC 80 E4 0F 0B C0 75 02 B4 10 C0 E9 04 80 C1 03 80 F9 12 72 19 8A 0B 66 83 C1 12 43 66 81 F9 11 01 72 0B 66 8B 0B 81 C1 11 01 00 00 43 43 8B F7 2B F0 F3 A4 12 D2 74 0A 72 B9 8A 03 43 88 07 47 EB F2 3B DD 73 1D 0A 13 F9 74 03 43 EB E6 8B 43 01 89 07 8B 43 05 89 47 04 8D 5B 09 8D 7F 08 33 C0 EB DF 5D 8B C7 59 2B C1 5F 5E 5B C3 E9 }
	condition:
		$1 at pe.entry_point
}

rule mpress_097_099 {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "0.97 - 0.99"
		pattern = "60E8000000005805490100008B3003F02BC08BFE66ADC1E00C8BC850AD2BC803F18BC857498A4439067405880431EBF48804312BC03BFE7328AC0AC074238AC8243FC1E01066AD80E140740F8BD68BCF03F0E86000000003F8EBD88BC8F3A4EBD25E5A83EA052BC93BCA73268BD9AC4124FE3CE875F24383C104AD0BC078063BC273E5EB0603C378DF03C22BC38946FCEBD6E8000000005F81C769FFFFFFB0E9AAB845010000ABE8000000005805A3000000E9930000005356578BF98BF28BDA03D8515533C08BEB8BDE2BD22BC9EB4F3BDD736C2BC9668B038D5B028ACC80E40F0BC07502B410C0E90480C10380F91272198A0B6683C112436681F91101720B668B0B81C11101000043438BF72BF0F3A412D2740A72B98A0343880747EBF23BDD731D0A13F9740343EBE68B430189078B43058947048D5B098D7F0833C0EBDF5D8BC7592BC15F5E5BC3E9"
	strings:
		$1 = { 60 E8 00 00 00 00 58 05 49 01 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 2B C0 3B FE 73 28 AC 0A C0 74 23 8A C8 24 3F C1 E0 10 66 AD 80 E1 40 74 0F 8B D6 8B CF 03 F0 E8 60 00 00 00 03 F8 EB D8 8B C8 F3 A4 EB D2 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 69 FF FF FF B0 E9 AA B8 45 01 00 00 AB E8 00 00 00 00 58 05 A3 00 00 00 E9 93 00 00 00 53 56 57 8B F9 8B F2 8B DA 03 D8 51 55 33 C0 8B EB 8B DE 2B D2 2B C9 EB 4F 3B DD 73 6C 2B C9 66 8B 03 8D 5B 02 8A CC 80 E4 0F 0B C0 75 02 B4 10 C0 E9 04 80 C1 03 80 F9 12 72 19 8A 0B 66 83 C1 12 43 66 81 F9 11 01 72 0B 66 8B 0B 81 C1 11 01 00 00 43 43 8B F7 2B F0 F3 A4 12 D2 74 0A 72 B9 8A 03 43 88 07 47 EB F2 3B DD 73 1D 0A 13 F9 74 03 43 EB E6 8B 43 01 89 07 8B 43 05 89 47 04 8D 5B 09 8D 7F 08 33 C0 EB DF 5D 8B C7 59 2B C1 5F 5E 5B C3 E9 }
	condition:
		$1 at pe.entry_point
}

rule mpress_101_105 {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "1.01 - 1.05"
		pattern = "60E8000000005805B60200008B3003F02BC08BFE66ADC1E00C8BC850AD2BC803F18BC85751498A443906"
	strings:
		$1 = { 60 E8 00 00 00 00 58 05 B6 02 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 }
	condition:
		$1 at pe.entry_point
}

rule mpress_107_127 {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "1.07 - 1.27"
		pattern = "60E80000000058059E0200008B3003F02BC08BFE66ADC1E00C8BC850AD2BC803F18BC85751498A4439067405880431EBF48804318BD68BCFE8560000005E5A83EA052BC93BCA73268BD9AC4124FE3CE875F24383C104AD0BC078063BC273E5EB0603C378DF03C22BC38946FCEBD6E8000000005F81C78DFFFFFFB0E9AAB89A020000ABE80000000058051C020000E90C020000"
	strings:
		$1 = { 60 E8 00 00 00 00 58 05 9E 02 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 74 05 88 04 31 EB F4 88 04 31 8B D6 8B CF E8 56 00 00 00 5E 5A 83 EA 05 2B C9 3B CA 73 26 8B D9 AC 41 24 FE 3C E8 75 F2 43 83 C1 04 AD 0B C0 78 06 3B C2 73 E5 EB 06 03 C3 78 DF 03 C2 2B C3 89 46 FC EB D6 E8 00 00 00 00 5F 81 C7 8D FF FF FF B0 E9 AA B8 9A 02 00 00 AB E8 00 00 00 00 58 05 1C 02 00 00 E9 0C 02 00 00 }
	condition:
		$1 at pe.entry_point
}

rule mpress_1x_2x {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "1.x - 2.x"
		pattern = "60E8000000005805????????8B3003F02BC08BFE66ADC1E00C8BC850AD2BC803F18BC85751498A443906"
	strings:
		$1 = { 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 }
	condition:
		$1 at pe.entry_point
}

rule mpress_201_lzma {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "2.01 [LZMA]"
		pattern = "60E80000000058055E0B00008B3003F02BC08BFE66ADC1E00C8BC850AD2BC803F18BC85751498A443906"
	strings:
		$1 = { 60 E8 00 00 00 00 58 05 5E 0B 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 }
	condition:
		$1 at pe.entry_point
}

rule mpress_201_lzmat {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "2.01 [LZMAT]"
		pattern = "60E8000000005805990200008B3003F02BC08BFE66ADC1E00C8BC850AD2BC803F18BC85751498A443906"
	strings:
		$1 = { 60 E8 00 00 00 00 58 05 99 02 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 }
	condition:
		$1 at pe.entry_point
}

rule mpress_205_lzma {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "2.05 [LZMA]"
		pattern = "60E8000000005805570B00008B3003F02BC08BFE66ADC1E00C8BC850AD2BC803F18BC85751498A443906"
	strings:
		$1 = { 60 E8 00 00 00 00 58 05 57 0B 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 }
	condition:
		$1 at pe.entry_point
}

rule mpress_205_lzmat {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "2.05 [LZMAT]"
		pattern = "60E80000000058059C0200008B3003F02BC08BFE66ADC1E00C8BC850AD2BC803F18BC85751498A443906"
	strings:
		$1 = { 60 E8 00 00 00 00 58 05 9C 02 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 }
	condition:
		$1 at pe.entry_point
}

rule mpress_212_219_lzma {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "2.12 - 2.19 [LZMA]"
		pattern = "60E80000000058055A0B00008B3003F02BC08BFE66ADC1E00C8BC850AD2BC803F18BC85751498A443906"
	strings:
		$1 = { 60 E8 00 00 00 00 58 05 5A 0B 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 }
	condition:
		$1 at pe.entry_point
}

rule mpress_212_219_lzmat {
	meta:
		tool = "P"
		name = "MPRESS"
		version = "2.12 - 2.19 [LZMAT]"
		pattern = "60E80000000058059F0200008B3003F02BC08BFE66ADC1E00C8BC850AD2BC803F18BC85751498A443906"
	strings:
		$1 = { 60 E8 00 00 00 00 58 05 9F 02 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 }
	condition:
		$1 at pe.entry_point
}

rule muckis_protector_i {
	meta:
		tool = "P"
		name = "mucki's protector"
		version = "I"
		pattern = "BE????????B9????????8A06F6D0880646E2F7E9"
	strings:
		$1 = { BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 E9 }
	condition:
		$1 at pe.entry_point
}

rule muckis_protector_ii_01 {
	meta:
		tool = "P"
		name = "Muckis protector"
		version = "II"
		pattern = "E8240000008B4C240CC70117000100C781B80000000000000031C0894114894118806A00"
	strings:
		$1 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 6A 00 }
	condition:
		$1 at pe.entry_point
}

rule muckis_protector_ii_02 {
	meta:
		tool = "P"
		name = "mucki's protector"
		version = "II"
		pattern = "E8240000008B4C240CC70117000100C781B80000000000000031C0894114894118806A00E885C07412648B3D180000008B7F300FB6470285C07401C3C70424????????BE????????B9????????8A06F6D0880646E2F7C3"
	strings:
		$1 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 6A 00 E8 85 C0 74 12 64 8B 3D 18 00 00 00 8B 7F 30 0F B6 47 02 85 C0 74 01 C3 C7 04 24 ?? ?? ?? ?? BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 C3 }
	condition:
		$1 at pe.entry_point
}

rule mz0ope_106b {
	meta:
		tool = "P"
		name = "MZ0oPE"
		version = "1.0.6b"
		pattern = "EBCA890383C30487FE32C0AE75FD87FE803EFF75E2465B83C304538B1B803FFF75C98BE56168????????C3"
	strings:
		$1 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 ?? ?? ?? ?? C3 }
	condition:
		$1 at pe.entry_point
}

rule mz_crypt_10 {
	meta:
		tool = "P"
		name = "MZ-Crypt"
		version = "1.0"
		pattern = "60E8000000005D81ED251440008BBD771440008B8D7F144000EB28837F1C07751E8B770C03B57B14400033C0EB0C508AA58314400030265840463B471076EF83C728490BC975D48B85731440008944241C61FFE0"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 25 14 40 00 8B BD 77 14 40 00 8B 8D 7F 14 40 00 EB 28 83 7F 1C 07 75 1E 8B 77 0C 03 B5 7B 14 40 00 33 C0 EB 0C 50 8A A5 83 14 40 00 30 26 58 40 46 3B 47 10 76 EF 83 C7 28 49 0B C9 75 D4 8B 85 73 14 40 00 89 44 24 1C 61 FF E0 }
	condition:
		$1 at pe.entry_point
}

rule njoiner_01 {
	meta:
		tool = "P"
		name = "N-Joiner"
		version = "0.1"
		extra = "asm version"
		pattern = "6A00680014400068001040006A00E8140000006A00E813000000CCFF25AC124000FF25B0124000FF25B4124000FF25B8124000FF25BC124000FF25C0124000FF25C4124000FF25C8124000FF25CC124000FF25D0124000FF25D4124000FF25D8124000FF25DC124000FF25E4124000FF25EC124000"
	strings:
		$1 = { 6A 00 68 00 14 40 00 68 00 10 40 00 6A 00 E8 14 00 00 00 6A 00 E8 13 00 00 00 CC FF 25 AC 12 40 00 FF 25 B0 12 40 00 FF 25 B4 12 40 00 FF 25 B8 12 40 00 FF 25 BC 12 40 00 FF 25 C0 12 40 00 FF 25 C4 12 40 00 FF 25 C8 12 40 00 FF 25 CC 12 40 00 FF 25 D0 12 40 00 FF 25 D4 12 40 00 FF 25 D8 12 40 00 FF 25 DC 12 40 00 FF 25 E4 12 40 00 FF 25 EC 12 40 00 }
	condition:
		$1 at pe.entry_point
}

rule njoy_10 {
	meta:
		tool = "P"
		name = "N-Joy"
		version = "1.0"
		pattern = "558BEC83C4F0B89C3B4000E88CFCFFFF6A0068E43940006A0A6A00E840FDFFFFE8EFF5FFFF8D4000"
	strings:
		$1 = { 55 8B EC 83 C4 F0 B8 9C 3B 40 00 E8 8C FC FF FF 6A 00 68 E4 39 40 00 6A 0A 6A 00 E8 40 FD FF FF E8 EF F5 FF FF 8D 40 00 }
	condition:
		$1 at pe.entry_point
}

rule njoy_11 {
	meta:
		tool = "P"
		name = "N-Joy"
		version = "1.1"
		pattern = "558BEC83C4F0B80C3C4000E824FCFFFF6A0068283A40006A0A6A00E8D8FCFFFFE87FF5FFFF8D4000"
	strings:
		$1 = { 55 8B EC 83 C4 F0 B8 0C 3C 40 00 E8 24 FC FF FF 6A 00 68 28 3A 40 00 6A 0A 6A 00 E8 D8 FC FF FF E8 7F F5 FF FF 8D 40 00 }
	condition:
		$1 at pe.entry_point
}

rule njoy_12 {
	meta:
		tool = "P"
		name = "N-Joy"
		version = "1.2"
		pattern = "558BEC83C4F0B8A4324000E8E8F1FFFF6A0068542A40006A0A6A00E8A8F2FFFFE8C7EAFFFF8D4000"
	strings:
		$1 = { 55 8B EC 83 C4 F0 B8 A4 32 40 00 E8 E8 F1 FF FF 6A 00 68 54 2A 40 00 6A 0A 6A 00 E8 A8 F2 FF FF E8 C7 EA FF FF 8D 40 00 }
	condition:
		$1 at pe.entry_point
}

rule njoy_13 {
	meta:
		tool = "P"
		name = "N-Joy"
		version = "1.3"
		pattern = "558BEC83C4F0B848364000E854EEFFFF6A0068D82B40006A0A6A00E82CEFFFFFE823E7FFFF8D4000"
	strings:
		$1 = { 55 8B EC 83 C4 F0 B8 48 36 40 00 E8 54 EE FF FF 6A 00 68 D8 2B 40 00 6A 0A 6A 00 E8 2C EF FF FF E8 23 E7 FF FF 8D 40 00 }
	condition:
		$1 at pe.entry_point
}

rule maked_packer_10 {
	meta:
		tool = "P"
		name = "Naked Packer"
		version = "1.0"
		pattern = "60FC0FB605????????85C07531B8????????2B05????????A3????????A1????????0305????????A3????????E89A000000A3????????C605????????01833D????????00750761FF25????????61FF7424046A00FF15????????50FF15????????C3FF7424046A00FF15????????50FF15????????C3"
	strings:
		$1 = { 60 FC 0F B6 05 ?? ?? ?? ?? 85 C0 75 31 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9A 00 00 00 A3 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 83 3D ?? ?? ?? ?? 00 75 07 61 FF 25 ?? ?? ?? ?? 61 FF 74 24 04 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? C3 FF 74 24 04 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? C3 }
	condition:
		$1 at pe.entry_point
}

rule maked_packer_1x {
	meta:
		tool = "P"
		name = "Naked Packer"
		version = "1.x"
		pattern = "6A??E89A0500008BD85368????????E86CFDFFFFB9050000008BF3BF????????53F3A5E88D0500008B3D????????A1????????668B15????????B9????????2BCF8945E8890D????????668955EC8B413C33D203C183C410668B4806668B501481E1FFFF00008D5C02188D41FFE800000000EB01??8945F0C645FF008D7DE88BF38A0E8A178AC13ACA751E84C074168A56018A4F018AC23AD1750E83C60283C70284C075DC33C0EB05"
	strings:
		$1 = { 6A ?? E8 9A 05 00 00 8B D8 53 68 ?? ?? ?? ?? E8 6C FD FF FF B9 05 00 00 00 8B F3 BF ?? ?? ?? ?? 53 F3 A5 E8 8D 05 00 00 8B 3D ?? ?? ?? ?? A1 ?? ?? ?? ?? 66 8B 15 ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B CF 89 45 E8 89 0D ?? ?? ?? ?? 66 89 55 EC 8B 41 3C 33 D2 03 C1 83 C4 10 66 8B 48 06 66 8B 50 14 81 E1 FF FF 00 00 8D 5C 02 18 8D 41 FF E8 00 00 00 00 EB 01 ?? 89 45 F0 C6 45 FF 00 8D 7D E8 8B F3 8A 0E 8A 17 8A C1 3A CA 75 1E 84 C0 74 16 8A 56 01 8A 4F 01 8A C2 3A D1 75 0E 83 C6 02 83 C7 02 84 C0 75 DC 33 C0 EB 05 }
	condition:
		$1 at pe.entry_point
}

rule nakedbind_10 {
	meta:
		tool = "P"
		name = "Nakedbind"
		version = "1.0"
		pattern = "648B38488BC8F2AFAF8B1F6633DB66813B4D5A740881EB0000"
	strings:
		$1 = { 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B 4D 5A 74 08 81 EB 00 00 }
	condition:
		$1 at pe.entry_point
}

rule native_ud_packer_11 {
	meta:
		tool = "P"
		name = "Native UD Packer"
		version = "1.1"
		pattern = "31C031DB31C9EB0E6A006A006A006A00FF1528414000FF159440400089C76888130000FF1598404000FF159440400081C78813000039F87305E9840000006A406800100000FF35043040006A00FF15A440400089C7FF350430400068CA10400050FF15A84040006A406800100000FF35083040006A00FF15A440400089C66800304000FF350430400057FF3508304000506A02FF154E4140006A006A006A00566A006A00FF159C404000506A006A006A1150FF154A414000586AFF50FF15AC4040006A00FF15A040"
	strings:
		$1 = { 31 C0 31 DB 31 C9 EB 0E 6A 00 6A 00 6A 00 6A 00 FF 15 28 41 40 00 FF 15 94 40 40 00 89 C7 68 88 13 00 00 FF 15 98 40 40 00 FF 15 94 40 40 00 81 C7 88 13 00 00 39 F8 73 05 E9 84 00 00 00 6A 40 68 00 10 00 00 FF 35 04 30 40 00 6A 00 FF 15 A4 40 40 00 89 C7 FF 35 04 30 40 00 68 CA 10 40 00 50 FF 15 A8 40 40 00 6A 40 68 00 10 00 00 FF 35 08 30 40 00 6A 00 FF 15 A4 40 40 00 89 C6 68 00 30 40 00 FF 35 04 30 40 00 57 FF 35 08 30 40 00 50 6A 02 FF 15 4E 41 40 00 6A 00 6A 00 6A 00 56 6A 00 6A 00 FF 15 9C 40 40 00 50 6A 00 6A 00 6A 11 50 FF 15 4A 41 40 00 58 6A FF 50 FF 15 AC 40 40 00 6A 00 FF 15 A0 40 }
	condition:
		$1 at pe.entry_point
}

rule nbinder_361 {
	meta:
		tool = "P"
		name = "nBinder"
		version = "3.6.1"
		pattern = "6E353634353635333233343534335F6E62335C005C6E353634353635333233343534335F6E62335C"
	strings:
		$1 = { 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C 00 5C 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C }
	condition:
		$1 at pe.entry_point
}

rule nbinder_40 {
	meta:
		tool = "P"
		name = "nBinder"
		version = "4.0"
		pattern = "5C6E62345F746D705F303133323435343335305C000000000000000000E955434CFF011A00000000963007772C610EEEBA51099919C46D078FF46A7035A563E9A395649E3288DB0EA4B8DC79"
	strings:
		$1 = { 5C 6E 62 34 5F 74 6D 70 5F 30 31 33 32 34 35 34 33 35 30 5C 00 00 00 00 00 00 00 00 00 E9 55 43 4C FF 01 1A 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 8F F4 6A 70 35 A5 63 E9 A3 95 64 9E 32 88 DB 0E A4 B8 DC 79 }
	condition:
		$1 at pe.entry_point
}

rule nbuild_10_soft {
	meta:
		tool = "P"
		name = "nbuild"
		version = "1.0 soft"
		pattern = "B9????BB????C0????80????43E2"
	strings:
		$1 = { B9 ?? ?? BB ?? ?? C0 ?? ?? 80 ?? ?? 43 E2 }
	condition:
		$1 at pe.entry_point
}

rule ncode_02 {
	meta:
		tool = "P"
		name = "N-Code"
		version = "0.2"
		pattern = "9066BE????6683FE??74??66B8????66BE????6683FE??74??6683E8??66BB????6683C3??66436681FB????74??6683F8"
	strings:
		$1 = { 90 66 BE ?? ?? 66 83 FE ?? 74 ?? 66 B8 ?? ?? 66 BE ?? ?? 66 83 FE ?? 74 ?? 66 83 E8 ?? 66 BB ?? ?? 66 83 C3 ?? 66 43 66 81 FB ?? ?? 74 ?? 66 83 F8 }
	condition:
		$1 at pe.entry_point
}

rule neolite_10_01 {
	meta:
		tool = "P"
		name = "NeoLite"
		version = "1.0"
		pattern = "E99B000000A0"
	strings:
		$1 = { E9 9B 00 00 00 A0 }
	condition:
		$1 at pe.entry_point
}

rule neolite_10_02 {
	meta:
		tool = "P"
		name = "NeoLite"
		version = "1.0"
		pattern = "8B4424048D5424FC2305????????E8????????FF35????????50FF25"
	strings:
		$1 = { 8B 44 24 04 8D 54 24 FC 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25 }
	condition:
		$1 at pe.entry_point
}

rule neolite_20_01 {
	meta:
		tool = "P"
		name = "NeoLite"
		version = "2.0"
		pattern = "8B4424042305????????50E8????????83C404FE05????????0BC074"
	strings:
		$1 = { 8B 44 24 04 23 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74 }
	condition:
		$1 at pe.entry_point
}

rule neolite_20_02 {
	meta:
		tool = "P"
		name = "NeoLite"
		version = "2.0"
		pattern = "E9????????????????????????????????????????????????????????4E656F4C697465"
	strings:
		$1 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4E 65 6F 4C 69 74 65 }
	condition:
		$1 at pe.entry_point
}

rule neolite_uv {
	meta:
		tool = "P"
		name = "NeoLite"
		pattern = "??????????????????????????????????????????9E370000????48??????6F4C????????????????????61"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9E 37 00 00 ?? ?? 48 ?? ?? ?? 6F 4C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 61 }
	condition:
		$1 at pe.entry_point
}

rule nfo_10 {
	meta:
		tool = "P"
		name = "NFO"
		version = "1.0"
		pattern = "8D50122BC9B11E8A023477880242E2F7C88C"
	strings:
		$1 = { 8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8 8C }
	condition:
		$1 at pe.entry_point
}

rule nfo_1x_modified {
	meta:
		tool = "P"
		name = "NFO"
		version = "1.x modified"
		pattern = "609C8D50"
	strings:
		$1 = { 60 9C 8D 50 }
	condition:
		$1 at pe.entry_point
}

rule noc_packer_uv {
	meta:
		tool = "P"
		name = "NOS Packer"
		pattern = "50E8000000005B81EB????????B9????????2BD98BF381EB????????8BFB81EB????????575156E8????????83C4??8BAB????????8D2C2B4D8A4D??80F9??74??83ED??8BD32B53"
	strings:
		$1 = { 50 E8 00 00 00 00 5B 81 EB ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B D9 8B F3 81 EB ?? ?? ?? ?? 8B FB 81 EB ?? ?? ?? ?? 57 51 56 E8 ?? ?? ?? ?? 83 C4 ?? 8B AB ?? ?? ?? ?? 8D 2C 2B 4D 8A 4D ?? 80 F9 ?? 74 ?? 83 ED ?? 8B D3 2B 53 }
	condition:
		$1 at pe.entry_point
}

rule ningishzida_10 {
	meta:
		tool = "P"
		name = "Ningishzida"
		version = "1.0"
		pattern = "9C6096E8000000005D81ED03254000B9041B00008DBD4B2540008BF7AC????????????????????????????????????????????????????????????????????????????????????????????????AAE2CC"
	strings:
		$1 = { 9C 60 96 E8 00 00 00 00 5D 81 ED 03 25 40 00 B9 04 1B 00 00 8D BD 4B 25 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }
	condition:
		$1 at pe.entry_point
}

rule nmacro_recorder_10 {
	meta:
		tool = "P"
		name = "nMacro recorder"
		version = "1.0"
		pattern = "5C6E6D725F74656D702E6E6D720000007262000058C7410010F84100110100000000000046E1000046E1000035000000F6884100"
	strings:
		$1 = { 5C 6E 6D 72 5F 74 65 6D 70 2E 6E 6D 72 00 00 00 72 62 00 00 58 C7 41 00 10 F8 41 00 11 01 00 00 00 00 00 00 46 E1 00 00 46 E1 00 00 35 00 00 00 F6 88 41 00 }
	condition:
		$1 at pe.entry_point
}

rule nme_11_public {
	meta:
		tool = "P"
		name = "NME"
		version = "1.1 public"
		pattern = "558BEC83C4F05356B830351413E89AE6FFFF33C055686C36141364FF30648920B8085C1413BA84361413E87DE2FFFFE8C0EAFFFF8B15CC451413A1C8451413E804F8FFFF8B15D0451413A1C8451413E8F4F7FFFF8B15CC451413A1C8451413E82CF9FFFFA3F85A14138B15D0451413A1C8451413E817F9FFFFA3FC5A1413B8045C1413E820FBFFFF8BD885DB7448B8005B14138B15C4451413E81EE7FFFFA1045C1413E8A8DAFFFF????????5C1413508BCE8BD3B8005B1413????????FF8BC6E8DFFBFFFF8BC6E89CDAFFFFB8005B1413E872E7FFFF33C05A59596489106873361413C3E90FDFFFFFEBF85E5BE87EE0FFFF0000FFFFFFFF0C0000004E4D4520312E312053747562"
	strings:
		$1 = { 55 8B EC 83 C4 F0 53 56 B8 30 35 14 13 E8 9A E6 FF FF 33 C0 55 68 6C 36 14 13 64 FF 30 64 89 20 B8 08 5C 14 13 BA 84 36 14 13 E8 7D E2 FF FF E8 C0 EA FF FF 8B 15 CC 45 14 13 A1 C8 45 14 13 E8 04 F8 FF FF 8B 15 D0 45 14 13 A1 C8 45 14 13 E8 F4 F7 FF FF 8B 15 CC 45 14 13 A1 C8 45 14 13 E8 2C F9 FF FF A3 F8 5A 14 13 8B 15 D0 45 14 13 A1 C8 45 14 13 E8 17 F9 FF FF A3 FC 5A 14 13 B8 04 5C 14 13 E8 20 FB FF FF 8B D8 85 DB 74 48 B8 00 5B 14 13 8B 15 C4 45 14 13 E8 1E E7 FF FF A1 04 5C 14 13 E8 A8 DA FF FF ?? ?? ?? ?? 5C 14 13 50 8B CE 8B D3 B8 00 5B 14 13 ?? ?? ?? ?? FF 8B C6 E8 DF FB FF FF 8B C6 E8 9C DA FF FF B8 00 5B 14 13 E8 72 E7 FF FF 33 C0 5A 59 59 64 89 10 68 73 36 14 13 C3 E9 0F DF FF FF EB F8 5E 5B E8 7E E0 FF FF 00 00 FF FF FF FF 0C 00 00 00 4E 4D 45 20 31 2E 31 20 53 74 75 62 }
	condition:
		$1 at pe.entry_point
}

rule noobyprotect_1004 {
	meta:
		tool = "P"
		name = "NoobyProtect"
		version = "1.0.0.4"
		pattern = "0000000000000000????????????????6B65726E656C33322E646C6C0000000000000000000000000000000000000000????????????????????????????????????004C6F61644C6962726172794100000047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000005669727475616C416C6C6F630045????????????????????????????????0000009C81442404"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 45 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 9C 81 44 24 04 }
	condition:
		$1 at pe.entry_point
}

rule noobyprotect_1090_1098 {
	meta:
		tool = "P"
		name = "NoobyProtect"
		version = "1.0.9.0 - 1.0.9.8"
		pattern = "5351E8000000008B1C2483C32533C9874BFC83F90074068033??43E2FA83C404595B9DE904000000"
	strings:
		$1 = { 53 51 E8 00 00 00 00 8B 1C 24 83 C3 25 33 C9 87 4B FC 83 F9 00 74 06 80 33 ?? 43 E2 FA 83 C4 04 59 5B 9D E9 04 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule noobyprotect_109x_se_public {
	meta:
		tool = "P"
		name = "NoobyProtect"
		version = "1.0.9.x SE public"
		pattern = "6B65726E656C33322E646C6C007573657233322E646C6C00????????0000000000000000????????????????????????0000000000000000????????????????0000000000000000000000000000000000000000????????????????000047657450726F63416464726573730000005669727475616C416C6C6F6300????????????????00000000????????00004D657373616765426F784100????????00000000"
	strings:
		$1 = { 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 72 33 32 2E 64 6C 6C 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 ?? ?? ?? ?? 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule noobyprotect_1100_se_public_01 {
	meta:
		tool = "P"
		name = "NoobyProtect"
		version = "1.1.0.0 SE public"
		pattern = "4E6F6F627950726F7465637420534520312E312E302E30"
	strings:
		$1 = { 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20 53 45 20 31 2E 31 2E 30 2E 30 }
	condition:
		$1 at pe.entry_point
}

rule noobyprotect_1100_se_public_02 {
	meta:
		tool = "P"
		name = "NoobyProtect"
		version = "1.1.0.0 SE public"
		pattern = "9C5351E8000000008B1C2483C32533C9874BFC83F90074068033??43E2FA83C404595B9DE904000000"
	strings:
		$1 = { 9C 53 51 E8 00 00 00 00 8B 1C 24 83 C3 25 33 C9 87 4B FC 83 F9 00 74 06 80 33 ?? 43 E2 FA 83 C4 04 59 5B 9D E9 04 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule noodlecrypt_200 {
	meta:
		tool = "P"
		name = "NoodleCrypt"
		version = "2.00"
		pattern = "EB019AE8??000000EB019AE8????0000EB019AE8????0000EB01"
	strings:
		$1 = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 9A E8 ?? ?? 00 00 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule npack_11150b_11200b {
	meta:
		tool = "P"
		name = "nPack"
		version = "1.1.150b - 1.1.200b"
		pattern = "833D40??????007505E901000000C3E841000000B880??????2B0508??????A33C??????E85E000000E8E0010000E8EC060000E8F7050000"
	strings:
		$1 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 }
	condition:
		$1 at pe.entry_point
}

rule npack_111502006b {
	meta:
		tool = "P"
		name = "nPack"
		version = "1.1.150.2006b"
		pattern = "833D??????????7505E901000000C3E841000000B8????????2B05????????A3????????E85E000000E8E0010000E8EC060000E8F7050000A1????????C705????????????????0105????????FF35????????C3C3565768????????FF15????????8B35????????8BF868????????57FFD668????????57A3????????FFD65FA3????????5EC3"
	strings:
		$1 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3 }
	condition:
		$1 at pe.entry_point
}

rule npack_11150206b_112002006b {
	meta:
		tool = "P"
		name = "nPack"
		version = "1.1.150.2006b, 1.1.200.2006b"
		pattern = "5589E583EC0883C4F46A02A1C8??????FFD0E8????????C9C3"
	strings:
		$1 = { 55 89 E5 83 EC 08 83 C4 F4 6A 02 A1 C8 ?? ?? ?? FF D0 E8 ?? ?? ?? ?? C9 C3 }
	condition:
		$1 at pe.entry_point
}

rule npack_112002006b {
	meta:
		tool = "P"
		name = "nPack"
		version = "1.1.200.2006b"
		pattern = "833D40??????007505E901000000C3E841000000B880??????2B0508??????A33C??????E85E000000E8EC010000E8F8060000E803060000A13C??????C70540??????01000000010500??????FF3500??????C3C3"
	strings:
		$1 = { 83 3D 40 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 ?? ?? ?? 2B 05 08 ?? ?? ?? A3 3C ?? ?? ?? E8 5E 00 00 00 E8 EC 01 00 00 E8 F8 06 00 00 E8 03 06 00 00 A1 3C ?? ?? ?? C7 05 40 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 }
	condition:
		$1 at pe.entry_point
}

rule npack_11250 {
	meta:
		tool = "P"
		name = "nPack"
		version = "1.1.250"
		pattern = "833D04??????007505E901000000C3E846000000E873000000B82E??????2B0508??????A300??????E89C000000E804020000E8FB060000E81B060000A100??????C70504??????01000000010500??????FF3500??????C3C3"
	strings:
		$1 = { 83 3D 04 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 2E ?? ?? ?? 2B 05 08 ?? ?? ?? A3 00 ?? ?? ?? E8 9C 00 00 00 E8 04 02 00 00 E8 FB 06 00 00 E8 1B 06 00 00 A1 00 ?? ?? ?? C7 05 04 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 ?? ?? ?? C3 C3 }
	condition:
		$1 at pe.entry_point
}

rule npack_112752006b {
	meta:
		tool = "P"
		name = "nPack"
		version = "1.1.275.2006b"
		pattern = "558BEC51515657BE????????8D7DF866A5A4BE????????8D7DFC8D45FC66A5508D45F850A4FF15????????833D??????????5F5E7505E802000000C9C3E846000000E873000000B8????????2B05????????A3????????E89C000000E81A020000E8CA060000E819060000A1????????C705????????????????0105????????FF35????????C3C3565768????????FF15????????8B??????????8BF868????????57FFD668????????57A3????????FFD65FA3????????5EC3"
	strings:
		$1 = { 55 8B EC 51 51 56 57 BE ?? ?? ?? ?? 8D 7D F8 66 A5 A4 BE ?? ?? ?? ?? 8D 7D FC 8D 45 FC 66 A5 50 8D 45 F8 50 A4 FF 15 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 5F 5E 75 05 E8 02 00 00 00 C9 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8 1A 02 00 00 E8 CA 06 00 00 E8 19 06 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3 }
	condition:
		$1 at pe.entry_point
}

rule npack_113002006b {
	meta:
		tool = "P"
		name = "nPack"
		version = "1.1.300.2006b"
		pattern = "833D??????????7505E901000000C3E846000000E873000000B8????????2B05????????A3????????E89C000000E82D020000E8DD060000E82C060000A1????????C705????????????????0105????????FF35????????C3C3565768????????FF15????????8B35????????8BF868????????57FFD668????????57A3????????FFD65FA3????????5EC3"
	strings:
		$1 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8 2D 02 00 00 E8 DD 06 00 00 E8 2C 06 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3 }
	condition:
		$1 at pe.entry_point
}

rule npack_115002008b {
	meta:
		tool = "P"
		name = "nPack"
		version = "1.1.500.2008b"
		pattern = "833D??????????7505E901000000C3E846000000E873000000B8????????2B05????????A3????????E89C000000E848020000E8F8060000E847060000A1????????C705????????????????0105????????FF35????????C3C3565768????????FF15????????8B35????????8BF868????????57FFD668????????57A3????????FFD65FA3????????5EC356576A??68????????6A??6A??FF15????????8BF0BF????????5657E823FEFFFF6A??5657E8F4FCFFFF83C41468????????6A??56FF15????????5F5EC3"
	strings:
		$1 = { 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8 48 02 00 00 E8 F8 06 00 00 E8 47 06 00 00 A1 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 C3 56 57 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 8B F8 68 ?? ?? ?? ?? 57 FF D6 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 5F A3 ?? ?? ?? ?? 5E C3 56 57 6A ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F0 BF ?? ?? ?? ?? 56 57 E8 23 FE FF FF 6A ?? 56 57 E8 F4 FC FF FF 83 C4 14 68 ?? ?? ?? ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 5F 5E C3 }
	condition:
		$1 at pe.entry_point
}

rule nspack_11 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "1.1"
		pattern = "9C60E8000000005DB8578440002D50844000"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }
	condition:
		$1
}

rule nspack_13 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "1.3"
		pattern = "9C60E8000000005DB8B38540002DAC8540002BE88DB573??FFFF8B0683F80074118DB57F??FFFF8B0683F8010F84F1010000C706010000008BD58B854F??FFFF2BD089954F??FFFF019567??FFFF8DB583??FFFF01168B368BFD606A40680010000068001000006A00FF95A3??FFFF85C00F8406030000898563??FFFFE8000000005BB93189400081E92E86400003D95053E83D0200006103BD47??FFFF8BDF833F00750A83C7"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 73 ?? FF FF 8B 06 83 F8 00 74 11 8D B5 7F ?? FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 4F ?? FF FF 2B D0 89 95 4F ?? FF FF 01 95 67 ?? FF FF 8D B5 83 ?? FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 A3 ?? FF FF 85 C0 0F 84 06 03 00 00 89 85 63 ?? FF FF E8 00 00 00 00 5B B9 31 89 40 00 81 E9 2E 86 40 00 03 D9 50 53 E8 3D 02 00 00 61 03 BD 47 ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 }
	condition:
		$1
}

rule nspack_14 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "1.4"
		pattern = "9C60E8000000005DB8B18540002DAA854000"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }
	condition:
		$1
}

rule nspack_23_01 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "2.3"
		pattern = "9C607061636B2440"
	strings:
		$1 = { 9C 60 70 61 63 6B 24 40 }
	condition:
		$1
}

rule nspack_23_02 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "2.3"
		pattern = "9C60E8????00005DB8070000002BE88DB5????FFFF"
	strings:
		$1 = { 9C 60 E8 ?? ?? 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF }
	condition:
		$1
}

rule nspack_23_03 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "2.3"
		pattern = "9C60E8000000005DB8070000002BE88DB5????FFFF8B0683F80074118DB5????FFFF8B0683F8010F844B020000C706010000008BD58B85????FFFF2BD08995????FFFF0195????FFFF8DB5????FFFF01168B368BFD606A40680010000068001000006A00FF95????FFFF85C00F84560300008985????FFFFE8000000005BB95403000003D95053E89D02000061"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 56 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 54 03 00 00 03 D9 50 53 E8 9D 02 00 00 61 }
	condition:
		$1
}

rule nspack_29 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "2.9"
		pattern = "9C60E8000000005DB8070000002BE88DB5????FFFF8A063C0074128BF58DB5????FFFF8A063C010F8442020000C606018BD52B95????FFFF8995????FFFF0195????FFFF8DB5????FFFF0116606A40680010000068001000006A00FF95????FFFF85C00F846A0300008985????FFFFE8000000005BB96803000003D95053E8B1020000618B368BFD03BD????FFFF8BDF833F00750A83C704B900000000EB16B901000000033B83C304833B007436"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8A 06 3C 00 74 12 8B F5 8D B5 ?? ?? FF FF 8A 06 3C 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }
	condition:
		$1
}

rule nspack_30 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "3.0"
		pattern = "9C60E8000000005DB8070000002BE88DB5????????668B066683F80074158BF58DB5????FFFF668B066683F8010F8442020000C606018BD52B95????FFFF8995????FFFF0195????FFFF8DB5????FFFF0116606A40680010000068001000006A00FF95????FFFF85C00F846A0300008985????FFFFE8000000005BB96803000003D95053E8B1020000618B368BFD03BD????FFFF8BDF833F00750A83C704B900000000EB16B901000000033B83C304833B007436"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? ?? ?? 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 ?? ?? FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }
	condition:
		$1
}

rule nspack_31 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "3.1"
		pattern = "9C60E8000000005D83ED078D9D????????8A033C0074108D9D????FFFF8A033C010F8442020000C603018BD52B95????FFFF8995????FFFF0195????FFFF8DB5????FFFF0116606A40680010000068001000006A00FF95????FFFF85C00F846A0300008985????FFFFE8000000005BB96803000003D95053E8B1020000618B368BFD03BD????FFFF8BDF833F00750A83C704B900000000EB16B901000000033B83C304833B00743601138B33037B0457515253FFB5????FFFFFFB5????FFFF8BD68BCF8B85????FFFF05AA050000FFD05B5A595F83F900740583C308EBC568008000006A00"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 68 00 80 00 00 6A 00 }
	condition:
		$1
}

rule nspack_33 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "3.3"
		pattern = "9C60E8000000005D83ED078D85????????80380074"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 00 74 }
	condition:
		$1
}

rule nspack_34 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "3.4"
		pattern = "9C60E8000000005D83ED078D85????FFFF8038010F8442020000C600018BD52B95????FFFF8995????FFFF0195????FFFF8DB5????FFFF0116606A40680010000068001000006A00FF95????FFFF85C00F846A0300008985????FFFFE8000000005BB96803000003D95053E8B1020000618B368BFD03BD????FFFF8BDF833F00750A83C704B900000000EB16B901000000033B83C304833B00743601138B33037B0457515253FFB5????FFFFFFB5????FFFF8BD68BCF8B85????FFFF05AA050000FFD05B5A595F83F900740583C308EBC5"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 ?? ?? FF FF 85 C0 0F 84 6A 03 00 00 89 85 ?? ?? FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD ?? ?? FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 ?? ?? FF FF FF B5 ?? ?? FF FF 8B D6 8B CF 8B 85 ?? ?? FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 }
	condition:
		$1
}

rule nspack_36 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "3.6"
		pattern = "9C60E8000000005D83ED078D??????????8338010F8447020000"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 83 38 01 0F 84 47 02 00 00 }
	condition:
		$1
}

rule nspack_37 {
	meta:
		tool = "P"
		name = "NsPacK"
		version = "3.7"
		pattern = "9C60E8000000005D83ED078D??????????8039010F??????0000"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 80 39 01 0F ?? ?? ?? 00 00 }
	condition:
		$1
}

rule ntkrnl_packer {
	meta:
		tool = "P"
		name = "NTKrnl"
		extra = "Packer"
		pattern = "00000000000000000000000034100000281000000000000000000000000000000000000000000000????????????????000000004B65726E656C33322E646C6C0000004C6F61644C69627261727941000000476574"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 }
	condition:
		$1 at pe.entry_point
}

rule ntkrnl_secure_suite {
	meta:
		tool = "P"
		name = "NTkrnl"
		extra = "Secure Suite"
		pattern = "341000002810000000000000000000000000000000000000000000004110000050100000000000004B65726E656C33322E646C6C0000004C6F61644C6962726172794100000047657450726F6341646472657373"
	strings:
		$1 = { 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }
	condition:
		$1 at pe.entry_point
}

rule ntpacker_10 {
	meta:
		tool = "P"
		name = "NTPacker"
		version = "1.0"
		pattern = "558BEC83C4E05333C08945E08945E48945E88945ECB8????4000E8????FFFF33C05568????400064FF306489208D4DECBA????4000A1????4000E8??FCFFFF8B55ECB8????4000E8????FFFF8D4DE8BA????4000A1????4000E8??FEFFFF8B55E8B8????4000E8????FFFFB8????4000E8??FBFFFF8BD8A1????4000BA????4000E8????FFFF75268BD3A1????4000E8????FFFF84C0752A8D55E433C0E8????FFFF8B45E48BD3E8????FFFFEB148D55E033C0E8????FFFF8B45E08BD3E8????FFFF6A00E8????FFFF33C05A595964891068????40008D45E0BA04000000E8????FFFFC3E9????FFFFEBEB5BE8????FFFF000000FFFFFFFF0100000025000000FFFFFFFF010000005C000000FFFFFFFF060000005345525645520000FFFFFFFF0100000031"
	strings:
		$1 = { 55 8B EC 83 C4 E0 53 33 C0 89 45 E0 89 45 E4 89 45 E8 89 45 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 8D 4D EC BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FC FF FF 8B 55 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 8D 4D E8 BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FE FF FF 8B 55 E8 B8 ?? ?? 40 00 E8 ?? ?? FF FF B8 ?? ?? 40 00 E8 ?? FB FF FF 8B D8 A1 ?? ?? 40 00 BA ?? ?? 40 00 E8 ?? ?? FF FF 75 26 8B D3 A1 ?? ?? 40 00 E8 ?? ?? FF FF 84 C0 75 2A 8D 55 E4 33 C0 E8 ?? ?? FF FF 8B 45 E4 8B D3 E8 ?? ?? FF FF EB 14 8D 55 E0 33 C0 E8 ?? ?? FF FF 8B 45 E0 8B D3 E8 ?? ?? FF FF 6A 00 E8 ?? ?? FF FF 33 C0 5A 59 59 64 89 10 68 ?? ?? 40 00 8D 45 E0 BA 04 00 00 00 E8 ?? ?? FF FF C3 E9 ?? ?? FF FF EB EB 5B E8 ?? ?? FF FF 00 00 00 FF FF FF FF 01 00 00 00 25 00 00 00 FF FF FF FF 01 00 00 00 5C 00 00 00 FF FF FF FF 06 00 00 00 53 45 52 56 45 52 00 00 FF FF FF FF 01 00 00 00 31 }
	condition:
		$1 at pe.entry_point
}

rule ntpacker_2x {
	meta:
		tool = "P"
		name = "NTPacker"
		version = "2.x"
		pattern = "4B57696E646F7773001055547970657300003F756E744D61696E46756E6374696F6E73000047756E744279706173730000B761504C696275000000"
	strings:
		$1 = { 4B 57 69 6E 64 6F 77 73 00 10 55 54 79 70 65 73 00 00 3F 75 6E 74 4D 61 69 6E 46 75 6E 63 74 69 6F 6E 73 00 00 47 75 6E 74 42 79 70 61 73 73 00 00 B7 61 50 4C 69 62 75 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule nx_pe_packer_10 {
	meta:
		tool = "P"
		name = "NX PE Packer"
		version = "1.0"
		pattern = "FF60FFCAFF00BADC0DE040005000600070008000"
	strings:
		$1 = { FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_10059f {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.0.0.59f"
		pattern = "E8AB1C"
	strings:
		$1 = { E8 AB 1C }
	condition:
		$1 at pe.entry_point
}

rule obsidium_10061 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.0.0.61"
		pattern = "E8AF1C0000"
	strings:
		$1 = { E8 AF 1C 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1111 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.1.1.1"
		pattern = "EB02????E8E71C0000"
	strings:
		$1 = { EB 02 ?? ?? E8 E7 1C 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1200_01 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.2.0.0"
		pattern = "EB02????E83F1E0000"
	strings:
		$1 = { EB 02 ?? ?? E8 3F 1E 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1200_02 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.2.0.0"
		pattern = "EB02????E8771E0000"
	strings:
		$1 = { EB 02 ?? ?? E8 77 1E 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1250 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.2.5.0"
		pattern = "E80E0000008B54240C8382B80000000D33C0C36467FF3600006467892600005033C08B00C3E9FA000000E8D5FFFFFF5864678F06000083C404E82B130000"
	strings:
		$1 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1258 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.2.5.8"
		pattern = "EB01??E829000000EB02????EB01??8B54240CEB04????????8382B800000024EB04????????33C0EB02????C3EB02????EB03??????6467FF360000EB01??646789260000EB03??????EB01??50EB03??????33C0EB04????????8B00EB03??????C3EB01??E9FA000000EB02????E8D5FFFFFFEB04????????EB03??????EB01??58EB01??EB02????64678F060000EB04????????83C404EB01??E87B210000"
	strings:
		$1 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 7B 21 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_12xx {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.2.x.x"
		pattern = "E80E00000033C08B54240C8382B80000000DC36467FF3600006467892600005033C08B00C3E9FA000000E8D5FFFFFF5864678F06000083C404E82B130000"
	strings:
		$1 = { E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1300 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.0.0"
		pattern = "EB04????????E829000000EB02????EB01??8B54240CEB02????8382B800000022EB02????33C0EB04????????C3EB04????????EB04????????6467FF360000EB04????????646789260000EB04????????EB01??50EB03??????33C0EB02????8B00EB01??C3EB04????????E9FA000000EB01??E8D5FFFFFFEB02????EB03??????58EB04????????EB01??64678F060000EB02????83C404EB02????E847260000"
	strings:
		$1 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 22 EB 02 ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 47 26 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1304 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.0.4"
		pattern = "EB02????E825000000EB04????????EB01??8B54240CEB01??8382B800000023EB01??33C0EB02????C3EB02????EB04????????6467FF360000EB03??????646789260000EB02????EB01??50EB01??33C0EB01??8B00EB01??C3EB02????E9FA000000EB02????E8D5FFFFFFEB03??????EB04????????58EB02????EB04????????64678F060000EB03??????83C404EB01??E83B260000"
	strings:
		$1 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? E8 3B 26 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_13013 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.0.13"
		pattern = "EB01??E826000000EB02????EB02????8B54240CEB01??8382B800000021EB04????????33C0EB02????C3EB01??EB04????????6467FF360000EB02????646789260000EB01??EB03??????50EB01??33C0EB03??????8B00EB02????C3EB02????E9FA000000EB01??E8D5FFFFFFEB03??????EB02????58EB03??????EB04????????64678F060000EB03??????83C404EB03??????E813260000"
	strings:
		$1 = { EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 13 26 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_13017 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.0.17"
		pattern = "EB02????E828000000EB04????????EB01??8B54240CEB01??8382B800000025EB02????33C0EB03??????C3EB03??????EB02????6467FF360000EB01??646789260000EB03??????EB04????????50EB04????????33C0EB02????8B00EB04????????C3EB01??E9FA000000EB03??????E8D5FFFFFFEB04????????EB02????58EB03??????EB01??64678F060000EB04????????83C404EB02????E84F260000"
	strings:
		$1 = { EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 4F 26 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_13021 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.0.21"
		pattern = "EB03??????E82E000000EB04????????EB04????????8B54240CEB04????????8382B800000023EB01??33C0EB04????????C3EB03??????EB02????6467FF360000EB01??646789260000EB02????EB02????50EB01??33C0EB03??????8B00EB03??????C3EB03??????E9FA000000EB04????????E8D5FFFFFFEB01??EB01??58EB04????????EB04????????64678F060000EB03??????83C404EB04????????E82B260000"
	strings:
		$1 = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 26 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_13037 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.0.37"
		pattern = "EB02????E826000000EB03??????EB01??8B54240CEB04????????8382B800000026EB01??33C0EB02????C3EB01??EB04????????6467FF360000EB01??646789260000EB01??EB03??????50EB03??????33C0EB03??????8B00EB04????????C3EB03??????E9FA000000EB03??????E8D5FFFFFFEB04????????EB01??58EB02????EB03??????64678F060000EB01??83C404EB03??????E823270000"
	strings:
		$1 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_130x {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.0.x"
		pattern = "EB03??????E82E000000EB04????????EB04????????8B??????EB04????????83????????????EB01??33C0EB04????????C3"
	strings:
		$1 = { EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B ?? ?? ?? EB 04 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? C3 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1311 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.1.1"
		pattern = "EB02????E827000000EB02????EB03??????8B54240CEB01??8382B800000022EB04????????33C0EB01??C3EB02????EB02????6467FF360000EB04????????646789260000EB01??EB03??????50EB03??????33C0EB01??8B00EB03??????C3EB01??E9FA000000EB03??????E8D5FFFFFFEB01??EB03??????58EB03??????EB01??64678F060000EB01??83C404EB03"
	strings:
		$1 = { EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1322 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.2.2"
		pattern = "EB04????????E82A000000EB03??????EB04????????8B54240CEB02????8382B800000026EB04????????33C0EB02????C3EB01??EB03??????6467FF360000EB02????646789260000EB02????EB01??50EB04????????33C0EB04????????8B00EB02????C3EB03??????E9FA000000EB04????????E8D5FFFFFFEB02????EB04????????58EB01??EB01??64678F060000EB01??83C404EB04"
	strings:
		$1 = { EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 04 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1331 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.3.1"
		pattern = "EB01??E829000000EB02????EB03??????8B54240CEB02????8382B800000024EB04????????33C0EB02????C3EB02????EB02????6467FF360000EB04????????646789260000EB01??EB02????50EB01??33C0EB04????????8B00EB03??????C3EB03??????E9FA000000EB02????E8D5FFFFFFEB01??EB04????????58EB02????EB04????????64678F060000EB01??83C404EB02????E85F270000"
	strings:
		$1 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 04 ?? ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 02 ?? ?? E8 5F 27 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1332 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.3.2"
		pattern = "EB01??E82B000000EB02????EB02????8B54240CEB03??????8382B800000024EB04????????33C0EB04????????C3EB02????EB01??6467FF360000EB03??????646789260000EB01??EB02????50EB02????33C0EB02????8B00EB02????C3EB04????????E9FA000000EB03??????E8D5FFFFFFEB03??????EB01??58EB01??EB02????64678F060000EB02????83C404EB02????E83B270000"
	strings:
		$1 = { EB 01 ?? E8 2B 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 3B 27 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1333 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.3.3"
		pattern = "EB02????E829000000EB03??????EB03??????8B??240CEB01??83??B800000028EB03??????33C0EB01??C3EB04????????EB02????6467FF360000EB04????????646789260000EB02????EB04????????50EB04????????33C0EB01??8B00EB03??????C3EB03??????E9FA000000EB03??????E8D5FFFFFFEB04????????EB04????????58EB01??EB03??????64678F060000EB04????????83C404EB04????????E82B270000"
	strings:
		$1 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B ?? 24 0C EB 01 ?? 83 ?? B8 00 00 00 28 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 01 ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 2B 27 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1334 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.3.4"
		pattern = "EB02????E829000000EB03??????EB02????8B54240CEB03??????8382B800000025EB02????33C0EB02????C3EB03??????EB01??6467FF360000EB02????646789260000EB02????EB04????????50EB02????33C0EB01??8B00EB04????????C3EB03??????E9FA000000EB02????E8D5FFFFFFEB02????EB03??????58EB02????EB03??????64678F060000EB03"
	strings:
		$1 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1336 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.3.6"
		pattern = "EB04????????E828000000EB01??????????????8B54240CEB01??8382B800000026EB04????????33C0EB01??C3EB03??????EB04????????6467FF360000EB04????????646789260000EB03??????EB04????????50EB01??33C0EB02????8B00EB04????????C3EB04????????E9FA000000EB03??????E8D5FFFFFFEB01??EB03??????58EB02????EB04????????64678F060000EB04"
	strings:
		$1 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 02 ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1337_01 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.3.7"
		pattern = "EB02????E82C000000EB04????????EB04????????8B54240CEB02????8382B800000027EB04????????33C0EB02????C3EB02????EB03??????6467FF360000EB04????????646789260000EB03??????EB01??50EB02????33C0EB02????8B00EB04????????C3EB02????E9FA000000EB04????????E8D5FFFFFFEB02????EB04????????58EB04????????EB03??????64678F060000EB01??83C404EB03??????E823270000"
	strings:
		$1 = { EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 27 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1337_02 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.3.7"
		pattern = "EB02????E827000000EB03??????EB01??8B54240CEB03??????8382B800000023EB03??????33C0EB02????C3EB01??EB03??????6467FF360000EB04????????646789260000EB01??EB01??50EB02????33C0EB01??8B00EB04????????C3EB02????E9FA000000EB04????????E8D5FFFFFFEB01??EB01??58EB04????????EB01??64678F060000EB02????83C404EB01??E8F7260000"
	strings:
		$1 = { EB 02 ?? ?? E8 27 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 02 ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 F7 26 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1338 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.3.8"
		pattern = "EB04????????E828000000EB01??EB01??8B54240CEB04????????8382B8000000??EB04????????33C0EB03??????C3EB01??EB01??6467FF360000EB03??????646789260000EB02????EB01??50EB04????????33C0EB02????8B00EB03??????C3EB03??????E9FA000000EB03??????E8D5FFFFFFEB02????EB04????????58EB04????????EB02????64678F060000EB04????????83C404EB04????????E857270000"
	strings:
		$1 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 ?? EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 01 ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 57 27 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1339 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.3.9"
		pattern = "EB02????E829000000EB03??????EB01??8B54240CEB04????????8382B800000028EB02????33C0EB02????C3EB03??????EB04????????6467FF360000EB03??????646789260000EB01??EB01??50EB03??????33C0EB03??????8B00EB04????????C3EB04????????E9FA000000EB03??????E8D5FFFFFFEB02????EB04????????58EB03??????EB04????????64678F060000EB03??????83C404EB04????????E8CF270000"
	strings:
		$1 = { EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 28 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 CF 27 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1341 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.4.1"
		pattern = "EB01??E82A000000EB04????????EB02????8B54240CEB03??????8382B800000021EB02????33C0EB03??????C3EB02????EB01??6467FF360000EB01??646789260000EB02????EB03??????50EB04????????33C0EB02????8B00EB04????????C3EB02????E9FA000000EB02????E8D5FFFFFFEB01??EB01??58EB03??????EB04????????64678F060000EB04????????83C404EB02????E8C3270000"
	strings:
		$1 = { EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 C3 27 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1342 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.4.2"
		pattern = "EB02????E826000000EB03??????EB01??8B54240CEB02????8382B800000024EB03??????33C0EB01??C3EB02????EB02????6467FF360000EB03??????646789260000EB03??????EB03??????50EB04????????33C0EB03??????8B00EB03??????C3EB03??????E9FA000000EB03??????E8D5FFFFFFEB01??EB03??????58EB04????????EB04????????64678F060000EB04????????83C404EB01??E8C3270000"
	strings:
		$1 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 C3 27 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1350 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.5.0"
		pattern = "EB03??????E8????????EB02????EB04????????8B54240CEB04????????8382B800000020EB03??????33C0EB01??C3EB02????EB03??????6467FF360000EB03??????646789260000EB01??EB04????????50EB04????????33C0EB04????????8B00EB03??????C3EB02????E9FA000000EB01??E8????????EB01??EB02????58EB04????????EB02????64678F060000EB02????83C404EB01??E8"
	strings:
		$1 = { EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 20 EB 03 ?? ?? ?? 33 C0 EB 01 ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 ?? ?? ?? ?? EB 01 ?? EB 02 ?? ?? 58 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 01 ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1352 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.5.2"
		pattern = "EB04????????E828000000EB01??EB01??8B54240CEB01??8382B800000025EB03??????33C0EB04????????C3EB04????????EB01??6467FF360000EB04????????646789260000EB02????EB03??????50EB04????????33C0EB02????8B00EB01??C3EB03??????E9FA000000EB04????????E8D5FFFFFFEB02????EB04????????58EB04????????EB04????????64678F060000EB03??????83C404EB03??????E8"
	strings:
		$1 = { EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 02 ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1353 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.5.3"
		pattern = "EB02????E82B000000EB04????????EB02????8B54240CEB03??????8382B800000024EB02????33C0EB02????C3EB04????????EB03??????6467FF360000EB04????????646789260000EB04????????EB04????????50EB04????????33C0EB01??8B00EB04????????C3EB03??????E9FA000000EB04????????E8D5FFFFFFEB01??EB01??58EB03??????EB04????????64678F060000EB03??????83C404EB02????E8"
	strings:
		$1 = { EB 02 ?? ?? E8 2B 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 24 EB 02 ?? ?? 33 C0 EB 02 ?? ?? C3 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1354 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.5.4"
		pattern = "EB03??????E82D000000EB04????????EB01??8B54240CEB04????????8382B800000025EB03??????33C0EB04????????C3EB03??????EB01??6467FF360000EB03??????646789260000EB03??????EB02????50EB01??33C0EB02????8B00EB04????????C3EB01??E9FA000000EB04????????E8D5FFFFFFEB03??????EB02????58EB04????????EB03??????64678F060000EB03??????83C404EB04????????E85B280000"
	strings:
		$1 = { EB 03 ?? ?? ?? E8 2D 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 25 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 50 EB 01 ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 04 ?? ?? ?? ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 5B 28 00 00 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1355 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.5.5"
		pattern = "EB01??E82B000000EB03??????EB04????????8B54240CEB02????8382B800000023EB03??????33C0EB02????C3EB03??????EB02????6467FF360000EB01??646789260000EB02????EB02????50EB03??????33C0EB04????????8B00EB03??????C3EB03??????E9????????EB01??E8????????EB04????????EB01??58EB03??????EB02????64678F060000EB01??83C404EB01??E8"
	strings:
		$1 = { EB 01 ?? E8 2B 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 23 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 02 ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? E9 ?? ?? ?? ?? EB 01 ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 01 ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1357 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.5.7"
		pattern = "EB01??E8??000000EB03??????EB01??8B54240CEB02????8382B800000024EB03??????33C0EB02????C3EB02????EB01??6467FF360000EB04????????646789260000EB01??EB02????50EB03??????33C0EB01??8B00EB03??????C3EB01??E9????????EB03??????E8????????EB03??????EB03??????58EB01??EB02????64678F060000EB01??83C404EB01??E8"
	strings:
		$1 = { EB 01 ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 24 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 01 ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 02 ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 01 ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 ?? ?? ?? ?? EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 03 ?? ?? ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 01 ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1360 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.6.0"
		pattern = "EB02????50EB01??E8??000000EB03??????EB02????8B54240CEB04????????8382B80000001FEB04????????33C0EB01??C3EB03??????EB02????33C0EB01??64FF30EB04????????648920EB03??????EB02????8B00EB01??C3EB02????E9??000000EB01??E8??FFFFFFEB01??EB03??????EB02????EB02????648F00EB01??83C404EB03??????58EB04????????E8"
	strings:
		$1 = { EB 02 ?? ?? 50 EB 01 ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 1F EB 04 ?? ?? ?? ?? 33 C0 EB 01 ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0 EB 01 ?? 64 FF 30 EB 04 ?? ?? ?? ?? 64 89 20 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 02 ?? ?? E9 ?? 00 00 00 EB 01 ?? E8 ?? FF FF FF EB 01 ?? EB 03 ?? ?? ?? EB 02 ?? ?? EB 02 ?? ?? 64 8F 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1361 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.6.1"
		pattern = "EB04????????50EB02????E8??000000EB03??????EB02????8B54240CEB03??????8382B8000000??EB02????33C0EB03??????C3EB03??????EB01??33C0EB04????????64FF30EB04????????648920EB01??EB03??????8B00EB02????C3EB03??????E9FA000000EB01??E8??FFFFFFEB01??EB03??????EB01??EB03??????648F00EB03??????83C404EB01??58EB02????E8"
	strings:
		$1 = { EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? E8 ?? 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 ?? EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 01 ?? 33 C0 EB 04 ?? ?? ?? ?? 64 FF 30 EB 04 ?? ?? ?? ?? 64 89 20 EB 01 ?? EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 ?? FF FF FF EB 01 ?? EB 03 ?? ?? ?? EB 01 ?? EB 03 ?? ?? ?? 64 8F 00 EB 03 ?? ?? ?? 83 C4 04 EB 01 ?? 58 EB 02 ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1363 {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.6.3"
		pattern = "EB03??????50EB04????????E8??000000EB04????????EB03??????8B54240CEB03??????8382B800000026EB03??????33C0EB03??????C3EB03??????EB02????33C0EB02????64FF30EB01??648920EB01??EB02????8B00EB03??????C3EB04????????E9??000000EB03??????E8"
	strings:
		$1 = { EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? E8 ?? 00 00 00 EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 26 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0 EB 02 ?? ?? 64 FF 30 EB 01 ?? 64 89 20 EB 01 ?? EB 02 ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 04 ?? ?? ?? ?? E9 ?? 00 00 00 EB 03 ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_1400b {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.4.0.0b"
		pattern = "EB01??E82F000000EB03??????EB04????????8B54240CEB03??????8382B800000021EB04????????33C0EB04????????C3EB03??????EB03??????6467FF360000EB03??????646789260000EB02????EB03??????50EB04????????33C0EB02????8B00EB01??C3EB01??E9????????EB01??E8D5FFFFFFEB03??????EB04????????58EB04????????EB04????????64678F060000EB04????????83C404EB04????????E8"
	strings:
		$1 = { EB 01 ?? E8 2F 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C EB 03 ?? ?? ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 03 ?? ?? ?? 64 67 89 26 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 01 ?? E9 ?? ?? ?? ?? EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 04 ?? ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule obsidium_uv {
	meta:
		tool = "P"
		name = "Obsidium"
		pattern = "E84719"
	strings:
		$1 = { E8 47 19 }
	condition:
		$1 at pe.entry_point
}

rule open_source_code_crypter {
	meta:
		tool = "P"
		name = "Open Source Code Crypter"
		pattern = "558BECB9090000006A006A004975F9535657B834444000E828F8FFFF33C055689F47400064FF30648920BAB0474000B81C674000E807FDFFFF8BD885DB75076A00E8C2F8FFFFBA286740008BC38B0D1C674000E8F0E0FFFFBE01000000B82C684000E8E1F0FFFFBF0A0000008D55EC8BC6E892FCFFFF8B4DECB82C684000BABC474000E854F2FFFFA12C684000E852F3FFFF8BD0B820674000E8A2FCFFFF8BD885DB0F8452020000B8246740008B1520674000E878F4FFFFB824674000E87AF3FFFF8BD08BC38B0D20674000E877E0FFFF8D55E8A124674000E842FDFFFF8B55E8B824674000"
	strings:
		$1 = { 55 8B EC B9 09 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 34 44 40 00 E8 28 F8 FF FF 33 C0 55 68 9F 47 40 00 64 FF 30 64 89 20 BA B0 47 40 00 B8 1C 67 40 00 E8 07 FD FF FF 8B D8 85 DB 75 07 6A 00 E8 C2 F8 FF FF BA 28 67 40 00 8B C3 8B 0D 1C 67 40 00 E8 F0 E0 FF FF BE 01 00 00 00 B8 2C 68 40 00 E8 E1 F0 FF FF BF 0A 00 00 00 8D 55 EC 8B C6 E8 92 FC FF FF 8B 4D EC B8 2C 68 40 00 BA BC 47 40 00 E8 54 F2 FF FF A1 2C 68 40 00 E8 52 F3 FF FF 8B D0 B8 20 67 40 00 E8 A2 FC FF FF 8B D8 85 DB 0F 84 52 02 00 00 B8 24 67 40 00 8B 15 20 67 40 00 E8 78 F4 FF FF B8 24 67 40 00 E8 7A F3 FF FF 8B D0 8B C3 8B 0D 20 67 40 00 E8 77 E0 FF FF 8D 55 E8 A1 24 67 40 00 E8 42 FD FF FF 8B 55 E8 B8 24 67 40 00 }
	condition:
		$1 at pe.entry_point
}

rule orien_uv {
	meta:
		tool = "P"
		name = "ORiEN"
		pattern = "E9??????00CED1CE??0D0A2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D0D0A2D204F5269454E2065786563757461626C652066696C65732070726F"
	strings:
		$1 = { E9 ?? ?? ?? 00 CE D1 CE ?? 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F }
	condition:
		$1 at pe.entry_point
}

rule orien_1xx_2xx {
	meta:
		tool = "P"
		name = "ORiEN"
		version = "1.xx - 2.xx"
		pattern = "4F5269454E2065786563757461626C652066696C65732070726F74656374696F6E2073797374656D"
	strings:
		$1 = { 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F 74 65 63 74 69 6F 6E 20 73 79 73 74 65 6D }
	condition:
		$1 at pe.entry_point
}

rule orien_211_212 {
	meta:
		tool = "P"
		name = "ORiEN"
		version = "2.11 - 2.12"
		pattern = "E95D010000CED1CE??0D"
	strings:
		$1 = { E9 5D 01 00 00 CE D1 CE ?? 0D }
	condition:
		$1 at pe.entry_point
}

rule pack_master_10_01 {
	meta:
		tool = "P"
		name = "Pack Master"
		version = "1.0"
		pattern = "60E801??????E883C404E801??????E95D81EDD32240??E80402????E8EB08EB02CD20FF24249A66BE4746"
	strings:
		$1 = { 60 E8 01 ?? ?? ?? E8 83 C4 04 E8 01 ?? ?? ?? E9 5D 81 ED D3 22 40 ?? E8 04 02 ?? ?? E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
	condition:
		$1 at pe.entry_point
}

rule pack_master_10_02 {
	meta:
		tool = "P"
		name = "Pack Master"
		version = "1.0"
		pattern = "60E801000000E883C404E801000000E95D81EDD3224000E804020000E8EB08EB02CD20FF24249A66BE4746"
	strings:
		$1 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED D3 22 40 00 E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
	condition:
		$1 at pe.entry_point
}

rule packanoid_uv {
	meta:
		tool = "P"
		name = "Packanoid"
		pattern = "BF????????BE????????E89D000000B8"
	strings:
		$1 = { BF ?? ?? ?? ?? BE ?? ?? ?? ?? E8 9D 00 00 00 B8 }
	condition:
		$1 at pe.entry_point
}

rule packitbitch_10_01 {
	meta:
		tool = "P"
		name = "PackItBitch"
		version = "1.0"
		pattern = "000000000000000000000000????????????????00000000000000000000000000000000000000004B45524E454C33322E444C4C00????????????????0000000000004C6F61644C6962726172794100000047657450726F63416464726573730000??000000000000????????????????0000000000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule packitbitch_10_02 {
	meta:
		tool = "P"
		name = "PackItBitch"
		version = "1.0"
		pattern = "00000000000000000000000028??????35??????00000000000000000000000000000000000000004B45524E454C33322E444C4C0041??????50??????0000000000004C6F61644C6962726172794100000047657450726F63416464726573730000??????????????79??????7D??????0000000000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 28 ?? ?? ?? 35 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 41 ?? ?? ?? 50 ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? ?? ?? 79 ?? ?? ?? 7D ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pacman_0001_01 {
	meta:
		tool = "P"
		name = "Packman"
		version = "0.0.0.1"
		pattern = "60E800000000588D??????????8D??????????8D"
	strings:
		$1 = { 60 E8 00 00 00 00 58 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D }
	condition:
		$1 at pe.entry_point
}

rule pacman_0001_02 {
	meta:
		tool = "P"
		name = "Packman"
		version = "0.0.0.1"
		pattern = "0F85??FFFFFF8DB3????????EB3D8B460C03C350FF5500568B360BF675028BF703F303FBEB1BD1C1D1E973050FB7C9EB0503CB8D4902505150FF5504AB5883C6048B0E85C975DF5E83C6148B7E1085FF75BC8D8B0000????B800????000BC0743403C3EB2A8D700803400433ED33D2668B2E660FA4EA0480FA03750D81E5FF0F000003EF03EB014D0046463BF075DC8B3885FF75D061E9??FEFFFF02D275058A164612D2C3"
	strings:
		$1 = { 0F 85 ?? FF FF FF 8D B3 ?? ?? ?? ?? EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36 0B F6 75 02 8B F7 03 F3 03 FB EB 1B D1 C1 D1 E9 73 05 0F B7 C9 EB 05 03 CB 8D 49 02 50 51 50 FF 55 04 AB 58 83 C6 04 8B 0E 85 C9 75 DF 5E 83 C6 14 8B 7E 10 85 FF 75 BC 8D 8B 00 00 ?? ?? B8 00 ?? ?? 00 0B C0 74 34 03 C3 EB 2A 8D 70 08 03 40 04 33 ED 33 D2 66 8B 2E 66 0F A4 EA 04 80 FA 03 75 0D 81 E5 FF 0F 00 00 03 EF 03 EB 01 4D 00 46 46 3B F0 75 DC 8B 38 85 FF 75 D0 61 E9 ?? FE FF FF 02 D2 75 05 8A 16 46 12 D2 C3 }
	condition:
		$1 at pe.entry_point
}

rule pacman_1000 {
	meta:
		tool = "P"
		name = "Packman"
		version = "1.0.0.0"
		pattern = "60E8000000005B8D5BC6011B8B138D73146A08590116AD4975FA"
	strings:
		$1 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA }
	condition:
		$1 at pe.entry_point
}

rule passlock_2000_10 {
	meta:
		tool = "P"
		name = "PassLock 2000"
		version = "1.0"
		pattern = "558BEC535657BB00504000662EF7053420400004000F8598000000E81F010000C74360010000008D83E401000050FF15F061400083EC44C7042444000000C744242C0000000054FF15E8614000B80A000000F744242C0100000074050FB744243083C444894356FF15D0614000E89E00000089434CFF15D46140008943486A00FF15E461400089435CE8F9000000E8AA000000B8FF000000720D53E8960000005BFF4B10FF4B18"
	strings:
		$1 = { 55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 00 00 C7 43 60 01 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 83 EC 44 C7 04 24 44 00 00 00 C7 44 24 2C 00 00 00 00 54 FF 15 E8 61 40 00 B8 0A 00 00 00 F7 44 24 2C 01 00 00 00 74 05 0F B7 44 24 30 83 C4 44 89 43 56 FF 15 D0 61 40 00 E8 9E 00 00 00 89 43 4C FF 15 D4 61 40 00 89 43 48 6A 00 FF 15 E4 61 40 00 89 43 5C E8 F9 00 00 00 E8 AA 00 00 00 B8 FF 00 00 00 72 0D 53 E8 96 00 00 00 5B FF 4B 10 FF 4B 18 }
	condition:
		$1 at pe.entry_point
}

rule password_protector_uv_01 {
	meta:
		tool = "P"
		name = "Password Protector"
		pattern = "060E0E071FE800005B83EB08BA270103D3E83C02BAEA"
	strings:
		$1 = { 06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA }
	condition:
		$1 at pe.entry_point
}

rule password_protector_uv_02 {
	meta:
		tool = "P"
		name = "Password Protector"
		pattern = "E8????????5D8BFD81??????????81??????????83????89??????????8D??????????8D??????????4680????74"
	strings:
		$1 = { E8 ?? ?? ?? ?? 5D 8B FD 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 46 80 ?? ?? 74 }
	condition:
		$1 at pe.entry_point
}

rule patch_creation_wizzard_12_byte_patch {
	meta:
		tool = "P"
		name = "Patch Creation Wizard"
		version = "1.2 Byte Patch"
		pattern = "E87F0300006A00E824030000A3B83340006A0068291040006A006A0150E82C0300006A00E8EF020000558BEC5651578B450C983D100100000F85C10000006A01FF35B8334000E81B030000506A016880000000FF7508E81D030000685F3040006A65FF7508E81403000068B03040006A67FF7508E80503000068013140006A66FF7508E8F60200006A00FF7508E8C8020000A3B4334000C705BC3340002C000000C705C0334000"
	strings:
		$1 = { E8 7F 03 00 00 6A 00 E8 24 03 00 00 A3 B8 33 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 2C 03 00 00 6A 00 E8 EF 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 B8 33 40 00 E8 1B 03 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 1D 03 00 00 68 5F 30 40 00 6A 65 FF 75 08 E8 14 03 00 00 68 B0 30 40 00 6A 67 FF 75 08 E8 05 03 00 00 68 01 31 40 00 6A 66 FF 75 08 E8 F6 02 00 00 6A 00 FF 75 08 E8 C8 02 00 00 A3 B4 33 40 00 C7 05 BC 33 40 00 2C 00 00 00 C7 05 C0 33 40 00 }
	condition:
		$1 at pe.entry_point
}

rule patch_creation_wizzard_12_mem_patch {
	meta:
		tool = "P"
		name = "Patch Creation Wizard"
		version = "1.2 Memory Patch"
		pattern = "6A00E89B020000A37A3340006A00688E1040006A006A0150E8B5020000685A31400068123140006A006A006A046A016A006A0068A23040006A00E85102000085C07431FF35623140006A006A30E862020000E80B010000FF355A314000E822020000FF355E314000E8530200006A00E8220200006A1068F730400068FE3040006A00E8630200006A00E808020000558BEC5651578B450C983D10010000756B6A01FF357A334000"
	strings:
		$1 = { 6A 00 E8 9B 02 00 00 A3 7A 33 40 00 6A 00 68 8E 10 40 00 6A 00 6A 01 50 E8 B5 02 00 00 68 5A 31 40 00 68 12 31 40 00 6A 00 6A 00 6A 04 6A 01 6A 00 6A 00 68 A2 30 40 00 6A 00 E8 51 02 00 00 85 C0 74 31 FF 35 62 31 40 00 6A 00 6A 30 E8 62 02 00 00 E8 0B 01 00 00 FF 35 5A 31 40 00 E8 22 02 00 00 FF 35 5E 31 40 00 E8 53 02 00 00 6A 00 E8 22 02 00 00 6A 10 68 F7 30 40 00 68 FE 30 40 00 6A 00 E8 63 02 00 00 6A 00 E8 08 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 75 6B 6A 01 FF 35 7A 33 40 00 }
	condition:
		$1 at pe.entry_point
}

rule patch_creation_wizzard_12_seekndestroy {
	meta:
		tool = "P"
		name = "Patch Creation Wizard"
		version = "1.2 Seek and Destroy Patch"
		pattern = "E8C50500006A00E85E050000A3CE3940006A0068291040006A006A0150E8720500006A00E82F050000558BEC5651578B450C983D100100000F85C10000006A01FF35CE394000E861050000506A016880000000FF7508E863050000685F3040006A65FF7508E85A05000068B03040006A67FF7508E84B05000068013140006A66FF7508E83C0500006A00FF7508E80E050000A3CA394000C705D23940002C000000C705D6394000"
	strings:
		$1 = { E8 C5 05 00 00 6A 00 E8 5E 05 00 00 A3 CE 39 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 72 05 00 00 6A 00 E8 2F 05 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 CE 39 40 00 E8 61 05 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 63 05 00 00 68 5F 30 40 00 6A 65 FF 75 08 E8 5A 05 00 00 68 B0 30 40 00 6A 67 FF 75 08 E8 4B 05 00 00 68 01 31 40 00 6A 66 FF 75 08 E8 3C 05 00 00 6A 00 FF 75 08 E8 0E 05 00 00 A3 CA 39 40 00 C7 05 D2 39 40 00 2C 00 00 00 C7 05 D6 39 40 00 }
	condition:
		$1 at pe.entry_point
}

rule pawning_antivirus_cryptor {
	meta:
		tool = "P"
		name = "Pawning AntiVirus Cryptor"
		pattern = "53565755BB2C????70BE00300070BF20????70807B28007516833F0074118B1789D033D289178BE8FFD5833F0075EF833D04300070007406FF1554300070807B2802750A833E00750533C089430CFF151C300070807B28017605833E0074228B431085C0741BFF15143000708B53108B42103B4204740A85C0740650E88FFAFFFFFF1520300070807B28017503FF5324807B28007405E835FFFFFF833B007517833D10????70007406FF1510????708B0650E8A9FAFFFF8B03568BF08BFBB90B000000F3A55EE973FFFFFF5D5F5E5BC3A300300070E826FFFFFFC3908F0504300070E9E9FFFFFFC3"
	strings:
		$1 = { 53 56 57 55 BB 2C ?? ?? 70 BE 00 30 00 70 BF 20 ?? ?? 70 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 00 70 00 74 06 FF 15 54 30 00 70 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 1C 30 00 70 80 7B 28 01 76 05 83 3E 00 74 22 8B 43 10 85 C0 74 1B FF 15 14 30 00 70 8B 53 10 8B 42 10 3B 42 04 74 0A 85 C0 74 06 50 E8 8F FA FF FF FF 15 20 30 00 70 80 7B 28 01 75 03 FF 53 24 80 7B 28 00 74 05 E8 35 FF FF FF 83 3B 00 75 17 83 3D 10 ?? ?? 70 00 74 06 FF 15 10 ?? ?? 70 8B 06 50 E8 A9 FA FF FF 8B 03 56 8B F0 8B FB B9 0B 00 00 00 F3 A5 5E E9 73 FF FF FF 5D 5F 5E 5B C3 A3 00 30 00 70 E8 26 FF FF FF C3 90 8F 05 04 30 00 70 E9 E9 FF FF FF C3 }
	condition:
		$1 at pe.entry_point
}

rule pc_guard_uv {
	meta:
		tool = "P"
		name = "PC Guard"
		pattern = "FC5550E8000000005DEB01E360E803000000D2EB0B58EB014840EB0135FFE0E761B8????????60E80300000083EB0EEB010C58EB013540EB0136FFE00B612BE8"
	strings:
		$1 = { FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 B8 ?? ?? ?? ?? 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 2B E8 }
	condition:
		$1 at pe.entry_point
}

rule pc_guard_303d_305d {
	meta:
		tool = "P"
		name = "PC Guard"
		version = "3.03d, 3.05d"
		pattern = "5550E8????????5DEB01E360E803??????D2EB0B58EB014840EB01"
	strings:
		$1 = { 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule pc_guard_405d_410d_415d {
	meta:
		tool = "P"
		name = "PC Guard"
		version = "4.05d, 4.10d, 4.15d"
		pattern = "FC5550E8000000005DEB01"
	strings:
		$1 = { FC 55 50 E8 00 00 00 00 5D EB 01 }
	condition:
		$1 at pe.entry_point
}

rule pc_guard_500 {
	meta:
		tool = "P"
		name = "PC Guard"
		version = "5.00"
		pattern = "FC5550E8000000005D60E80300000083EB0EEB010C58EB013540EB0136FFE00B61B8????????EB01E360E803000000D2EB0B58EB014840EB0135FFE0E7612BE8"
	strings:
		$1 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 ?? ?? ?? ?? EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 }
	condition:
		$1 at pe.entry_point
}

rule pcpec_alpha {
	meta:
		tool = "P"
		name = "PCPEC"
		version = "alpha"
		pattern = "535152565755E8????????5D8BCD81??????????2B??????????83"
	strings:
		$1 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B CD 81 ?? ?? ?? ?? ?? 2B ?? ?? ?? ?? ?? 83 }
	condition:
		$1 at pe.entry_point
}

rule pcpec_alpha_preview {
	meta:
		tool = "P"
		name = "PCPEC"
		version = "alpha preview"
		pattern = "535152565755E8000000005D8BCD81ED333040"
	strings:
		$1 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 }
	condition:
		$1 at pe.entry_point
}

rule pcshrinker_020 {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.20"
		pattern = "E8E801????6001ADB32740??68"
	strings:
		$1 = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }
	condition:
		$1 at pe.entry_point
}

rule pcshrinker_029 {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.29"
		pattern = "??BD????????01AD553940??8DB5353940"
	strings:
		$1 = { ?? BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40 }
	condition:
		$1 at pe.entry_point
}

rule pcshrinker_040b {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.40b"
		pattern = "9C60BD????????01??????????FF??????????6A??FF??????????50502D"
	strings:
		$1 = { 9C 60 BD ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 6A ?? FF ?? ?? ?? ?? ?? 50 50 2D }
	condition:
		$1 at pe.entry_point
}

rule pcshrinker_045 {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.45"
		pattern = "??BD????????01ADE33840??FFB5DF3840"
	strings:
		$1 = { ?? BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }
	condition:
		$1 at pe.entry_point
}

rule pcshrinker_071b {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.71b"
		pattern = "01AD543A4000FFB5503A40006A40FF95883A4000"
	strings:
		$1 = { 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00 }
	condition:
		$1 at pe.entry_point
}

rule pcshrinker_071 {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.71"
		pattern = "9C60BD????????01AD543A40??FFB5503A40??6A40FF95883A40??50502D????????8985"
	strings:
		$1 = { 9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85 }
	condition:
		$1 at pe.entry_point
}

rule pcshrinker_uv {
	meta:
		tool = "P"
		name = "PCShrinker"
		pattern = "9C60BD????????01??????????FF??????????6A??FF??????????50502D"
	strings:
		$1 = { 9C 60 BD ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 6A ?? FF ?? ?? ?? ?? ?? 50 50 2D }
	condition:
		$1 at pe.entry_point
}

rule pecrypt_uv {
	meta:
		tool = "P"
		name = "PE Crypt"
		pattern = "558BEC83C4E0535633C08945E48945E08945EC????????64824000E87CC7FFFF33C05568BE84400064FF3064892068CC844000????????00A110A7400050E81DC8FFFF8BD885DB7539E83AC8FFFF6A006A0068A0A940006800040000506A006800130000E8FFC7FFFF6A0068E0844000A1A0A94000506A00E8????????E97D01000053A110A7400050E842C8FFFF8BF085F675186A0068E084400068E48440006A00E871C8FFFFE953010000536A00E82CC8FFFFA3????????833D48A840000075186A0068E084400068F88440006A00E843C8FFFFE92501000056E8F8C7FFFFA34CA84000A148A84000E891A1FFFF8BD88B1548A8400085D27C164233C08B0D4CA8400003C88A098D3418880E404A75ED8B1548A8400085D27C324233C08D34188A0E80F9017505C606FFEB1C8D0C188A0984??????????00EB0E8B0D4CA8400003C80FB60949880E404A75D18D????????E8A5A3FFFF8B45E88D55ECE856D5FFFF8D45ECBA18854000E879BAFFFF8B45ECE839BBFFFF8BD0B854A84000E831A6FFFFBA01000000B854A84000E812A9FFFFE8DDA1FFFF6850A840008BD38B0D48A84000B854A84000E856A7FFFFE8C1A1FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 E0 53 56 33 C0 89 45 E4 89 45 E0 89 45 EC ?? ?? ?? ?? 64 82 40 00 E8 7C C7 FF FF 33 C0 55 68 BE 84 40 00 64 FF 30 64 89 20 68 CC 84 40 00 ?? ?? ?? ?? 00 A1 10 A7 40 00 50 E8 1D C8 FF FF 8B D8 85 DB 75 39 E8 3A C8 FF FF 6A 00 6A 00 68 A0 A9 40 00 68 00 04 00 00 50 6A 00 68 00 13 00 00 E8 FF C7 FF FF 6A 00 68 E0 84 40 00 A1 A0 A9 40 00 50 6A 00 E8 ?? ?? ?? ?? E9 7D 01 00 00 53 A1 10 A7 40 00 50 E8 42 C8 FF FF 8B F0 85 F6 75 18 6A 00 68 E0 84 40 00 68 E4 84 40 00 6A 00 E8 71 C8 FF FF E9 53 01 00 00 53 6A 00 E8 2C C8 FF FF A3 ?? ?? ?? ?? 83 3D 48 A8 40 00 00 75 18 6A 00 68 E0 84 40 00 68 F8 84 40 00 6A 00 E8 43 C8 FF FF E9 25 01 00 00 56 E8 F8 C7 FF FF A3 4C A8 40 00 A1 48 A8 40 00 E8 91 A1 FF FF 8B D8 8B 15 48 A8 40 00 85 D2 7C 16 42 33 C0 8B 0D 4C A8 40 00 03 C8 8A 09 8D 34 18 88 0E 40 4A 75 ED 8B 15 48 A8 40 00 85 D2 7C 32 42 33 C0 8D 34 18 8A 0E 80 F9 01 75 05 C6 06 FF EB 1C 8D 0C 18 8A 09 84 ?? ?? ?? ?? ?? 00 EB 0E 8B 0D 4C A8 40 00 03 C8 0F B6 09 49 88 0E 40 4A 75 D1 8D ?? ?? ?? ?? E8 A5 A3 FF FF 8B 45 E8 8D 55 EC E8 56 D5 FF FF 8D 45 EC BA 18 85 40 00 E8 79 BA FF FF 8B 45 EC E8 39 BB FF FF 8B D0 B8 54 A8 40 00 E8 31 A6 FF FF BA 01 00 00 00 B8 54 A8 40 00 E8 12 A9 FF FF E8 DD A1 FF FF 68 50 A8 40 00 8B D3 8B 0D 48 A8 40 00 B8 54 A8 40 00 E8 56 A7 FF FF E8 C1 A1 FF FF }
	condition:
		$1 at pe.entry_point
}

rule pecrypt_100_102_01 {
	meta:
		tool = "P"
		name = "PE Crypt"
		version = "1.00 - 1.02"
		pattern = "E8000000005B83????EB??524E4421"
	strings:
		$1 = { E8 00 00 00 00 5B 83 ?? ?? EB ?? 52 4E 44 21 }
	condition:
		$1 at pe.entry_point
}

rule pecrypt_100_102_02 {
	meta:
		tool = "P"
		name = "PE Crypt"
		version = "1.00 - 1.02"
		pattern = "E8????????5B83EB05EB04524E44"
	strings:
		$1 = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 }
	condition:
		$1 at pe.entry_point
}

rule pecrypt_15 {
	meta:
		tool = "P"
		name = "PE Crypt"
		version = "1.5"
		pattern = "60E8000000005D81ED55204000B97B0900008DBD9D2040008BF7AC????????????????????????????????????????????????????????????????????????????????????????????????AAE2CC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 55 20 40 00 B9 7B 09 00 00 8D BD 9D 20 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }
	condition:
		$1 at pe.entry_point
}

rule pe_diminisher_01_01 {
	meta:
		tool = "P"
		name = "PE Diminisher"
		version = "0.1"
		pattern = "535152565755E800000000"
	strings:
		$1 = { 53 51 52 56 57 55 E8 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pe_diminisher_01_02 {
	meta:
		tool = "P"
		name = "PE Diminisher"
		version = "0.1"
		pattern = "5D8BD581EDA23040??2B95913340??81EA0B??????89959A3340??80BD99"
	strings:
		$1 = { 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99 }
	condition:
		$1 at pe.entry_point
}

rule pe_intro_10 {
	meta:
		tool = "P"
		name = "PE Intro"
		version = "1.0"
		pattern = "8B04249C60E8????????5D81ED0A4540??80BD674440????0F8548"
	strings:
		$1 = { 8B 04 24 9C 60 E8 ?? ?? ?? ?? 5D 81 ED 0A 45 40 ?? 80 BD 67 44 40 ?? ?? 0F 85 48 }
	condition:
		$1 at pe.entry_point
}

rule pe_ninja_uv_01 {
	meta:
		tool = "P"
		name = "PE Ninja"
		pattern = "5D8BC581EDB22C40002B85943E40002D710200008985983E40000FB6B59C3E40008BFD"
	strings:
		$1 = { 5D 8B C5 81 ED B2 2C 40 00 2B 85 94 3E 40 00 2D 71 02 00 00 89 85 98 3E 40 00 0F B6 B5 9C 3E 40 00 8B FD }
	condition:
		$1 at pe.entry_point
}

rule pe_ninja_uv_02 {
	meta:
		tool = "P"
		name = "PE Ninja"
		pattern = "909090909090909090909090909090909090909090909090909090909090909090909090"
	strings:
		$1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pe_ninja_10 {
	meta:
		tool = "P"
		name = "PE Ninja"
		version = "1.0"
		pattern = "BE5B2A4000BF35120000E8401200003D2283A3C60F85670F000090909090909090909090909090909090909090909090"
	strings:
		$1 = { BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pe_packer_uv {
	meta:
		tool = "P"
		name = "PE Packer"
		pattern = "FC8B35700140??83EE406A4068??3010"
	strings:
		$1 = { FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10 }
	condition:
		$1 at pe.entry_point
}

rule pe_password_02 {
	meta:
		tool = "P"
		name = "PE Password"
		version = "0.2 SMT/SMF"
		pattern = "E804??????8BEC5DC333C05D8BFD81ED332640??81EF????????83EF0589AD882740??8D9D072940??8DB5622840??4680"
	strings:
		$1 = { E8 04 ?? ?? ?? 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 ?? 81 EF ?? ?? ?? ?? 83 EF 05 89 AD 88 27 40 ?? 8D 9D 07 29 40 ?? 8D B5 62 28 40 ?? 46 80 }
	condition:
		$1 at pe.entry_point
}

rule pe_protector_260 {
	meta:
		tool = "P"
		name = "PE Protector"
		version = "2.60 hying's PE-Armor V0.460"
		pattern = "555351525657E8E1000000??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????5D81ED0B0000008B9D9B000000039D9F0000000BDB74148B837F4600000383874600005F5E5A595B5DFFE08D754356FF55548DB5A30000005650FF55508985B00000008D754356FF55548DB5B40000005650FF55508985C00000008D754356FF55548DB5C40000005650FF55508985D00000006A406800100000FFB5970000006A00FF95B000000089859B000000558D9DF2010000538D9DCC010000FFD38B7424048B7C240CF74604070000007508813E270000C07506B800000000C3"
	strings:
		$1 = { 55 53 51 52 56 57 E8 E1 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5D 81 ED 0B 00 00 00 8B 9D 9B 00 00 00 03 9D 9F 00 00 00 0B DB 74 14 8B 83 7F 46 00 00 03 83 87 46 00 00 5F 5E 5A 59 5B 5D FF E0 8D 75 43 56 FF 55 54 8D B5 A3 00 00 00 56 50 FF 55 50 89 85 B0 00 00 00 8D 75 43 56 FF 55 54 8D B5 B4 00 00 00 56 50 FF 55 50 89 85 C0 00 00 00 8D 75 43 56 FF 55 54 8D B5 C4 00 00 00 56 50 FF 55 50 89 85 D0 00 00 00 6A 40 68 00 10 00 00 FF B5 97 00 00 00 6A 00 FF 95 B0 00 00 00 89 85 9B 00 00 00 55 8D 9D F2 01 00 00 53 8D 9D CC 01 00 00 FF D3 8B 74 24 04 8B 7C 24 0C F7 46 04 07 00 00 00 75 08 81 3E 27 00 00 C0 75 06 B8 00 00 00 00 C3 }
	condition:
		$1 at pe.entry_point
}

rule pe_armor_0460 {
	meta:
		tool = "P"
		name = "PE-Armor"
		version = "0.460"
		pattern = "E8AA0000002D????0000000000000000003D????002D????0000000000000000000000000000000000000000004B????005C????006F????00000000004B45524E454C33322E646C6C0000000047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C6962726172794100A2010000????00005669727475616C416C6C6F63000000000000????00??????00??????00??????00"
	strings:
		$1 = { E8 AA 00 00 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 3D ?? ?? 00 2D ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 5C ?? ?? 00 6F ?? ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 A2 01 00 00 ?? ?? 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule pe_armor_0490 {
	meta:
		tool = "P"
		name = "PE-Armor"
		version = "0.490"
		pattern = "5652515355E81501000032????0000000000"
	strings:
		$1 = { 56 52 51 53 55 E8 15 01 00 00 32 ?? ?? 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pe_armor_0460_0759 {
	meta:
		tool = "P"
		name = "PE-Armor"
		version = "0.460 - 0.759"
		pattern = "0000000000000000????????????????0000000000000000000000000000000000000000????????????????????????000000004B45524E454C33322E646C6C0000000047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C6962726172794100"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 }
	condition:
		$1 at pe.entry_point
}

rule pe_armor_0750 {
	meta:
		tool = "P"
		name = "PE-Armor"
		version = "0.750"
		pattern = "0000000000000000????000000000000????010000000000000000005669727475616C416C6C6F630000000000000000??????????????????????????????????????00000000000000000074??????0000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 ?? ?? 01 00 00 00 00 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 74 ?? ?? ?? 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pe_armor_076 {
	meta:
		tool = "P"
		name = "PE-Armor"
		version = "0.760"
		pattern = "E90000000060E8140000005D81ED000000006A??E8A3000000"
	strings:
		$1 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A ?? E8 A3 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pe_armor_0760_0765 {
	meta:
		tool = "P"
		name = "PE-Armor"
		version = "0.760 - 0.765"
		pattern = "0000000000000000????????0000000000000000????????????????0000000000000000000000000000000000000000????????????????????????000000004B45524E454C33322E646C6C0000000047657450726F63416464726573730000004C6F61644C696272617279410000004765744D6F64756C6548616E646C65410000000000080000000000000060E800000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 00 08 00 00 00 00 00 00 00 60 E8 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pe_armor_07xx {
	meta:
		tool = "P"
		name = "PE-Armor"
		version = "0.7xx"
		pattern = "60E8000000005D81ED????????8DB5????????555681C5????????55C3"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 55 56 81 C5 ?? ?? ?? ?? 55 C3 }
	condition:
		$1 at pe.entry_point
}

rule pe_crypter_uv {
	meta:
		tool = "P"
		name = "PE-Crypter"
		pattern = "60E8000000005DEB26"
	strings:
		$1 = { 60 E8 00 00 00 00 5D EB 26 }
	condition:
		$1 at pe.entry_point
}

rule re_pack_099 {
	meta:
		tool = "P"
		name = "PE-PACK"
		version = "0.99"
		pattern = "60E8????????5D83ED0680BDE004????010F84F2"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 83 ED 06 80 BD E0 04 ?? ?? 01 0F 84 F2 }
	condition:
		$1 at pe.entry_point
}

rule re_pack_100_01 {
	meta:
		tool = "P"
		name = "PE-PACK"
		version = "1.00"
		pattern = "74??E9"
	strings:
		$1 = { 74 ?? E9 }
	condition:
		$1 at pe.entry_point
}

rule re_pack_100_02 {
	meta:
		tool = "P"
		name = "PE-PACK"
		version = "1.00"
		pattern = "C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C40D0A202D3DFE2050452D5041434B2076312E30202DFE2D2028432920436F70797269676874203139393820627920414E414B694E20FE3D2D200D0AC4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4"
	strings:
		$1 = { C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 20 2D 3D FE 20 50 45 2D 50 41 43 4B 20 76 31 2E 30 20 2D FE 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 31 39 39 38 20 62 79 20 41 4E 41 4B 69 4E 20 FE 3D 2D 20 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }
	condition:
		$1 at pe.entry_point
}

rule pe_protect_09_01 {
	meta:
		tool = "P"
		name = "PE-Protect"
		version = "0.9"
		pattern = "50452D50524F5445435420302E39"
	strings:
		$1 = { 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 }
	condition:
		$1 at pe.entry_point
}

rule pe_protect_09_02 {
	meta:
		tool = "P"
		name = "PE-Protect"
		version = "0.9"
		pattern = "525155576467A1300085C0780DE8????????5883C007C6??C3"
	strings:
		$1 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3 }
	condition:
		$1 at pe.entry_point
}

rule pe_protect_09_03 {
	meta:
		tool = "P"
		name = "PE-Protect"
		version = "0.9"
		pattern = "E9??0000000D0A0D0AC4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C40D0A50452D50524F5445435420302E39202843296F"
	strings:
		$1 = { E9 ?? 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 20 28 43 29 6F }
	condition:
		$1 at pe.entry_point
}
rule pe_protect_09_04 {
	meta:
		tool = "P"
		name = "PE-Protect"
		version = "0.9"
		pattern = "E9CF0000000D0A0D0AC4C4C4C4C4C4C4C4C4C4C4"
	strings:
		$1 = { E9 CF 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }
	condition:
		$1 at pe.entry_point
}

rule pe_shield_01b {
	meta:
		tool = "P"
		name = "PE-SHiELD"
		version = "0.1b MTE"
		pattern = "E8????????????????????????????????????????????????????B91B01????D1"
	strings:
		$1 = { E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B9 1B 01 ?? ?? D1 }
	condition:
		$1 at pe.entry_point
}

rule pe_shield_02_02b_02b2 {
	meta:
		tool = "P"
		name = "PE-SHiELD"
		version = "0.2, 0.2b, 0.2b2"
		pattern = "60E8????????414E414B494E5D83ED06EB02EA04"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }
	condition:
		$1 at pe.entry_point
}

rule pe_shield_025 {
	meta:
		tool = "P"
		name = "PE-SHiELD"
		version = "0.25"
		pattern = "60E82B000000"
	strings:
		$1 = { 60 E8 2B 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pe_shield_0251 {
	meta:
		tool = "P"
		name = "PE-SHiELD"
		version = "0.251"
		pattern = "5D83ED06EB02EA048D"
	strings:
		$1 = { 5D 83 ED 06 EB 02 EA 04 8D }
	condition:
		$1 at pe.entry_point
}

rule pe123_2006412 {
	meta:
		tool = "P"
		name = "Pe123"
		version = "2006.4.12"
		pattern = "8BC0609CE801000000C353E87200000050E81C0300008BD8FFD35BC38BC0E8000000005883C005C38BC0558BEC608B4D108B7D0C8B7508F3A4615DC20C00E8000000005883E805C38BC0E8000000005883C005C38BC0E80000000058C1E80CC1E00C6681384D5A740C2D001000006681384D5A75F4C3E8000000005883E805C38BC0558BEC81C44CFEFFFF536A408D8544FFFFFF50E8BCFFFFFF50E88AFFFFFF68F80000008D85"
	strings:
		$1 = { 8B C0 60 9C E8 01 00 00 00 C3 53 E8 72 00 00 00 50 E8 1C 03 00 00 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 E8 00 00 00 00 58 C1 E8 0C C1 E0 0C 66 81 38 4D 5A 74 0C 2D 00 10 00 00 66 81 38 4D 5A 75 F4 C3 E8 00 00 00 00 58 83 E8 05 C3 8B C0 55 8B EC 81 C4 4C FE FF FF 53 6A 40 8D 85 44 FF FF FF 50 E8 BC FF FF FF 50 E8 8A FF FF FF 68 F8 00 00 00 8D 85 }
	condition:
		$1 at pe.entry_point
}

rule pe123_200644 {
	meta:
		tool = "P"
		name = "Pe123"
		version = "2006.4.4"
		pattern = "8BC0EB013460EB012A9CEB02EAC8E80F000000EB033D2323EB014AEB015BC38D400053EB016CEB017EEB018FE81501000050E867040000EB019A8BD8FFD35BC38BC0E8000000005883C005C38BC0558BEC608B4D108B7D0C8B7508F3A4615DC20C00E8000000005883E805C38BC0E8000000005883C005C38BC0E80000000058C1E80CC1E00C6681384D5A740C2D001000006681384D5A75F4C3E8000000005883E805C38BC055"
	strings:
		$1 = { 8B C0 EB 01 34 60 EB 01 2A 9C EB 02 EA C8 E8 0F 00 00 00 EB 03 3D 23 23 EB 01 4A EB 01 5B C3 8D 40 00 53 EB 01 6C EB 01 7E EB 01 8F E8 15 01 00 00 50 E8 67 04 00 00 EB 01 9A 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 E8 00 00 00 00 58 C1 E8 0C C1 E0 0C 66 81 38 4D 5A 74 0C 2D 00 10 00 00 66 81 38 4D 5A 75 F4 C3 E8 00 00 00 00 58 83 E8 05 C3 8B C0 55 }
	condition:
		$1 at pe.entry_point
}

rule pe123_uv {
	meta:
		tool = "P"
		name = "Pe123"
		pattern = "8BC0??????????????????????????????????????????????????????????????00??????????????????????????????????????????????????????????????????????????????C0"
	strings:
		$1 = { 8B C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C0 }
	condition:
		$1 at pe.entry_point
}

rule pezip_10 {
	meta:
		tool = "P"
		name = "PEZip"
		version = "1.0"
		pattern = "D9D0F8740223DBF5F5505152538D44241050555657D9D022C9C1F7A05566C1C8B05D81E6FFFFFFFFF877075276037201905AC1E06090BD1F01000087E8E207E305175D47E442417F06506683EE005825FFFFFFFF510FB6C96683F6003DCB604792504058FCE2EE59F87C08537404780284C95B660BEDF8F5BA9FFAFFFF52577704780284E45F5A5080EF00585081E0FFFFFFFF583CEFFC7A053DDFDAACD1050000000073057103"
	strings:
		$1 = { D9 D0 F8 74 02 23 DB F5 F5 50 51 52 53 8D 44 24 10 50 55 56 57 D9 D0 22 C9 C1 F7 A0 55 66 C1 C8 B0 5D 81 E6 FF FF FF FF F8 77 07 52 76 03 72 01 90 5A C1 E0 60 90 BD 1F 01 00 00 87 E8 E2 07 E3 05 17 5D 47 E4 42 41 7F 06 50 66 83 EE 00 58 25 FF FF FF FF 51 0F B6 C9 66 83 F6 00 3D CB 60 47 92 50 40 58 FC E2 EE 59 F8 7C 08 53 74 04 78 02 84 C9 5B 66 0B ED F8 F5 BA 9F FA FF FF 52 57 77 04 78 02 84 E4 5F 5A 50 80 EF 00 58 50 81 E0 FF FF FF FF 58 3C EF FC 7A 05 3D DF DA AC D1 05 00 00 00 00 73 05 71 03 }
	condition:
		$1 at pe.entry_point
}

rule pe_admin_10 {
	meta:
		tool = "P"
		name = "PE_Admin"
		version = "1.0 EncryptPE 1.2003.5.18"
		pattern = "609C64FF3500000000E879010000900000000000000000000000????????????????0000000000000000000000000000000000000000????????????????????????????????????????????????????????????????????????000000006B65726E656C33322E646C6C00000047657453797374656D4469726563746F72794100000043726561746546696C654100000043726561746546696C654D617070696E67410000004D6170566965774F6646696C65000000556E6D6170566965774F6646696C65000000436C6F736548616E646C650000004C6F61644C6962726172794100000047657450726F63416464726573730000004578697450726F63657373"
	strings:
		$1 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 90 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
	condition:
		$1 at pe.entry_point
}

rule pebundle_uv {
	meta:
		tool = "P"
		name = "PEBundle"
		pattern = "9C60E8????????33C08BC483C004938BE38B5BFC81EB07??400087DD????????400001"
	strings:
		$1 = { 9C 60 E8 ?? ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 ?? 40 00 87 DD ?? ?? ?? ?? 40 00 01 }
	condition:
		$1 at pe.entry_point
}

rule pebundle_020_20x {
	meta:
		tool = "P"
		name = "PEBundle"
		version = "0.20 - 2.0x"
		pattern = "9C60E802??????33C08BC483C004938BE38B5BFC81EB????40??87DD6A0468??10????68??02????6A??FF95"
	strings:
		$1 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 }
	condition:
		$1 at pe.entry_point
}

rule pebundle_200b5_230 {
	meta:
		tool = "P"
		name = "PEBundle"
		version = "2.00b5 - 2.30"
		pattern = "9C60E802??????33C08BC483C004938BE38B5BFC81EB????40??87DD01AD????????01AD"
	strings:
		$1 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 01 AD ?? ?? ?? ?? 01 AD }
	condition:
		$1 at pe.entry_point
}

rule pebundle_244 {
	meta:
		tool = "P"
		name = "PEBundle"
		version = "2.44"
		pattern = "9C60E802??????33C08BC483C004938BE38B5BFC81EB????40??87DD83BD"
	strings:
		$1 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD }
	condition:
		$1 at pe.entry_point
}

rule pebundle_310 {
	meta:
		tool = "P"
		name = "PEBundle"
		version = "3.10"
		pattern = "9C60E80200000033C08BC483C004938BE38B5BFC81EB0720400087DD????????400001"
	strings:
		$1 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD ?? ?? ?? ?? 40 00 01 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_090 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.90"
		pattern = "EB0668????4000C39C60BD????0000B902000000B0908DBD7A424000F3AA01ADD9434000FFB5"
	strings:
		$1 = { EB 06 68 ?? ?? 40 00 C3 9C 60 BD ?? ?? 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_092 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.92"
		pattern = "EB0668????????C39C60BD????????B902??????B0908DBDA54F40??F3AA01AD045140??FFB5"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD A5 4F 40 ?? F3 AA 01 AD 04 51 40 ?? FF B5 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_094 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.94"
		pattern = "EB0668????????C39C60E8????????5D555881ED????????2B85????????0185????????50B902"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_0971_0976 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.971 - 0.976"
		pattern = "EB0668C39C60E85D555B81ED8B85018566C785"
	strings:
		$1 = { EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_0977 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.977"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EBA08640??87DD8B852A87"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 ?? 87 DD 8B 85 2A 87 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_0978 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.978"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB248840??87DD8B85A988"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 ?? 87 DD 8B 85 A9 88 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_09781 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.978.1"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB498740??87DD8B85CE87"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 49 87 40 ?? 87 DD 8B 85 CE 87 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_09782 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.978.2"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EBD18440??87DD8B855685"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 ?? 87 DD 8B 85 56 85 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_098 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.98"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EBD78440??87DD8B855C85"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D7 84 40 ?? 87 DD 8B 85 5C 85 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_099 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.99"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB2F8540??87DD8B85B485"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 ?? 87 DD 8B 85 B4 85 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_100 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.00"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EBC48440??87DD8B854985"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB C4 84 40 ?? 87 DD 8B 85 49 85 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_110b1 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b1"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB286340??87DD8B85AD63"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 ?? 87 DD 8B 85 AD 63 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_110b2 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b2"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F6040??87DD8B859460"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 94 60 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_110b3 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b3"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F6040??87DD8B85956040??0185036040??66C785??6040??9090BB95"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 95 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_110b4 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b4"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F6040??87DD8B85956040??0185036040??66C785??6040??9090BB44"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 44 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_110b5 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b5"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F6040??87DD8B85956040??0185036040??66C785??6040??9090BB49"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 49 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_110b6 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b6"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F60??0087DD8B859A6040??0185036040??66C785??6040??90900185926040??BBB7"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 ?? 00 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB B7 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_110b7 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b7"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F6040??87DD8B859A6040??0185036040??66C785??6040??90900185926040??BB14"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB 14 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_120_1201 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.20 - 1.20.1"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B859A7040"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 9A 70 40 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_122 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.22"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B85A67040??0185037040??66C785??7040??909001859E7040??BBF308"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB F3 08 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_123b3_1241 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.23b3 - 1.24.1"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B85A67040??0185037040??66C785704090??9001859E7040BB??D208"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 08 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_1242_1243 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.24.2 - 1.24.3"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B85A67040??0185037040??66C785704090??9001859E7040BB??D209"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 09 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_125 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.25"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B85A67040??0185037040??66C785704090??9001859E7040BB??F30D"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? F3 0D }
	condition:
		$1 at pe.entry_point
}

rule pecompact_126b1_126b2 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.26b1 - 1.26b2"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B85A67040??0185037040??66C785704090??9001859E7040BB??050E"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? 05 0E }
	condition:
		$1 at pe.entry_point
}

rule pecompact_133 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.33"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F8040??87DD8B85A68040??0185038040??66C785008040??909001859E8040??BBE80E"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 00 80 40 ?? 90 90 01 85 9E 80 40 ?? BB E8 0E }
	condition:
		$1 at pe.entry_point
}

rule pecompact_134_140b1 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.34 - 1.40b1"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F8040??87DD8B85A68040??0185038040??66C785??0080??40909001859E80??40BBF810"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 00 80 ?? 40 90 90 01 85 9E 80 ?? 40 BB F8 10 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_140_145 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.40 - 1.45"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0FA040??87DD8B85A6A040??018503A040??66C785??A040??909001859EA040??BBC311"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB C3 11 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_140b2_140b4 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.40b2 - 1.40b4"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0FA040??87DD8B85A6A040??018503A040??66C785??A040??909001859EA040??BB8611"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 86 11 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_140b5_140b6 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.40b5 - 1.40b6"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0FA040??87DD8B85A6A040??018503A040??66C785??A040??909001859EA040??BB8A11"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 8A 11 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_146 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.46"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0FA040??87DD8B85A6A040??018503A040??66C785??A040??909001859EA040??BB6012"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 60 12 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_147_150 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.47 - 1.50"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0FA040??87DD8B85A6A040??018503A040??66C785??A040??909001859EA040??BB5B12"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 5B 12 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_155 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.55"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F8040??87DD8B85A28040??0185038040??66C785??8040??909001859E8040??BB2D12"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A2 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB 2D 12 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_156 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.56"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F9040??87DD8B85A29040??0185039040??66C785??9040??909001859E9040??BB2D12"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 90 40 ?? 87 DD 8B 85 A2 90 40 ?? 01 85 03 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 9E 90 40 ?? BB 2D 12 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_160_165 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.60 - 1.65"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB3F8040??87DD8B85D28040??0185338040??66C785??8040??90900185CE8040??BBBB12"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 ?? 87 DD 8B 85 D2 80 40 ?? 01 85 33 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 CE 80 40 ?? BB BB 12 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_166 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.66"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB3F9040??87DD8B85E69040??0185339040??66C785??9040??90900185DA9040??0185DE9040??0185E29040??BB5B11"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 5B 11 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_167 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.67"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB3F904087DD8B85E69040018533904066C785904090900185DA90400185DE90400185E29040BB8B11"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 8B 11 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_168_184 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.68 - 1.84"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB3F904087DD8B85E69040018533904066C785904090900185DA90400185DE90400185E29040BB7B11"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 7B 11 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_1xx {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.xx"
		pattern = "EB0668????????C39C60E8????????33C08BC483C004938BE38B5BFC81EB????4000"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 00 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_200a38 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.00a38"
		pattern = "B8????????80B8BF10001001747AC680BF100010019C5553515752568D980F1000108B53148BE86A406800100000FF73046A008B4B1003CA8B01FFD08BF8508B338B531403F28B4B0C03CA8D85B7100010FF73048F00505756FFD1580343088BF88B53148BF08B46FC83C0042BF08956088B4B10894E18FFD78985BB1000105E5A5F595B5D9DFFE08B80BB100010FFE00000000000000000000000000000000000000000000000"
	strings:
		$1 = { B8 ?? ?? ?? ?? 80 B8 BF 10 00 10 01 74 7A C6 80 BF 10 00 10 01 9C 55 53 51 57 52 56 8D 98 0F 10 00 10 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 8B F8 50 8B 33 8B 53 14 03 F2 8B 4B 0C 03 CA 8D 85 B7 10 00 10 FF 73 04 8F 00 50 57 56 FF D1 58 03 43 08 8B F8 8B 53 14 8B F0 8B 46 FC 83 C0 04 2B F0 89 56 08 8B 4B 10 89 4E 18 FF D7 89 85 BB 10 00 10 5E 5A 5F 59 5B 5D 9D FF E0 8B 80 BB 10 00 10 FF E0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_200b {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.00b"
		pattern = "B8????????05????????5064FF350000000064892500000000CC90909090"
	strings:
		$1 = { B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_25_retail_slim {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.5 retail slim"
		pattern = "B8??????015064FF35000000006489250000000033C089085045433200"
	strings:
		$1 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_25_retail {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.5 retail"
		pattern = "B8??????015064FF35000000006489250000000033C089085045436F6D706163743200"
	strings:
		$1 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_253_slim {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.53 slim"
		pattern = "B8????????5064FF35000000006489250000000033C08908504543320000080C0048E101565753558B5C241C85DB0F84AB21E8BD0EE6600D0B6B65726E6C3332"
	strings:
		$1 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D 0B 6B 65 72 6E 6C 33 32 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_253 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.53"
		pattern = "B8????????5064FF35000000006489250000000033C089085045436F6D706163743200000000080C0048E101565753558B5C241C85DB0F84AB21E8BD0EE6600D"
	strings:
		$1 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 00 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D }
	condition:
		$1 at pe.entry_point
}

rule pecompact_253_276 {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.53 - 2.76"
		pattern = "B8????????5553515756528D98C91100108B5318528BE86A406800100000FF73046A008B4B1003CA8B01FFD05A8BF850528B338B432003C28B08894B208B431C03C28B08894B1C03F28B4B0C03CA8D431C505756FF"
	strings:
		$1 = { B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 C9 11 00 10 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 5A 8B F8 50 52 8B 33 8B 43 20 03 C2 8B 08 89 4B 20 8B 43 1C 03 C2 8B 08 89 4B 1C 03 F2 8B 4B 0C 03 CA 8D 43 1C 50 57 56 FF }
	condition:
		$1 at pe.entry_point
}

rule pecompact_2xxb {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.xxb"
		pattern = "B8??????0080002840"
	strings:
		$1 = { B8 ?? ?? ?? 00 80 00 28 40 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_2xx_slim {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.xx slim"
		pattern = "B8????????5064FF35000000006489250000000033C089085045433200"
	strings:
		$1 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }
	condition:
		$1 at pe.entry_point
}

rule pecompact_2xx {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.xx"
		pattern = "B8????????5064FF35000000006489250000000033C089085045436F6D706163743200"
	strings:
		$1 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }
	condition:
		$1 at pe.entry_point
}

rule pecrc32_088 {
	meta:
		tool = "P"
		name = "PECrc32"
		version = "0.88"
		pattern = "60E8000000005D81EDB6A445008DBDB0A4450081EF82000000"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED B6 A4 45 00 8D BD B0 A4 45 00 81 EF 82 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule peid_bundle_100_101 {
	meta:
		tool = "P"
		name = "PEiD-Bundle"
		version = "1.00 - 1.01"
		pattern = "60E8??0200008B44240452486631C06681384D5A75F58B503C813C025045000075E95AC204006089DD89C38B453C8B54287801EA528B522001EA31C9418B348A"
	strings:
		$1 = { 60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
	condition:
		$1 at pe.entry_point
}

rule peid_bundle_100 {
	meta:
		tool = "P"
		name = "PEiD-Bundle"
		version = "1.00"
		pattern = "60E8210200008B44240452486631C06681384D5A75F58B503C813C025045000075E95AC204006089DD89C38B453C8B54287801EA528B522001EA31C9418B348A"
	strings:
		$1 = { 60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
	condition:
		$1 at pe.entry_point
}

rule peid_bundle_101 {
	meta:
		tool = "P"
		name = "PEiD-Bundle"
		version = "1.01"
		pattern = "60E8230200008B44240452486631C06681384D5A75F58B503C813C025045000075E95AC204006089DD89C38B453C8B54287801EA528B522001EA31C9418B348A"
	strings:
		$1 = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
	condition:
		$1 at pe.entry_point
}

rule peid_bundle_102_103_01 {
	meta:
		tool = "P"
		name = "PEiD-Bundle"
		version = "1.02 - 1.03"
		pattern = "837C2408010F85????????60E89C0000000000000000000000000000004100080039000800000000000000000000000000000000000000000001000080000000"
	strings:
		$1 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule peid_bundle_102_103_02 {
	meta:
		tool = "P"
		name = "PEiD-Bundle"
		version = "1.02 - 1.03"
		pattern = "60E89C00000000000000000000000000000036??????2E??????000000000000000000000000000000000000000001000080000000004B65726E656C33322E44"
	strings:
		$1 = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
	condition:
		$1 at pe.entry_point
}

rule peid_bundle_102_104 {
	meta:
		tool = "P"
		name = "PEiD-Bundle"
		version = "1.02 - 1.04"
		pattern = "60E8??00000000000000000000000000000036??????2E??????000000000000000000000000000000000000000001000080000000004B65726E656C33322E44"
	strings:
		$1 = { 60 E8 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
	condition:
		$1 at pe.entry_point
}

rule pelock_106 {
	meta:
		tool = "P"
		name = "PELock"
		version = "1.06"
		pattern = "0000000000000000????????????????000000004C6F61644C6962726172794100005669727475616C416C6C6F63004B45"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45 }
	condition:
		$1 at pe.entry_point
}

rule pelock_nt_201 {
	meta:
		tool = "P"
		name = "PELock"
		version = "NT 2.01"
		pattern = "EB03CD20EBEB01EB1EEB01EBEB02CD209CEB03CD"
	strings:
		$1 = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }
	condition:
		$1 at pe.entry_point
}

rule pelock_nt_202c {
	meta:
		tool = "P"
		name = "PELock"
		version = "NT 2.02c"
		pattern = "EB02C7851EEB03CD20EBEB01EB9CEB01EBEB02CD"
	strings:
		$1 = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }
	condition:
		$1 at pe.entry_point
}

rule pelock_nt_203 {
	meta:
		tool = "P"
		name = "PELock"
		version = "NT 2.03"
		pattern = "EB02C7851EEB03CD20C79CEB0269B160EB02EB01"
	strings:
		$1 = { EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule pelock_nt_204 {
	meta:
		tool = "P"
		name = "PELock"
		version = "NT 2.04"
		pattern = "EB??CD??????????CD??????????EB??EB??EB??EB??CD??????????E8????????E9????????50C3"
	strings:
		$1 = { EB ?? CD ?? ?? ?? ?? ?? CD ?? ?? ?? ?? ?? EB ?? EB ?? EB ?? EB ?? CD ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 50 C3 }
	condition:
		$1 at pe.entry_point
}

rule pemangle_uv {
	meta:
		tool = "P"
		name = "PEMangle"
		pattern = "609CBE????????8BFEB9????????BB44524F4CAD33C3"
	strings:
		$1 = { 60 9C BE ?? ?? ?? ?? 8B FE B9 ?? ?? ?? ?? BB 44 52 4F 4C AD 33 C3 }
	condition:
		$1 at pe.entry_point
}

rule pencrypt_uv_01 {
	meta:
		tool = "P"
		name = "PEncrypt"
		pattern = "558BEC81EC780500005356BE04010000578D8594FDFFFF5633DB5053FF15????40008D8594FDFFFF56508D8594FDFFFF50FF15????40008B3D??20400053536A03536A018D8594FDFFFF680000008050"
	strings:
		$1 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 ?? ?? 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 ?? ?? 40 00 8B 3D ?? 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 }
	condition:
		$1 at pe.entry_point
}

rule pencrypt_uv_02 {
	meta:
		tool = "P"
		name = "PEncrypt"
		pattern = "558BEC81EC7C050000535657BE04010000568D8590FDFFFF33DB5053895DF4FF1538204000568D8590FDFFFF5050FF15342040008B3D3020400053536A03536A0168000000808D8590FDFFFF50FFD783"
	strings:
		$1 = { 55 8B EC 81 EC 7C 05 00 00 53 56 57 BE 04 01 00 00 56 8D 85 90 FD FF FF 33 DB 50 53 89 5D F4 FF 15 38 20 40 00 56 8D 85 90 FD FF FF 50 50 FF 15 34 20 40 00 8B 3D 30 20 40 00 53 53 6A 03 53 6A 01 68 00 00 00 80 8D 85 90 FD FF FF 50 FF D7 83 }
	condition:
		$1 at pe.entry_point
}

rule pencrypt_10_01 {
	meta:
		tool = "P"
		name = "PEncrypt"
		version = "1.0"
		pattern = "558BEC83C4D05356578D75FC8B442430250000FFFF81384D5A900074072D00100000EBF18945FCE8C8FFFFFF2D0F0500008945F48B068B403C03068B407803068BC88B512003168B5924031E895DF08B591C031E895DEC8B41188BC84985C9725A4133C08BD8C1E30203DA8B3B033E813F4765745075408BDF83C304813B726F634175338BDF83C308813B64647265752683C70C66813F7373"
	strings:
		$1 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D 0F 05 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 5D EC 8B 41 18 8B C8 49 85 C9 72 5A 41 33 C0 8B D8 C1 E3 02 03 DA 8B 3B 03 3E 81 3F 47 65 74 50 75 40 8B DF 83 C3 04 81 3B 72 6F 63 41 75 33 8B DF 83 C3 08 81 3B 64 64 72 65 75 26 83 C7 0C 66 81 3F 73 73 }
	condition:
		$1 at pe.entry_point
}

rule pencrypt_10_02 {
	meta:
		tool = "P"
		name = "PEncrypt"
		version = "1.0"
		pattern = "609CBE001040008BFEB9????????BB78563412AD33C3ABE2FA9D61E9??????FF"
	strings:
		$1 = { 60 9C BE 00 10 40 00 8B FE B9 ?? ?? ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 E9 ?? ?? ?? FF }
	condition:
		$1 at pe.entry_point
}

rule pencrypt_20 {
	meta:
		tool = "P"
		name = "PEncrypt"
		version = "2.0"
		pattern = "EB250000F7BF000000000000000000001200E8005669727475616C50726F746563740000000000E8000000005D81ED2C1040008DB514104000E833000000898510104000BF000040008BF7037F3C8B4F5451568D85"
	strings:
		$1 = { EB 25 00 00 F7 BF 00 00 00 00 00 00 00 00 00 00 12 00 E8 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 00 00 E8 00 00 00 00 5D 81 ED 2C 10 40 00 8D B5 14 10 40 00 E8 33 00 00 00 89 85 10 10 40 00 BF 00 00 40 00 8B F7 03 7F 3C 8B 4F 54 51 56 8D 85 }
	condition:
		$1 at pe.entry_point
}

rule pencrypt_30 {
	meta:
		tool = "P"
		name = "PEncrypt"
		version = "3.0"
		pattern = "E8000000005D81ED051040008DB5241040008BFEB90F000000BB????????AD33C3E2FA"
	strings:
		$1 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 8D B5 24 10 40 00 8B FE B9 0F 00 00 00 BB ?? ?? ?? ?? AD 33 C3 E2 FA }
	condition:
		$1 at pe.entry_point
}

rule pencrypt_31 {
	meta:
		tool = "P"
		name = "PEncrypt"
		version = "3.1"
		pattern = "E9??????00F00FC6"
	strings:
		$1 = { E9 ?? ?? ?? 00 F0 0F C6 }
	condition:
		$1 at pe.entry_point
}

rule pencrypt_40b {
	meta:
		tool = "P"
		name = "PEncrypt"
		version = "4.0b"
		pattern = "66????006683??00"
	strings:
		$1 = { 66 ?? ?? 00 66 83 ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule penguincrypt_10 {
	meta:
		tool = "P"
		name = "PEnguinCrypt"
		version = "1.0"
		pattern = "B893????0055506764FF360000676489260000BD4B484342B804000000CC3C0475049090C39067648F060000585DBB0000400033C933C0"
	strings:
		$1 = { B8 93 ?? ?? 00 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 00 00 58 5D BB 00 00 40 00 33 C9 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule penightmare_13 {
	meta:
		tool = "P"
		name = "PENightMare"
		version = "1.3"
		pattern = "60E8000000005DB9????????8031154181F9"
	strings:
		$1 = { 60 E8 00 00 00 00 5D B9 ?? ?? ?? ?? 80 31 15 41 81 F9 }
	condition:
		$1 at pe.entry_point
}

rule penightmare_2b {
	meta:
		tool = "P"
		name = "PENightMare"
		version = "2b"
		pattern = "60E9????????EF4003A7078F071C375D43A704B92C3A"
	strings:
		$1 = { 60 E9 ?? ?? ?? ?? EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }
	condition:
		$1 at pe.entry_point
}

rule pequake_006 {
	meta:
		tool = "P"
		name = "PEQuake"
		version = "0.06"
		pattern = "E8A5000000"
	strings:
		$1 = { E8 A5 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule peshit_uv {
	meta:
		tool = "P"
		name = "PEShit"
		pattern = "B8????????B9????????83F9007E068030??40E2F5E9??????FF"
	strings:
		$1 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 83 F9 00 7E 06 80 30 ?? 40 E2 F5 E9 ?? ?? ?? FF }
	condition:
		$1 at pe.entry_point
}

rule pespin_01 {
	meta:
		tool = "P"
		name = "PESpin"
		version = "0.1"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C245CCB46000BE4749E7501????????????????????19770043B7F6C36BB70000F9FFE3C9C20800??????????5D33C941E217EB07??????????????E801000000??5A83EA0BFFE28B??????????8B423C03C289??????????41C1E1078B0C0103CA8B591003DA8B1B89??????????538F85????????BB????????B9A50800008D??????????4F301C39FECBE2F9682D010000598D??????????C00C3902E2FAE802000000FF15????????4F5600BB54130B00D1E32BC3FFE0E801000000"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 ?? ?? ?? ?? ?? 53 8F 85 ?? ?? ?? ?? BB ?? ?? ?? ?? B9 A5 08 00 00 8D ?? ?? ?? ?? ?? 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 ?? ?? ?? ?? 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pespin_03 {
	meta:
		tool = "P"
		name = "PESpin"
		version = "0.3"
		pattern = "EB016860E8000000008B1C2483C312812BE8B10600FE4BFD822C24B7CD46000BE4749E7501C7817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800A3687201FF5D33C941E217EB07EAEB01EBEB0DFFE801000000EA5A83EA0BFFE28B95CB2C40008B423C03C28985D52C400041C1E1078B0C0103CA8B591003DA8B1B899DE92C4000538F85B62B4000BB??000000B9750A00008DBD7E2D40004F301C39FECBE2F9683C010000598DBDB6364000C00C3902E2FAE802000000FF155A8D851F535600BB54130B00D1E32BC3FFE0E80100000068E81A0000008D3428B908000000B8????????2BC983C9150FA3C80F83810000008DB40DDC2C4000"
	strings:
		$1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 ?? ?? ?? ?? 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 }
	condition:
		$1 at pe.entry_point
}

rule pespin_041 {
	meta:
		tool = "P"
		name = "PESpin"
		version = "0.41"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C2402D246000BE4749E7501????????????????????19770043B7F6C36BB70000F9FFE3C9C20800??????????5D33C941E217EB07??????????????E801000000??5A83EA0BFFE28B??????????8B423C03C289??????????41C1E1078B0C0103CA8B591003DA8B1B89??????????538F??????????BB????????B9????????8D??????????4FEB01AB301C39FECBE2F9EB01??683C010000598D??????????C00C3902E2FAE802000000FF15????????595600BB54130B00D1E32BC3FFE0E801000000??E81A000000"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 02 D2 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 ?? ?? ?? ?? ?? 53 8F ?? ?? ?? ?? ?? BB ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 4F EB 01 AB 30 1C 39 FE CB E2 F9 EB 01 ?? 68 3C 01 00 00 59 8D ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 ?? ?? ?? ?? 59 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 ?? E8 1A 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule pespin_07 {
	meta:
		tool = "P"
		name = "PESpin"
		version = "0.7"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C2483D546000BE4749E7501????????????????????19770043B7F6C36BB70000F9FFE3C9C20800??????????5D33C941E217EB07??????????????E801000000??5A83EA0BFFE2EB04??EB0400EBFBFF8B??????????8B423C03C289??????????EB01??41C1E1078B0C0103CAE803000000EB04??EBFB??8304240CC3"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB FF 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? EB 01 ?? 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? EB FB ?? 83 04 24 0C C3 }
	condition:
		$1 at pe.entry_point
}

rule pespin_09b {
	meta:
		tool = "P"
		name = "PESpin"
		version = "0.9b"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C2472C846000BE4749E7501????????????????????19770043B7F6C36BB70000F9FFE3C9C20800??????????5D33C941E226E801000000??5A33C9????????????8B423C03C289??????????41C1E1078B0C0103CA8B591003DA8B1B????????????8B592403DA8B1B????????????53????????????????????????6A0C5B6A1759300C0302CB4B75F8408D9D418F4E005053812C2401780E00????????????C392EB1568??????????B9??080000????????????4F301C39FECBE2F9681D01000059????????????C00C3902E2FA68????????50016C2404E8BD09000033C00F84C0080000????????????50????????????????????????FFE0C38D642404E8530A0000D7585B51C3F7F332DA????????????????????????812C24A300000058????????????53FFE0"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 26 E8 01 00 00 00 ?? 5A 33 C9 ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B ?? ?? ?? ?? ?? ?? 8B 59 24 03 DA 8B 1B ?? ?? ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6A 0C 5B 6A 17 59 30 0C 03 02 CB 4B 75 F8 40 8D 9D 41 8F 4E 00 50 53 81 2C 24 01 78 0E 00 ?? ?? ?? ?? ?? ?? C3 92 EB 15 68 ?? ?? ?? ?? ?? B9 ?? 08 00 00 ?? ?? ?? ?? ?? ?? 4F 30 1C 39 FE CB E2 F9 68 1D 01 00 00 59 ?? ?? ?? ?? ?? ?? C0 0C 39 02 E2 FA 68 ?? ?? ?? ?? 50 01 6C 24 04 E8 BD 09 00 00 33 C0 0F 84 C0 08 00 00 ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF E0 C3 8D 64 24 04 E8 53 0A 00 00 D7 58 5B 51 C3 F7 F3 32 DA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 2C 24 A3 00 00 00 58 ?? ?? ?? ?? ?? ?? 53 FF E0 }
	condition:
		$1 at pe.entry_point
}

rule pespin_10 {
	meta:
		tool = "P"
		name = "PESpin"
		version = "1.0"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C24C8DC46000BE4749E7501????????????????????19770043B7F6C3??????????????C9C20800??????????5D33C941E217EB07??????????????E801000000??5A83EA0BFFE2EB04??EB04??EBFBFF8B??????????8B423C03C289??????????EB02????F97208730EF983042417C3E8040000000FF57311EB06????????????????????????????????????????FF3424C341C1E1078B0C0103CAE803000000EB04????????8304240CC3"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 C8 DC 46 00 0B E4 74 9E 75 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 19 77 00 43 B7 F6 C3 ?? ?? ?? ?? ?? ?? ?? C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB FF 8B ?? ?? ?? ?? ?? 8B 42 3C 03 C2 89 ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? ?? ?? ?? 83 04 24 0C C3 }
	condition:
		$1 at pe.entry_point
}

rule pespin_1100 {
	meta:
		tool = "P"
		name = "PESpin"
		version = "1.100"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C247DDE46000BE4749E7501??817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800??????????5D33C941E217EB07??????????????E801000000??5A83EA0BFFE2EB04??EB0400EBFB????????????????????????????????????EB02????F97208730EF983042417C3E8040000000FF57311EB06????????????F5720EF572F868EBEC83042407F5FF3424C341C1E1078B0C0103CAE803000000EB04??EBFB"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 ?? 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 ?? ?? ?? ?? ?? ?? F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? EB FB }
	condition:
		$1 at pe.entry_point
}

rule pespin_1300 {
	meta:
		tool = "P"
		name = "PESPin"
		version = "1.300"
		pattern = "EB016860E8000000008B1C2483C312812BE8B10600FE4BFD822C24ACDF46000BE4749E7501C7817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800A3687201FF5D33C941E217EB07EAEB01EBEB0DFFE801000000EA5A83EA0BFFE2EB049AEB0400EBFBFF8B950D4F40008B423C03C28985174F4000EB021277F97208730EF983042417C3E8040000000FF57311EB069A72ED1FEB07F5720EF572F868EBEC830424"
	strings:
		$1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 0D 4F 40 00 8B 42 3C 03 C2 89 85 17 4F 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 }
	condition:
		$1 at pe.entry_point
}

rule pespin_1300b {
	meta:
		tool = "P"
		name = "PESpin"
		version = "1.300b"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C2471DF46000BE4749E7501C7817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800A3687201FF5D33C941E217EB07??????????????E801000000??5A83EA0BFFE2EB04??EB04??EBFB??????????????8B423C03C2????????????EB02????F97208730EF983042417C3E8040000000FF57311EB069A72ED1FEB07F5720EF572F868EBEC83042407F5FF3424C3"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB ?? ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 }
	condition:
		$1 at pe.entry_point
}

rule pespin_1304 {
	meta:
		tool = "P"
		name = "PESpin"
		version = "1.304"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C2488DF46000BE4749E7501C7817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800A3687201FF5D33C941E217EB07??EB01??EB0D??E801000000??5A83EA0BFFE2EB04??EB04??EBFB??????????????8B423C03C2????????????EB02????F97208730EF983042417C3E804000000????????EB06????????????F5720EF572F868EBEC83042407F5FF3424C3"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? EB 01 ?? EB 0D ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB ?? ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 ?? ?? ?? ?? EB 06 ?? ?? ?? ?? ?? ?? F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 }
	condition:
		$1 at pe.entry_point
}

rule pespin_1320 {
	meta:
		tool = "P"
		name = "PESpin"
		version = "1.320"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C2417E646000BE4749E7501C7817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800A3687201FF5D33C941E217EB07??EB01??EB0DFFE801000000??5A83EA0BFFE2EB04??EB0400EBFBFFE802000000????5A81??????????83EAFE8995A95740002BC02BC983F1060985CB5740009CD32C2480C1FB210C245052B836C709FF05FE37F600F76424088D8428B1354000894424085A588D642404FF6424FCCD20BB6974580BC1C3"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 17 E6 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? EB 01 ?? EB 0D FF E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB FF E8 02 00 00 00 ?? ?? 5A 81 ?? ?? ?? ?? ?? 83 EA FE 89 95 A9 57 40 00 2B C0 2B C9 83 F1 06 09 85 CB 57 40 00 9C D3 2C 24 80 C1 FB 21 0C 24 50 52 B8 36 C7 09 FF 05 FE 37 F6 00 F7 64 24 08 8D 84 28 B1 35 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC CD 20 BB 69 74 58 0B C1 C3 }
	condition:
		$1 at pe.entry_point
}

rule pespin_1330 {
	meta:
		tool = "P"
		name = "PESpin"
		version = "1.330"
		pattern = "EB016860E8000000008B1C2483C312812BE8B10600FE4BFD822C2477E746000BE4749E7501C7817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800A3687201FF5D33C941E217EB07EAEB01EBEB0DFFE801000000EA5A83EA0BFFE2EB049A"
	strings:
		$1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 77 E7 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A }
	condition:
		$1 at pe.entry_point
}

rule pestuboep_1x_01 {
	meta:
		tool = "P"
		name = "PEStubOEP"
		version = "1.x"
		pattern = "4048BE00????0040486033C0B8??????00FFE0C3C3"
	strings:
		$1 = { 40 48 BE 00 ?? ?? 00 40 48 60 33 C0 B8 ?? ?? ?? 00 FF E0 C3 C3 }
	condition:
		$1 at pe.entry_point
}

rule pestuboep_1x_02 {
	meta:
		tool = "P"
		name = "PeStubOEP"
		version = "1.x"
		pattern = "9033C933D2B8??????00B9FF"
	strings:
		$1 = { 90 33 C9 33 D2 B8 ?? ?? ?? 00 B9 FF }
	condition:
		$1 at pe.entry_point
}

rule pestuboep_1x_03 {
	meta:
		tool = "P"
		name = "PeStubOEP"
		version = "1.x"
		pattern = "E80500000033C04048C3E805"
	strings:
		$1 = { E8 05 00 00 00 33 C0 40 48 C3 E8 05 }
	condition:
		$1 at pe.entry_point
}

rule petite__uv {
	meta:
		tool = "P"
		name = "Petite"
		pattern = "B8????????669C6050"
	strings:
		$1 = { B8 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		$1 at pe.entry_point
}

rule petite_12 {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.2"
		pattern = "9C60E8CA??????03??04??05??06??07??08"
	strings:
		$1 = { 9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }
	condition:
		$1 at pe.entry_point
}

rule petite_13_01 {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.3"
		pattern = "??????????669C60508D88??F?????8D900416????8BDC8BE168????????5350800424085080042442"
	strings:
		$1 = { ?? ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? F? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42 }
	condition:
		$1 at pe.entry_point
}

rule petite_13_02 {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.3"
		pattern = "????????????9C60508D8800??????8D90????00008BDC8BE1680000????53508004240850800424425080042461508004249D50800424BB833A000F84DA1400008B442418F64203807419FD807203808BF08BF8037204037A088B0AF3A583C20CFCEBD48B7A0803F88B5A0485DB7413525357030250E87B00000085C0742E5F5F585A8B4A0CC1F902F3AB8B4A0C83E103F3AA83C210EBA04552524F522100436F727275707420"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? 9C 60 50 8D 88 00 ?? ?? ?? 8D 90 ?? ?? 00 00 8B DC 8B E1 68 00 00 ?? ?? 53 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 DA 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03 72 04 03 7A 08 8B 0A F3 A5 83 C2 0C FC EB D4 8B 7A 08 03 F8 8B 5A 04 85 DB 74 13 52 53 57 03 02 50 E8 7B 00 00 00 85 C0 74 2E 5F 5F 58 5A 8B 4A 0C C1 F9 02 F3 AB 8B 4A 0C 83 E1 03 F3 AA 83 C2 10 EB A0 45 52 52 4F 52 21 00 43 6F 72 72 75 70 74 20 }
	condition:
		$1 at pe.entry_point
}

rule petite_13a {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.3a"
		pattern = "??????????669C60508D88????????8D90F815????8BDC8BE168????????5350800424085080042442"
	strings:
		$1 = { ?? ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 F8 15 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42 }
	condition:
		$1 at pe.entry_point
}

rule petite_14_01 {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.4"
		pattern = "669C60508BD803??6854BC????6A??FF50148BCC"
	strings:
		$1 = { 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B CC }
	condition:
		$1 at pe.entry_point
}

rule petite_14_02 {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.4"
		pattern = "B8????????669C60508BD8030068????????6A00"
	strings:
		$1 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00 }
	condition:
		$1 at pe.entry_point
}

rule petite_14_03 {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.4"
		pattern = "??????????669C60508BD803006854BC00006A00FF50148BCC8DA054BC0000508BC38D90??160000680000????51508004240850800424425080042461508004249D50800424BB833A000F84D81400008B442418F64203807419FD807203808BF08BF8037204037A088B0AF3A583C20CFCEBD48B7A0803F88B5A0485DB7413525357030250E87900000085C074305F5F585A8B4A0CC1F90233C0F3AB8B4A0C83E103F3AA83C210"
	strings:
		$1 = { ?? ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC 8D A0 54 BC 00 00 50 8B C3 8D 90 ?? 16 00 00 68 00 00 ?? ?? 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 D8 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03 72 04 03 7A 08 8B 0A F3 A5 83 C2 0C FC EB D4 8B 7A 08 03 F8 8B 5A 04 85 DB 74 13 52 53 57 03 02 50 E8 79 00 00 00 85 C0 74 30 5F 5F 58 5A 8B 4A 0C C1 F9 02 33 C0 F3 AB 8B 4A 0C 83 E1 03 F3 AA 83 C2 10 }
	condition:
		$1 at pe.entry_point
}

rule petite_14_04_or_higher {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.4 or higher"
		pattern = "B8????????669C60508D??????????68????????83"
	strings:
		$1 = { B8 ?? ?? ?? ?? 66 9C 60 50 8D ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 83 }
	condition:
		$1 at pe.entry_point
}

rule petite_20 {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.0"
		pattern = "B8????????669C60508BD803??6854BC????6A??FF50188BCC8DA054BC????8BC38D90E015????68"
	strings:
		$1 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 18 8B CC 8D A0 54 BC ?? ?? 8B C3 8D 90 E0 15 ?? ?? 68 }
	condition:
		$1 at pe.entry_point
}

rule petite_21_01 {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.1"
		pattern = "B8????????68????????64????????????64????????????669C6050"
	strings:
		$1 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		$1 at pe.entry_point
}

rule petite_21_02 {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.1"
		pattern = "B8????????6A??68????????64FF35????????648925????????669C6050"
	strings:
		$1 = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		$1 at pe.entry_point
}

rule petite_22_01 {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.2"
		pattern = "B800?04?006?00????0???????????0000"
	strings:
		$1 = { B8 00 ?0 4? 00 6? 00 ?? ?? 0? ?? ?? ?? ?? ?? 00 00 }
	condition:
		$1 at pe.entry_point
}

rule petite_22_02 {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.2"
		pattern = "B8????????68????????64FF35????????648925????????669C6050"
	strings:
		$1 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		$1 at pe.entry_point
}

rule petite_22_03 {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.2"
		pattern = "B8??????????68????????64FF350000000064892500000000669C6050680000????8B3C248B306681C780078D74060889388B5E1050566A026880080000576A??6A06566A04688008000057FFD383EE0859F3A5596683C76881C6????0000F3A5FFD3588D90B80100008B0A0FBAF11F73168B0424FD8BF08BF8037204037A08F3A583C20CFCEBE283C2108B5AF485DB74D88B04248B7AF803F8528D3401EB175858585A74C4E91C"
	strings:
		$1 = { B8 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 68 00 00 ?? ?? 8B 3C 24 8B 30 66 81 C7 80 07 8D 74 06 08 89 38 8B 5E 10 50 56 6A 02 68 80 08 00 00 57 6A ?? 6A 06 56 6A 04 68 80 08 00 00 57 FF D3 83 EE 08 59 F3 A5 59 66 83 C7 68 81 C6 ?? ?? 00 00 F3 A5 FF D3 58 8D 90 B8 01 00 00 8B 0A 0F BA F1 1F 73 16 8B 04 24 FD 8B F0 8B F8 03 72 04 03 7A 08 F3 A5 83 C2 0C FC EB E2 83 C2 10 8B 5A F4 85 DB 74 D8 8B 04 24 8B 7A F8 03 F8 52 8D 34 01 EB 17 58 58 58 5A 74 C4 E9 1C }
	condition:
		$1 at pe.entry_point
}

rule petite_22_or_higher {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.2 or higher"
		pattern = "B8????????6A??68????????64FF350000000064892500000000669C60508BD8030068????????6A00FF50"
	strings:
		$1 = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00 FF 50 }
	condition:
		$1 at pe.entry_point
}

rule petite_23 {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.3"
		pattern = "B800?0??0068????4?0064FF350000000064892500000000669C60508BD8030068????0?006A00FF501C89430868000040008B3C248B336681C780078D741E08893B538B5E10B880080000566A0250576A??6A0A566A045057FFD383EE0859F3A5596683"
	strings:
		$1 = { B8 00 ?0 ?? 00 68 ?? ?? 4? 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68 ?? ?? 0? 00 6A 00 FF 50 1C 89 43 08 68 00 00 40 00 8B 3C 24 8B 33 66 81 C7 80 07 8D 74 1E 08 89 3B 53 8B 5E 10 B8 80 08 00 00 56 6A 02 50 57 6A ?? 6A 0A 56 6A 04 50 57 FF D3 83 EE 08 59 F3 A5 59 66 83 }
	condition:
		$1 at pe.entry_point
}

rule pex_099_01 {
	meta:
		tool = "P"
		name = "PeX"
		version = "0.99"
		pattern = "60E801????????83C404E801????????5D81"
	strings:
		$1 = { 60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81 }
	condition:
		$1 at pe.entry_point
}

rule pex_099_02 {
	meta:
		tool = "P"
		name = "PeX"
		version = "0.99"
		pattern = "E9F50000000D0AC4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C40D0A205065582028632920627920626172745E437261636B506C20626574612072656C65617365202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
	strings:
		$1 = { E9 F5 00 00 00 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 20 50 65 58 20 28 63 29 20 62 79 20 62 61 72 74 5E 43 72 61 63 6B 50 6C 20 62 65 74 61 20 72 65 6C 65 61 73 65 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }
	condition:
		$1 at pe.entry_point
}

rule pi_cryptor_10_01 {
	meta:
		tool = "P"
		name = "Pi Cryptor"
		version = "1.0"
		pattern = "558BEC83C4EC53565731C08945ECB8401E0600E848FAFFFF33C05568361F060064FF306489206A0068800000006A036A006A0168000000808D55EC31C0E84EF4FFFF8B45ECE8F6F7FFFF50E8CCFAFFFF8BD883FBFF744E6A0053E8CDFAFFFF8BF881EFAC2600006A006A0068AC26000053E8DEFAFFFF89F8E8E3F1FFFF89C66A006828310600575653E8AEFAFFFF53E880FAFFFF89FA81EA720100008BC6E855FEFFFF89C689F009C07405E8A8FBFFFF31C0"
	strings:
		$1 = { 55 8B EC 83 C4 EC 53 56 57 31 C0 89 45 EC B8 40 1E 06 00 E8 48 FA FF FF 33 C0 55 68 36 1F 06 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 31 C0 E8 4E F4 FF FF 8B 45 EC E8 F6 F7 FF FF 50 E8 CC FA FF FF 8B D8 83 FB FF 74 4E 6A 00 53 E8 CD FA FF FF 8B F8 81 EF AC 26 00 00 6A 00 6A 00 68 AC 26 00 00 53 E8 DE FA FF FF 89 F8 E8 E3 F1 FF FF 89 C6 6A 00 68 28 31 06 00 57 56 53 E8 AE FA FF FF 53 E8 80 FA FF FF 89 FA 81 EA 72 01 00 00 8B C6 E8 55 FE FF FF 89 C6 89 F0 09 C0 74 05 E8 A8 FB FF FF 31 C0 }
	condition:
		$1 at pe.entry_point
}

rule pi_cryptor_10_02 {
	meta:
		tool = "P"
		name = "Pi Cryptor"
		version = "1.0"
		pattern = "8955F8BB010000008A041F240F8B55FC8A143280E20F32C28A141F80E2F002D088141F468D45F48B55FCE8????????8B45F4E8????????3BF07E05BE0100000043FF4DF875C2????????5A595964891068????????8D45F4E8????????C3E9"
	strings:
		$1 = { 89 55 F8 BB 01 00 00 00 8A 04 1F 24 0F 8B 55 FC 8A 14 32 80 E2 0F 32 C2 8A 14 1F 80 E2 F0 02 D0 88 14 1F 46 8D 45 F4 8B 55 FC E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 3B F0 7E 05 BE 01 00 00 00 43 FF 4D F8 75 C2 ?? ?? ?? ?? 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? C3 E9 }
	condition:
		$1 at pe.entry_point
}

rule pohernah_100 {
	meta:
		tool = "P"
		name = "Pohernah"
		version = "1.0.0"
		pattern = "5860E8000000005D81ED202540008BBD862540008B8D8E2540006BC00583F00489859225400083F900742D817F1CAB000000751E8B770C03B58A25400031C03B4710740E508B85922540003006584046EBED83C72849EBCE8B85822540008944241C61FFE0"
	strings:
		$1 = { 58 60 E8 00 00 00 00 5D 81 ED 20 25 40 00 8B BD 86 25 40 00 8B 8D 8E 25 40 00 6B C0 05 83 F0 04 89 85 92 25 40 00 83 F9 00 74 2D 81 7F 1C AB 00 00 00 75 1E 8B 77 0C 03 B5 8A 25 40 00 31 C0 3B 47 10 74 0E 50 8B 85 92 25 40 00 30 06 58 40 46 EB ED 83 C7 28 49 EB CE 8B 85 82 25 40 00 89 44 24 1C 61 FF E0 }
	condition:
		$1 at pe.entry_point
}

rule pohernah_101 {
	meta:
		tool = "P"
		name = "Pohernah"
		version = "1.0.1 Crypter"
		pattern = "60E8000000005D81EDF12640008BBD182840008B8D20284000B83828400001E880300583F9007471817F1CAB00000075628B570C03951C28400031C05131C966B9FA006683F90074498B570C03951C2840008B852428400083F802750681C200020000518B4F1083F802750681E90002000057BFC800000089CEE82700000089C15FB83828400001E8E8240000005949EBB15983C72849EB8A8B85142840008944241C61FFE0"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED F1 26 40 00 8B BD 18 28 40 00 8B 8D 20 28 40 00 B8 38 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 1C 28 40 00 31 C0 51 31 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 1C 28 40 00 8B 85 24 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 38 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 14 28 40 00 89 44 24 1C 61 FF E0 }
	condition:
		$1 at pe.entry_point
}

rule pohernah_102 {
	meta:
		tool = "P"
		name = "Pohernah"
		version = "1.0.2 Crypter"
		pattern = "60E8000000005D81EDDE2640008BBD052840008B8D0D284000B82528400001E880300583F9007471817F1CAB00000075628B570C03950928400031C05131C966B9F7006683F90074498B570C0395092840008B851128400083F802750681C200020000518B4F1083F802750681E90002000057BFC800000089CEE82700000089C15FB82528400001E8E8240000005949EBB15983C72849EB8A8B85012840008944241C61FFE0"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED DE 26 40 00 8B BD 05 28 40 00 8B 8D 0D 28 40 00 B8 25 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 09 28 40 00 31 C0 51 31 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 09 28 40 00 8B 85 11 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 25 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 01 28 40 00 89 44 24 1C 61 FF E0 }
	condition:
		$1 at pe.entry_point
}

rule pohernah_103 {
	meta:
		tool = "P"
		name = "Pohernah"
		version = "1.0.3 Crypter"
		pattern = "60E8000000005D81ED2A27400031C04083F006403D401F00007507BE6A274000EB02EBEB8B859E28400083F801751731C001EE3D99000000740C8B8D86284000300E4046EBED"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 2A 27 40 00 31 C0 40 83 F0 06 40 3D 40 1F 00 00 75 07 BE 6A 27 40 00 EB 02 EB EB 8B 85 9E 28 40 00 83 F8 01 75 17 31 C0 01 EE 3D 99 00 00 00 74 0C 8B 8D 86 28 40 00 30 0E 40 46 EB ED }
	condition:
		$1 at pe.entry_point
}

rule polycrypt_214b_215_01 {
	meta:
		tool = "P"
		name = "PolyCrypt PE"
		version = "2.1.4b, 2.1.5"
		pattern = "506F6C7943727970742050452028632920323030342D323030352C204A4C6162536F6674776172652E0050004300500045"
	strings:
		$1 = { 50 6F 6C 79 43 72 79 70 74 20 50 45 20 28 63 29 20 32 30 30 34 2D 32 30 30 35 2C 20 4A 4C 61 62 53 6F 66 74 77 61 72 65 2E 00 50 00 43 00 50 00 45 }
	condition:
		$1 at pe.entry_point
}

rule polycrypt_214b_215_02 {
	meta:
		tool = "P"
		name = "PolyCrypt PE"
		version = "2.1.4b, 2.1.5"
		pattern = "918BF4ADFEC9803408??E2FAC360E8EDFFFFFFEB"
	strings:
		$1 = { 91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB }
	condition:
		$1 at pe.entry_point
}

rule polycryptor_uv {
	meta:
		tool = "P"
		name = "PolyCryptor"
		pattern = "EB??28506F6C7953637279707420??????20627920534D5429"
	strings:
		$1 = { EB ?? 28 50 6F 6C 79 53 63 72 79 70 74 20 ?? ?? ?? 20 62 79 20 53 4D 54 29 }
	condition:
		$1 at pe.entry_point
}

rule polyene_001_or_higher_01 {
	meta:
		tool = "P"
		name = "PolyEnE"
		version = "0.01 or higher"
		pattern = "506F6C79456E45004D657373616765426F7841005553455233322E646C6C"
	strings:
		$1 = { 50 6F 6C 79 45 6E 45 00 4D 65 73 73 61 67 65 42 6F 78 41 00 55 53 45 52 33 32 2E 64 6C 6C }
	condition:
		$1 at pe.entry_point
}

rule polyene_001_or_higher_02 {
	meta:
		tool = "P"
		name = "PolyEnE"
		version = "0.01 or higher"
		pattern = "600000E0????????????????????????????????????????????????????????????????????????600000E0"
	strings:
		$1 = { 60 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 00 00 E0 }
	condition:
		$1 at pe.entry_point
}

rule popa_001 {
	meta:
		tool = "P"
		name = "PoPa"
		version = "0.01"
		pattern = "558BEC83C4EC53565733C08945ECB8A43E0010E830F6FFFF33C05568BE400010????????89206A0068800000006A036A006A0168000000808D55EC33C0E862E7FFFF8B45ECE832F2FFFF50E8B4F6FFFFA36466001033D255689340001064FF32648922833D64660010FF0F843A0100006A006A006A00A16466001050E89BF6FFFF83E81050A16466001050E8BCF6FFFF6A0068806600106A106868660010A16466001050E88BF6FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 A4 3E 00 10 E8 30 F6 FF FF 33 C0 55 68 BE 40 00 10 ?? ?? ?? ?? 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 62 E7 FF FF 8B 45 EC E8 32 F2 FF FF 50 E8 B4 F6 FF FF A3 64 66 00 10 33 D2 55 68 93 40 00 10 64 FF 32 64 89 22 83 3D 64 66 00 10 FF 0F 84 3A 01 00 00 6A 00 6A 00 6A 00 A1 64 66 00 10 50 E8 9B F6 FF FF 83 E8 10 50 A1 64 66 00 10 50 E8 BC F6 FF FF 6A 00 68 80 66 00 10 6A 10 68 68 66 00 10 A1 64 66 00 10 50 E8 8B F6 FF FF }
	condition:
		$1 at pe.entry_point
}

rule ppc_protect_11x {
	meta:
		tool = "P"
		name = "PPC-PROTECT"
		version = "1.1x"
		pattern = "FF5F2DE920009FE5000090E518008FE518009FE5000090E510008FE50100A0E3000000EB020000EA04F01FE5"
	strings:
		$1 = { FF 5F 2D E9 20 00 9F E5 00 00 90 E5 18 00 8F E5 18 00 9F E5 00 00 90 E5 10 00 8F E5 01 00 A0 E3 00 00 00 EB 02 00 00 EA 04 F0 1F E5 }
	condition:
		$1 at pe.entry_point
}

rule princesssandy_10 {
	meta:
		tool = "P"
		name = "PrincessSandy"
		version = "1.0"
		pattern = "6827114000E83C0100006A00E841010000A3002040008B583C03D80FB743140FB74B068D7C1818813F2E4C4F41740B83C7284975F2E9A70000008B5F0C031D00204000891D042040008BFB83C704684C20400068082040006A006A006A206A006A006A00576A00E8CE00000085C07478BD50C300008B3D042040008B078D3C0783C704893D042040008B0F83C7048B1F83C7044D85ED7457606A0051685C20400053FF354C2040"
	strings:
		$1 = { 68 27 11 40 00 E8 3C 01 00 00 6A 00 E8 41 01 00 00 A3 00 20 40 00 8B 58 3C 03 D8 0F B7 43 14 0F B7 4B 06 8D 7C 18 18 81 3F 2E 4C 4F 41 74 0B 83 C7 28 49 75 F2 E9 A7 00 00 00 8B 5F 0C 03 1D 00 20 40 00 89 1D 04 20 40 00 8B FB 83 C7 04 68 4C 20 40 00 68 08 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 57 6A 00 E8 CE 00 00 00 85 C0 74 78 BD 50 C3 00 00 8B 3D 04 20 40 00 8B 07 8D 3C 07 83 C7 04 89 3D 04 20 40 00 8B 0F 83 C7 04 8B 1F 83 C7 04 4D 85 ED 74 57 60 6A 00 51 68 5C 20 40 00 53 FF 35 4C 20 40 }
	condition:
		$1 at pe.entry_point
}

rule private_exe_protector_18_01 {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "1.8"
		pattern = "BBDCEE0D76D9D08D1685D890D9D0"
	strings:
		$1 = { BB DC EE 0D 76 D9 D0 8D 16 85 D8 90 D9 D0 }
	condition:
		$1 at pe.entry_point
}

rule private_exe_protector_18_02 {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "1.8"
		pattern = "A4B302E86D00000073F631C9E864000000731C31C0E85B0000007323B30241B010E84F00000010C073F7753FAAEBD4E84D00000029D97510E842000000EB28ACD1E8744D11C9EB1C9148C1E008ACE82C0000003D007D0000730A80FC05730683F87F770241419589E8B3015689FE29C6F3A45EEB8E00D275058A164610D2C331C941E8EEFFFFFF11C9E8E7FFFFFF72F2C331FF31F6C3"
	strings:
		$1 = { A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 FF 31 F6 C3 }
	condition:
		$1 at pe.entry_point
}

rule private_exe_protector_18_19 {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "1.8 - 1.9"
		pattern = "00000000000000000000000000000000000000004B45524E454C33322E444C4C00????????0000000000004578697450726F63657373"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
	condition:
		$1 at pe.entry_point
}

rule private_exe_protector_197 {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "1.9.7"
		pattern = "558BEC83C4F4FC5357568B7424208B7C242466813E4A430F85A502000083C60A33DBBA00000080C744241408000000438DA424000000008BFF03D275088B1683C604F913D2732C8B4C241033C08DA42400000000050000000003D275088B1683C604F913D213C04975EF0244240C880747EBC603D275088B1683C604F913D20F826E01000003D275088B1683C604F913D20F83DC000000B90400000033C08DA424000000008D64240003D275088B1683C604F913D213C04975EF4874B10F89EF01000003D275088B1683C604F913D27342BD00010000B90800000033C08DA42400000000050000000003D275088B1683C604F913D213C04975EF8807474D75D6"
	strings:
		$1 = { 55 8B EC 83 C4 F4 FC 53 57 56 8B 74 24 20 8B 7C 24 24 66 81 3E 4A 43 0F 85 A5 02 00 00 83 C6 0A 33 DB BA 00 00 00 80 C7 44 24 14 08 00 00 00 43 8D A4 24 00 00 00 00 8B FF 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 2C 8B 4C 24 10 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 02 44 24 0C 88 07 47 EB C6 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 82 6E 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 83 DC 00 00 00 B9 04 00 00 00 33 C0 8D A4 24 00 00 00 00 8D 64 24 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 48 74 B1 0F 89 EF 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 42 BD 00 01 00 00 B9 08 00 00 00 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 88 07 47 4D 75 D6 }
	condition:
		$1 at pe.entry_point
}

rule private_exe_protector_1x {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "1.x"
		pattern = "B8????????B9??9001??BE??1040??68509141??6801??????C3"
	strings:
		$1 = { B8 ?? ?? ?? ?? B9 ?? 90 01 ?? BE ?? 10 40 ?? 68 50 91 41 ?? 68 01 ?? ?? ?? C3 }
	condition:
		$1 at pe.entry_point
}

rule private_exe_protector_20_01 {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "2.0"
		pattern = "0000000000000000????????????????00000000000000000000000000000000000000004B45524E454C33322E444C4C00????????000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule private_exe_protector_20_02 {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "2.0"
		pattern = "89????380000008B??0000000081??????????89??0000000081??0400000081??0400000081??000000000F85D6FFFFFF"
	strings:
		$1 = { 89 ?? ?? 38 00 00 00 8B ?? 00 00 00 00 81 ?? ?? ?? ?? ?? 89 ?? 00 00 00 00 81 ?? 04 00 00 00 81 ?? 04 00 00 00 81 ?? 00 00 00 00 0F 85 D6 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule private_exe_protector_215_220 {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "2.15 - 2.20"
		pattern = "00000000000000000000000000????????????????00000000000000000000000000000000000000004B45524E454C33322E444C4C0000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule private_exe_protector_230_24x {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "2.30 - 2.4x"
		pattern = "000000000000000000000000????????????????????????????????????????000000000000000000000000000000000000000000000400????????????????????????????????0000000000000000000000000000000000000000000000E0????????????????????????????????????????????????000000000000000000000000000000E0000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule private_exe_protector_25x_27x {
	meta:
		tool = "P"
		name = "Private exe Protector"
		version = "2.5x - 2.7x"
		pattern = "0000000000000000????????????????????????00100000????????00040000000000000000000000000000200000E0????????????????????????????????000000000000000000000000000000000000000000000400????????????????????????????????0000000000000000000000000000000000000000000000E0????????????????????????????????????????????????000000000000000000000000000000E0????????????????????????????????????????????????000000000000000000000000400000C000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 ?? ?? ?? ?? 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule private_personal_packer_102 {
	meta:
		tool = "P"
		name = "Private Personal Packer"
		version = "1.0.2"
		pattern = "E817000000E868000000FF352C370010E8ED0100006A00E82E040000E841040000A3743700106A64E85F040000E830040000A3783700106A64E84E040000E81F040000A37C370010A1743700108B1D783700102BD88B0D7C3700102BC883FB64730F81F9C800000073076A00E8D9030000C36A0A6A076A00"
	strings:
		$1 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 }
	condition:
		$1 at pe.entry_point
}

rule private_personal_packer_103 {
	meta:
		tool = "P"
		name = "Private Personal Packer"
		version = "1.0.3"
		pattern = "E8190000009090E868000000FF352C370010E8ED0100006A00E82E040000E841040000A3743700106A64E85F040000E830040000A3783700106A64E84E040000E81F040000A37C370010A1743700108B1D783700102BD88B0D7C3700102BC883FB64730F81F9C800000073076A00E8D9030000C36A0A6A076A00E8D3030000A320370010506A00E8DE030000A324370010FF35203700106A00E8EA030000A330370010FF3524370010E8C2030000A3283700108B0D303700108B3D28370010EB0949C0043955803439240BC9"
	strings:
		$1 = { E8 19 00 00 00 90 90 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9 }
	condition:
		$1 at pe.entry_point
}

rule privatexe_20a_01 {
	meta:
		tool = "P"
		name = "PrivateEXE"
		version = "2.0a"
		pattern = "53E8????????5B8BC32D"
	strings:
		$1 = { 53 E8 ?? ?? ?? ?? 5B 8B C3 2D }
	condition:
		$1 at pe.entry_point
}

rule privatexe_20a_02 {
	meta:
		tool = "P"
		name = "PrivateEXE"
		version = "2.0a"
		pattern = "0660C8??????0E68????9A????????3D????0F??????50500E68????9A????????0E"
	strings:
		$1 = { 06 60 C8 ?? ?? ?? 0E 68 ?? ?? 9A ?? ?? ?? ?? 3D ?? ?? 0F ?? ?? ?? 50 50 0E 68 ?? ?? 9A ?? ?? ?? ?? 0E }
	condition:
		$1 at pe.entry_point
}

rule proactivate_uv {
	meta:
		tool = "P"
		name = "PROACTIVATE"
		pattern = "558BECB90E0000006A006A004975F951535657B8??????00909090909033C05568????????64FF30648920A1????????83C005A3????????C705????????0D000000E885E2FFFF813D????????217E7E"
	strings:
		$1 = { 55 8B EC B9 0E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? ?? ?? 00 90 90 90 90 90 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 A1 ?? ?? ?? ?? 83 C0 05 A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0D 00 00 00 E8 85 E2 FF FF 81 3D ?? ?? ?? ?? 21 7E 7E }
	condition:
		$1 at pe.entry_point
}

rule program_protector_xp_10 {
	meta:
		tool = "P"
		name = "Program Protector XP"
		version = "1.0"
		pattern = "E8????????5883D80589C381C3????????8B436450"
	strings:
		$1 = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50 }
	condition:
		$1 at pe.entry_point
}

rule protect_shareware_11 {
	meta:
		tool = "P"
		name = "Protect Shareware"
		version = "1.1"
		pattern = "53007400720069006E006700460069006C00650049006E0066006F000000??01000001003000340030003900300034004200300000003400??00010043006F006D00700061006E0079004E0061006D006500000000"
	strings:
		$1 = { 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 ?? 01 00 00 01 00 30 00 34 00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 34 00 ?? 00 01 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule protection_plus_uv {
	meta:
		tool = "P"
		name = "Protection Plus"
		pattern = "506029C064FF30E8????????5D83ED3C89E889A514??????2B851C??????89851C??????8D852703????508B??85C00F85C0??????8DBD5B03????8DB54303"
	strings:
		$1 = { 50 60 29 C0 64 FF 30 E8 ?? ?? ?? ?? 5D 83 ED 3C 89 E8 89 A5 14 ?? ?? ?? 2B 85 1C ?? ?? ?? 89 85 1C ?? ?? ?? 8D 85 27 03 ?? ?? 50 8B ?? 85 C0 0F 85 C0 ?? ?? ?? 8D BD 5B 03 ?? ?? 8D B5 43 03 }
	condition:
		$1 at pe.entry_point
}

rule protext_uv {
	meta:
		tool = "P"
		name = "PROTEXT"
		pattern = "E91D010000E87D00000005E5EBFFF7C0E9408D098D00C1E720C0E6200F88D2010000790468949EAC0F89C601000034B821C966C1E12066C1ED4088E47103E77D"
	strings:
		$1 = { E9 1D 01 00 00 E8 7D 00 00 00 05 E5 EB FF F7 C0 E9 40 8D 09 8D 00 C1 E7 20 C0 E6 20 0F 88 D2 01 00 00 79 04 68 94 9E AC 0F 89 C6 01 00 00 34 B8 21 C9 66 C1 E1 20 66 C1 ED 40 88 E4 71 03 E7 7D }
	condition:
		$1 at pe.entry_point
}

rule pscrambler_12 {
	meta:
		tool = "P"
		name = "pscrambler"
		version = "1.2"
		pattern = "558BECB9040000006A006A004975F95153????????10E82DF3FFFF33C05568E831001064FF306489208D45E0E853F5FFFF8B45E08D55E4E830F6FFFF8B45E48D55E8E8A9F4FFFF8B45E88D55ECE8EEF7FFFF8B55ECB8C4540010E8D9ECFFFF833DC4540010000F8405010000803DA0400010007441A1C4540010E8D9EDFFFFE848E0FFFF8BD8A1C4540010E8C8EDFFFF50B8C4540010E865EFFFFF8BD359E869E1FFFF8BC3E812FAFFFF8BC3E833E0FFFFE9AD000000B805010000E80CE0FFFF8BD8536805010000E857F3FFFF8D45DC8BD3E839EDFFFF8B55DCB814560010B900320010E8BBEDFFFF8B1514560010B8C8540010E853E5FFFFBA01000000B8C8540010E88CE8FFFFE8DFE0FFFF85C075526A00A1C4540010E83BEDFFFF50B8C4540010E8D8EEFFFF8BD0B8C854001059E83BE6FFFFE876E0FFFFB8C8540010E84CE6FFFFE867E0FFFF6A006A006A00A114560010E853EEFFFF506A006A00E841F3FFFF803D9C400010007405E8EFFBFFFF33C05A595964891068EF3100108D45DCBA05000000E87DEBFFFFC3E923E9FFFFEBEB5BE863EAFFFF000000FFFFFFFF0800000074656D702E657865"
	strings:
		$1 = { 55 8B EC B9 04 00 00 00 6A 00 6A 00 49 75 F9 51 53 ?? ?? ?? ?? 10 E8 2D F3 FF FF 33 C0 55 68 E8 31 00 10 64 FF 30 64 89 20 8D 45 E0 E8 53 F5 FF FF 8B 45 E0 8D 55 E4 E8 30 F6 FF FF 8B 45 E4 8D 55 E8 E8 A9 F4 FF FF 8B 45 E8 8D 55 EC E8 EE F7 FF FF 8B 55 EC B8 C4 54 00 10 E8 D9 EC FF FF 83 3D C4 54 00 10 00 0F 84 05 01 00 00 80 3D A0 40 00 10 00 74 41 A1 C4 54 00 10 E8 D9 ED FF FF E8 48 E0 FF FF 8B D8 A1 C4 54 00 10 E8 C8 ED FF FF 50 B8 C4 54 00 10 E8 65 EF FF FF 8B D3 59 E8 69 E1 FF FF 8B C3 E8 12 FA FF FF 8B C3 E8 33 E0 FF FF E9 AD 00 00 00 B8 05 01 00 00 E8 0C E0 FF FF 8B D8 53 68 05 01 00 00 E8 57 F3 FF FF 8D 45 DC 8B D3 E8 39 ED FF FF 8B 55 DC B8 14 56 00 10 B9 00 32 00 10 E8 BB ED FF FF 8B 15 14 56 00 10 B8 C8 54 00 10 E8 53 E5 FF FF BA 01 00 00 00 B8 C8 54 00 10 E8 8C E8 FF FF E8 DF E0 FF FF 85 C0 75 52 6A 00 A1 C4 54 00 10 E8 3B ED FF FF 50 B8 C4 54 00 10 E8 D8 EE FF FF 8B D0 B8 C8 54 00 10 59 E8 3B E6 FF FF E8 76 E0 FF FF B8 C8 54 00 10 E8 4C E6 FF FF E8 67 E0 FF FF 6A 00 6A 00 6A 00 A1 14 56 00 10 E8 53 EE FF FF 50 6A 00 6A 00 E8 41 F3 FF FF 80 3D 9C 40 00 10 00 74 05 E8 EF FB FF FF 33 C0 5A 59 59 64 89 10 68 EF 31 00 10 8D 45 DC BA 05 00 00 00 E8 7D EB FF FF C3 E9 23 E9 FF FF EB EB 5B E8 63 EA FF FF 00 00 00 FF FF FF FF 08 00 00 00 74 65 6D 70 2E 65 78 65 }
	condition:
		$1 at pe.entry_point
}

rule punisher_15d {
	meta:
		tool = "P"
		name = "PUNiSHER"
		version = "1.5d"
		pattern = "EB0483A4BCCE60EB0480BC0411E800000000"
	strings:
		$1 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule punisher_15 {
	meta:
		tool = "P"
		name = "PUNiSHER"
		version = "1.5"
		pattern = "3F0000806620??007E20??009220??00A420??00000000004B45524E454C3332"
	strings:
		$1 = { 3F 00 00 80 66 20 ?? 00 7E 20 ?? 00 92 20 ?? 00 A4 20 ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 }
	condition:
		$1 at pe.entry_point
}

rule punkmode_1x {
	meta:
		tool = "P"
		name = "PuNkMoD"
		version = "1.x"
		pattern = "94B9????0000BC????????80340C"
	strings:
		$1 = { 94 B9 ?? ?? 00 00 BC ?? ?? ?? ?? 80 34 0C }
	condition:
		$1 at pe.entry_point
}

rule qinwyingshieldlicense_10x_121 {
	meta:
		tool = "P"
		name = "QinYingShieldLicense"
		version = "1.0x - 1.21"
		pattern = "E8000000005805????????9C50C20400558BEC565753349947493433EF31CDF5B0CBB5B0A3A1A3A1B9FEB9FEB9FEB9FEBFC9CFA7D1BDA3ACC4E3B2BBD6AAB5C0D5E2C0EFB5C4D6B8C1EECAC7CAB2C3B4A3A1B9FEB9FEB9FE00000000000000"
	strings:
		$1 = { E8 00 00 00 00 58 05 ?? ?? ?? ?? 9C 50 C2 04 00 55 8B EC 56 57 53 34 99 47 49 34 33 EF 31 CD F5 B0 CB B5 B0 A3 A1 A3 A1 B9 FE B9 FE B9 FE B9 FE BF C9 CF A7 D1 BD A3 AC C4 E3 B2 BB D6 AA B5 C0 D5 E2 C0 EF B5 C4 D6 B8 C1 EE CA C7 CA B2 C3 B4 A3 A1 B9 FE B9 FE B9 FE 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule qryptor_uv_01 {
	meta:
		tool = "P"
		name = "QrYPt0r"
		pattern = "EB00E8B5000000E92E01000064FF3500000000????????????????????????????????????????????????????????????????????????????????????????????????????648925000000008B442404"
	strings:
		$1 = { EB 00 E8 B5 00 00 00 E9 2E 01 00 00 64 FF 35 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 89 25 00 00 00 00 8B 44 24 04 }
	condition:
		$1 at pe.entry_point
}

rule qryptor_uv_02 {
	meta:
		tool = "P"
		name = "QrYPt0r"
		pattern = "80F9000F848D0100008AC3????????????????????????????????????????????????????????????????????????????????????????????????????32C13CF37589????????????????????????????????????????????????????????????????????????????????????????????????????BAD9040000E8000000005F81C716010000802C3A01"
	strings:
		$1 = { 80 F9 00 0F 84 8D 01 00 00 8A C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 C1 3C F3 75 89 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BA D9 04 00 00 E8 00 00 00 00 5F 81 C7 16 01 00 00 80 2C 3A 01 }
	condition:
		$1 at pe.entry_point
}

rule qryptor_uv_03 {
	meta:
		tool = "P"
		name = "QrYPt0r"
		pattern = "8618CC64FF3500000000????????????????????????????????????????????????????????????????????????????????????????????????????64892500000000BB0000F7BF????????????????????????????????????????????????????????????????????????????????????????????????????B8785634128703E8CDFEFFFFE8B3"
	strings:
		$1 = { 86 18 CC 64 FF 35 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 89 25 00 00 00 00 BB 00 00 F7 BF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B8 78 56 34 12 87 03 E8 CD FE FF FF E8 B3 }
	condition:
		$1 at pe.entry_point
}

rule riscs_process_patcher_14 {
	meta:
		tool = "P"
		name = "R!SC's Process Patcher"
		version = "1.4"
		pattern = "E8E10100008038227513803800742E80382075068078FF22741840EBED803800741BEB19408078FF2075F9803800740DEB0B40803800740580382274008BF8B8046040006800204000C705A220400044000000689220400068A22040006A006A006A046A006A006A005750E87C01000085C00F842A010000B8006040008B00A31C224000BE40604000837EFC000F84F60000008B3E83C60485FF0F848300000081FF722173630F"
	strings:
		$1 = { E8 E1 01 00 00 80 38 22 75 13 80 38 00 74 2E 80 38 20 75 06 80 78 FF 22 74 18 40 EB ED 80 38 00 74 1B EB 19 40 80 78 FF 20 75 F9 80 38 00 74 0D EB 0B 40 80 38 00 74 05 80 38 22 74 00 8B F8 B8 04 60 40 00 68 00 20 40 00 C7 05 A2 20 40 00 44 00 00 00 68 92 20 40 00 68 A2 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 7C 01 00 00 85 C0 0F 84 2A 01 00 00 B8 00 60 40 00 8B 00 A3 1C 22 40 00 BE 40 60 40 00 83 7E FC 00 0F 84 F6 00 00 00 8B 3E 83 C6 04 85 FF 0F 84 83 00 00 00 81 FF 72 21 73 63 0F }
	condition:
		$1 at pe.entry_point
}

rule riscs_process_patcher_151 {
	meta:
		tool = "P"
		name = "R!SC's Process Patcher"
		version = "1.5.1"
		pattern = "6800204000E8C3010000803800740D668178FE22207502EB0340EBEE8BF8B80460400068C420400068D42040006A006A006A046A006A006A005750E89F01000085C00F8439010000BE006040008B06A32821400083C640837EFC000F848F0000008B3E83C60485FF0F84E500000081FF72217363747A0FB71E8BCF8D7E02C70524214000000000008305242140000150A128214000390524214000580F84D8000000606A005368"
	strings:
		$1 = { 68 00 20 40 00 E8 C3 01 00 00 80 38 00 74 0D 66 81 78 FE 22 20 75 02 EB 03 40 EB EE 8B F8 B8 04 60 40 00 68 C4 20 40 00 68 D4 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 9F 01 00 00 85 C0 0F 84 39 01 00 00 BE 00 60 40 00 8B 06 A3 28 21 40 00 83 C6 40 83 7E FC 00 0F 84 8F 00 00 00 8B 3E 83 C6 04 85 FF 0F 84 E5 00 00 00 81 FF 72 21 73 63 74 7A 0F B7 1E 8B CF 8D 7E 02 C7 05 24 21 40 00 00 00 00 00 83 05 24 21 40 00 01 50 A1 28 21 40 00 39 05 24 21 40 00 58 0F 84 D8 00 00 00 60 6A 00 53 68 }
	condition:
		$1 at pe.entry_point
}

rule ratpacker_uv {
	meta:
		tool = "P"
		name = "RatPacker (Glue)"
		pattern = "4020FF00000000000000??BE006040008DBE00B0FFFF"
	strings:
		$1 = { 40 20 FF 00 00 00 00 00 00 00 ?? BE 00 60 40 00 8D BE 00 B0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule razor_1911_encryptor_uv {
	meta:
		tool = "P"
		name = "RAZOR 1911 encryptor"
		pattern = "E8????BF????3BFC72??B44CCD21BE????B9????FDF3A5FC"
	strings:
		$1 = { E8 ?? ?? BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC }
	condition:
		$1 at pe.entry_point
}

rule rcryptor_11 {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.1"
		pattern = "8B042483E84F68????????FFD0"
	strings:
		$1 = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 }
	condition:
		$1 at pe.entry_point
}

rule rcryptor_13b {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.3b"
		pattern = "6183EF4F6068????????FFD7"
	strings:
		$1 = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 }
	condition:
		$1 at pe.entry_point
}

rule rcryptor_13_14 {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.3 - 1.4"
		pattern = "558BEC8B44240483E84F68????????FFD0585950"
	strings:
		$1 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 }
	condition:
		$1 at pe.entry_point
}

rule rcryptor_15 {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.5"
		pattern = "832C244F68????????FF542404834424044F"
	strings:
		$1 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F }
	condition:
		$1 at pe.entry_point
}

rule rcryptor_16v_16c {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.6b - 1.6c"
		pattern = "8BC70304242BC78038500F851B8B1FFF68"
	strings:
		$1 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 }
	condition:
		$1 at pe.entry_point
}

rule rcryptor_16_01 {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.6"
		pattern = "33D068????????FFD2"
	strings:
		$1 = { 33 D0 68 ?? ?? ?? ?? FF D2 }
	condition:
		$1 at pe.entry_point
}

rule rcryptor_16_02 {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.6"
		pattern = "60906161807FF04590600F851B8B1FFF68"
	strings:
		$1 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 }
	condition:
		$1 at pe.entry_point
}

rule rcryptor_1x {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.x"
		pattern = "90589050908B00903C5090580F8567D6EF115068"
	strings:
		$1 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 }
	condition:
		$1 at pe.entry_point
}

rule rcryptor_20 {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "2.0"
		pattern = "F7D183F1FF6A00F7D183F1FF810424????????F7D183F1FF"
	strings:
		$1 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF }
	condition:
		$1 at pe.entry_point
}

rule re_crypt_07x_01 {
	meta:
		tool = "P"
		name = "RE-Crypt"
		version = "0.7x"
		pattern = "60E8000000005D558104240A000000C38BF581C5????0000896D348975388B7D3881E700FFFFFF81C74800000047037D608B4D5C83F9007E0F8B17335558891783C70483C1FCEBEC8B"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B 17 33 55 58 89 17 83 C7 04 83 C1 FC EB EC 8B }
	condition:
		$1 at pe.entry_point
}

rule re_crypt_07x_02 {
	meta:
		tool = "P"
		name = "RE-Crypt"
		version = "0.7x"
		pattern = "60E8000000005D81EDF31D4000B97B0900008DBD3B1E40008BF76160E8000000005D558104240A000000C38BF581C5????0000896D348975388B7D3881E700FFFFFF81C74800000047037D608B4D5C83F9007E0F8B"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 61 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B }
	condition:
		$1 at pe.entry_point
}

rule reflexive_arcade_wrapper_uv {
	meta:
		tool = "P"
		name = "Reflexive Arcade Wrapper"
		pattern = "558BEC6AFF68986842006814FA410064A100000000506489250000000083EC585356578965E8FF15F850420033D28AD489153CE842008BC881E1FF000000890D38E84200C1E10803CA890D34E84200C1E810A330E8420033F656E8584300005985C075086A1CE8B0000000598975FCE823400000FF1518514200A344FE4200E8E13E0000A378E84200E88A3C0000E8CC3B0000E83EF5FFFF8975D08D45A450FF1514514200E85D"
	strings:
		$1 = { 55 8B EC 6A FF 68 98 68 42 00 68 14 FA 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 F8 50 42 00 33 D2 8A D4 89 15 3C E8 42 00 8B C8 81 E1 FF 00 00 00 89 0D 38 E8 42 00 C1 E1 08 03 CA 89 0D 34 E8 42 00 C1 E8 10 A3 30 E8 42 00 33 F6 56 E8 58 43 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 23 40 00 00 FF 15 18 51 42 00 A3 44 FE 42 00 E8 E1 3E 00 00 A3 78 E8 42 00 E8 8A 3C 00 00 E8 CC 3B 00 00 E8 3E F5 FF FF 89 75 D0 8D 45 A4 50 FF 15 14 51 42 00 E8 5D }
	condition:
		$1 at pe.entry_point
}

rule res_crypt_102 {
	meta:
		tool = "P"
		name = "ResCrypt"
		version = "1.02"
		pattern = "55E8????????5D81ED06??????BE?????????3F58BDEBA01??????33C9668B4E0C66034E0E85C9745483C6108B0683FA01751B25??????7F83F803740C83F80E740783F8107402EB0583C608EB2D8B460483C608A9??????80740E515625??????7F03C38BF042EBB25103C38B3803FD8B4804D20F300F47E2F959E2AF4A74045E59EBF78D85????????5DFFE?"
	strings:
		$1 = { 55 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? BE ?? ?? ?? ?? ?3 F5 8B DE BA 01 ?? ?? ?? 33 C9 66 8B 4E 0C 66 03 4E 0E 85 C9 74 54 83 C6 10 8B 06 83 FA 01 75 1B 25 ?? ?? ?? 7F 83 F8 03 74 0C 83 F8 0E 74 07 83 F8 10 74 02 EB 05 83 C6 08 EB 2D 8B 46 04 83 C6 08 A9 ?? ?? ?? 80 74 0E 51 56 25 ?? ?? ?? 7F 03 C3 8B F0 42 EB B2 51 03 C3 8B 38 03 FD 8B 48 04 D2 0F 30 0F 47 E2 F9 59 E2 AF 4A 74 04 5E 59 EB F7 8D 85 ?? ?? ?? ?? 5D FF E? }
	condition:
		$1 at pe.entry_point
}

rule reversinglabsprotector_074b {
	meta:
		tool = "P"
		name = "ReversingLabsProtector"
		version = "0.7.4b"
		pattern = "6800004100E801000000C3C3"
	strings:
		$1 = { 68 00 00 41 00 E8 01 00 00 00 C3 C3 }
	condition:
		$1 at pe.entry_point
}

rule rjoiner_12 {
	meta:
		tool = "P"
		name = "RJoiner"
		version = "1.2"
		pattern = "558BEC81EC0C0200008D85F4FDFFFF56506804010000FF1514104000908D85F4FDFFFF50FF151010400090BE0020400090833EFF0F8484000000535733FF8D46"
	strings:
		$1 = { 55 8B EC 81 EC 0C 02 00 00 8D 85 F4 FD FF FF 56 50 68 04 01 00 00 FF 15 14 10 40 00 90 8D 85 F4 FD FF FF 50 FF 15 10 10 40 00 90 BE 00 20 40 00 90 83 3E FF 0F 84 84 00 00 00 53 57 33 FF 8D 46 }
	condition:
		$1 at pe.entry_point
}

rule rjoiner_12a {
	meta:
		tool = "P"
		name = "RJoiner"
		version = "1.2a"
		pattern = "558BEC81EC0C0100008D85F4FEFFFF56506804010000FF150C1040009490948D85F4FEFFFF50FF1508104000949094BE00204000949094833EFF747D535733DB8D7E049490945368800000006A02536A0168000000C057FF15041040008945F89490948B068D7406049490948D45FC53508D4604FF3650FF75F8FF1500104000949094FF75F8FF15101040009490948D85F4FEFFFF6A0A505357682010400053FF15181040009490948B068D740604949094833EFF75895F5B33C05EC9C21000CCCC2411"
	strings:
		$1 = { 55 8B EC 81 EC 0C 01 00 00 8D 85 F4 FE FF FF 56 50 68 04 01 00 00 FF 15 0C 10 40 00 94 90 94 8D 85 F4 FE FF FF 50 FF 15 08 10 40 00 94 90 94 BE 00 20 40 00 94 90 94 83 3E FF 74 7D 53 57 33 DB 8D 7E 04 94 90 94 53 68 80 00 00 00 6A 02 53 6A 01 68 00 00 00 C0 57 FF 15 04 10 40 00 89 45 F8 94 90 94 8B 06 8D 74 06 04 94 90 94 8D 45 FC 53 50 8D 46 04 FF 36 50 FF 75 F8 FF 15 00 10 40 00 94 90 94 FF 75 F8 FF 15 10 10 40 00 94 90 94 8D 85 F4 FE FF FF 6A 0A 50 53 57 68 20 10 40 00 53 FF 15 18 10 40 00 94 90 94 8B 06 8D 74 06 04 94 90 94 83 3E FF 75 89 5F 5B 33 C0 5E C9 C2 10 00 CC CC 24 11 }
	condition:
		$1 at pe.entry_point
}
rule rjoiner_uv {
	meta:
		tool = "P"
		name = "RJoiner"
		pattern = "E803FDFFFF6A00E80C000000FF256C104000FF2570104000FF2574104000FF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C10"
	strings:
		$1 = { E8 03 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 6C 10 40 00 FF 25 70 10 40 00 FF 25 74 10 40 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_uv_01 {
	meta:
		tool = "P"
		name = "RLPack"
		pattern = "60E8000000008B2C2483C4048DB5????????8D9D????????33FFE8830100006A??68????????68????????6A??FF95????????8985????????EB14"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 83 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB 14 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_uv_02 {
	meta:
		tool = "P"
		name = "RLPack"
		pattern = "60E8000000008B2C2483C404EB03??????EB03??????8DB5CB2200008D9DF002000033FFE8????????EB03??????6A4068????????68????????6A00FF959B0A"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 ?? ?? ?? ?? EB 03 ?? ?? ?? 6A 40 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 9B 0A }
	condition:
		$1 at pe.entry_point
}

rule rlpack_uv_03 {
	meta:
		tool = "P"
		name = "RLPack"
		pattern = "B800000000600BC07458E8000000005805430000008038E9750361EB35E800000000582500F0FFFF33FF66BB195A6683C33466391875120FB7503C03D0BBE944"
	strings:
		$1 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_073b_01 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "0.7.3b"
		pattern = "2E726C700000000000500000????????????????????????000000000000000000000000200000E0"
	strings:
		$1 = { 2E 72 6C 70 00 00 00 00 00 50 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_073b_02 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "0.7.3b"
		pattern = "608BDDE8000000005D9532C095899D80000000B842314000BB413040002BC303C533D28A1040B9????00008BF930108A10404975F864EF863D3000000FB9FF4B89525C4CBD77C20CCE884E2DE80000005D0DDB5E564187FC0FF3054081684B937140BB873C40408B8806757040408BBBB343C48F932BF34A88060730F5EA2A35F04B8AC307C1C602C434C074743202C4450B3C96BE0A82C3DE36A97E5A51A6BC63A866CB305820"
	strings:
		$1 = { 60 8B DD E8 00 00 00 00 5D 95 32 C0 95 89 9D 80 00 00 00 B8 42 31 40 00 BB 41 30 40 00 2B C3 03 C5 33 D2 8A 10 40 B9 ?? ?? 00 00 8B F9 30 10 8A 10 40 49 75 F8 64 EF 86 3D 30 00 00 0F B9 FF 4B 89 52 5C 4C BD 77 C2 0C CE 88 4E 2D E8 00 00 00 5D 0D DB 5E 56 41 87 FC 0F F3 05 40 81 68 4B 93 71 40 BB 87 3C 40 40 8B 88 06 75 70 40 40 8B BB B3 43 C4 8F 93 2B F3 4A 88 06 07 30 F5 EA 2A 35 F0 4B 8A C3 07 C1 C6 02 C4 34 C0 74 74 32 02 C4 45 0B 3C 96 BE 0A 82 C3 DE 36 A9 7E 5A 51 A6 BC 63 A8 66 CB 30 58 20 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_10b {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.0b"
		pattern = "60E8000000008D6424048B6C24FC8DB54C0200008D9D1301000033FFEB0FFF743704FF3437FFD383C40883C708833C370075EB"
	strings:
		$1 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$1 at pe.entry_point
}

rule rlpack_111_114 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.11 - 1.14"
		pattern = "60E8000000008B2C2483C4048DB5????????8D9D????????33FFEB0FFF??????FF??????D383C4??83C7??833C370075EB"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF EB 0F FF ?? ?? ?? FF ?? ?? ?? D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB }
	condition:
		$1 at pe.entry_point
}

rule rlpack_112_114_lzma_430 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.12 - 1.14 [LZMA 4.30]"
		pattern = "60E8000000008B2C2483C4048DB5????????8D9D????????33FF6A??68????????68????????6A??FF95????????8985????????EB??60"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? EB ?? 60 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_115_118_aplib_043 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.15 - 1.18 [aPLib 0.43]"
		pattern = "60E8000000008B2C2483C4048DB5????????8D9D????????33FFE845010000EB0FFF743704FF3437FFD383C40883C708833C370075EB"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$1 at pe.entry_point
}

rule rlpack_115_118 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.15 - 1.18 DLL"
		pattern = "807C2408010F85????????60E8000000008B2C2483C4??8DB5????????8D9D????????33FFE8"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_118_aplib_043 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.18 [aPLib 0.43]"
		pattern = "60E8000000008B2C2483C4??8DB51A0400008D9DC102000033FFE861010000EB0FFF743704FF3437FFD383C4??83C7??833C370075EB83BD0604000000740E83BD0A040000007405E8D70100008D743704536A??68????????68????????6A00FF95A70300008985160400005BFFB51604000056FFD383C4??8BB5160400008BC6EB01"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_118_lzma_430 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.18 [LZMA 4.30]"
		pattern = "60E8000000008B2C2483C4??8DB5210B00008D9DFF02000033FFE89F0100006A??68????????68????????6A00FF95AA0A00008985F90A0000EB1460FFB5F90A0000FF3437FF743704FFD36183C7??833C370075E683BD0D0B000000740E83BD110B0000007405E8F60100008D743704536A??68????????68????????6A00FF95AA0A000089851D0B00005B60FFB5F90A000056FFB51D0B0000FFD3618BB51D0B00008BC6EB01"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 ?? 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_119_aplib_043_01 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.19 [aPlib 0.43]"
		pattern = "60E8000000008B2C2483C404837C242801750C8B44242489853C040000EB0C8B853804000089853C0400008DB5600400008D9DEB02000033FFE852010000EB1B8B853C040000FF743704010424FF3437010424FFD383C40883C708833C370075DF83BD4804000000740E83BD4C040000007405E8B80100008D743704536A40680010000068????????6A00FF95D103000089855C0400005BFFB55C04000056FFD383C4088BB55C0400008BC6EB014080380175FA408B3803BD3C04000083C004898558040000E99400000056FF95C903000085C00F84B40000008985540400008BC6EB5B8B85580400008B00A90000008074143500000080508B8558040000C70020202000EB06FFB558040000FFB554040000FF95CD03000085C07471890783C7048B8558040000EB014080380075FA4089855804000066817802008074A580380075A0EB0146803E0075FA46408B3803BD3C04000083C004898558040000803E010F8563FFFFFF680040000068????????FFB55C040000FF95D5030000E83D000000E82401000061E9????????61C3"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_119_aplib_043_02 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.19 [aPlib 0.43]"
		pattern = "807C2408010F858901000060E8000000008B2C2483C404837C242801750C8B44242489853C040000EB0C8B853804000089853C0400008DB5600400008D9DEB02000033FFE852010000EB1B8B853C040000FF743704010424FF3437010424FFD383C40883C708833C370075DF83BD4804000000740E83BD4C040000007405E8B80100008D743704536A40680010000068????????6A00FF95D103000089855C0400005BFFB55C04000056FFD383C4088BB55C0400008BC6EB014080380175FA408B3803BD3C04000083C004898558040000E99400000056FF95C903000085C00F84B40000008985540400008BC6EB5B8B85580400008B00A90000008074143500000080508B8558040000C70020202000EB06FFB558040000FFB554040000FF95CD03000085C07471890783C7048B8558040000EB014080380075FA4089855804000066817802008074A580380075A0EB0146803E0075FA46408B3803BD3C04000083C004898558040000803E010F8563FFFFFF680040000068????????FFB55C040000FF95D5030000E83D000000E82401000061E9????????61C3"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 89 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_119_lzma_430_01 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.19 [LZMA 4.30]"
		pattern = "60E8000000008B2C2483C404837C242801750C8B4424248985490B0000EB0C8B85450B00008985490B00008DB56D0B00008D9D2F03000033FF6A4068001000006800200C006A00FF95DA0A00008985410B0000E876010000EB20608B85490B0000FFB5410B0000FF3437010424FF743704010424FFD36183C708833C370075DA83BD550B000000740E83BD590B0000007405E8D70100008D743704536A40680010000068????????6A00FF95DA0A00008985690B00005B60FFB5410B000056FFB5690B0000FFD3618BB5690B00008BC6EB014080380175FA408B3803BD490B000083C0048985650B0000E99800000056FF95D20A00008985610B000085C00F84C80000008BC6EB5F8B85650B00008B00A90000008074143500000080508B85650B0000C70020202000EB06FFB5650B0000FFB5610B0000FF95D60A000085C00F8487000000890783C7048B85650B0000EB014080380075FA408985650B000066817802008074A1803800759CEB0146803E0075FA46408B3803BD490B000083C0048985650B0000803E010F855FFFFFFF680040000068????????FFB5690B0000FF95DE0A000068004000006800200C00FFB5410B0000FF95DE0A0000E83D000000E82401000061E9????????61C3"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_119_lzma_430_02 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.19 [LZMA 4.30]"
		pattern = "807C2408010F85C701000060E8000000008B2C2483C404837C242801750C8B4424248985490B0000EB0C8B85450B00008985490B00008DB56D0B00008D9D2F03000033FF6A4068001000006800200C006A00FF95DA0A00008985410B0000E876010000EB20608B85490B0000FFB5410B0000FF3437010424FF743704010424FFD36183C708833C370075DA83BD550B000000740E83BD590B0000007405E8D70100008D743704536A40680010000068????????6A00FF95DA0A00008985690B00005B60FFB5410B000056FFB5690B0000FFD3618BB5690B00008BC6EB014080380175FA408B3803BD490B000083C0048985650B0000E99800000056FF95D20A00008985610B000085C00F84C80000008BC6EB5F8B85650B00008B00A90000008074143500000080508B85650B0000C70020202000EB06FFB5650B0000FFB5610B0000FF95D60A000085C00F8487000000890783C7048B85650B0000EB014080380075FA408985650B000066817802008074A1803800759CEB0146803E0075FA46408B3803BD490B000083C0048985650B0000803E010F855FFFFFFF680040000068????????FFB5690B0000FF95DE0A000068004000006800200C00FFB5410B0000FF95DE0A0000E83D000000E82401000061E9????????61C3"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 C7 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_120_basic_edition_aplib {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.20 Basic Edition [aPLib]"
		pattern = "60E8000000008B2C2483C404837C242801750C8B442424898592050000EB0C8B858E0500008985920500008DB5BA0500008D9D4104000033FFE838010000EB1B8B8592050000FF743704010424FF3437010424FFD383C40883C708833C370075DF83BD9E05000000740E83BDA2050000007405E8D6010000"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00 EB 1B 8B 85 92 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 9E 05 00 00 00 74 0E 83 BD A2 05 00 00 00 74 05 E8 D6 01 00 00 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_120_basic_edition_lzma {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.20 Basic Edition [LZMA]"
		pattern = "60E8000000008B2C2483C404837C242801750C8B44242489859C0C0000EB0C8B85980C000089859C0C00008DB5C40C00008D9D8204000033FF6A4068001000006800200C006A00FF952D0C00008985940C0000E859010000EB20608B859C0C0000FFB5940C0000FF3437010424FF743704010424FFD36183"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 9C 0C 00 00 EB 0C 8B 85 98 0C 00 00 89 85 9C 0C 00 00 8D B5 C4 0C 00 00 8D 9D 82 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 2D 0C 00 00 89 85 94 0C 00 00 E8 59 01 00 00 EB 20 60 8B 85 9C 0C 00 00 FF B5 94 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_120_aplib_043 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.20 [aPlib 0.43]"
		pattern = "807C2408010F856F01000060E8000000008B2C2483C404837C242801750C8B442424898592050000EB0C8B858E0500008985920500008DB5BA0500008D9D4104000033FFE838010000EB1B8B8592050000FF743704010424FF3437010424FFD383C40883C708833C370075DF83BD9E05000000740E83BDA2050000007405E8D60100008D743704536A40680010000068????????6A00FF95270500008985B60500005BFFB5B605000056FFD383C4088BB5B60500008BC6EB014080380175FA408B3803BD9205000083C0048985B2050000EB6E56FF951F0500000BC07505E8C902000085C00F84940000008985AE0500008BC6EB2A8B85B20500008B0050FFB5AE050000E81102000085C0747289078385B20500000483C7048B85B205000083380075D1EB0146803E0075FA4683C0048B3803BD9205000083C0048985B2050000803E01758D680040000068????????FFB5B6050000FF952B05000068008000006A00FFB5B6050000FF952B050000E861000000E85C01000061E9????????61C3"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 6F 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00 EB 1B 8B 85 92 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 9E 05 00 00 00 74 0E 83 BD A2 05 00 00 00 74 05 E8 D6 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 27 05 00 00 89 85 B6 05 00 00 5B FF B5 B6 05 00 00 56 FF D3 83 C4 08 8B B5 B6 05 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 92 05 00 00 83 C0 04 89 85 B2 05 00 00 EB 6E 56 FF 95 1F 05 00 00 0B C0 75 05 E8 C9 02 00 00 85 C0 0F 84 94 00 00 00 89 85 AE 05 00 00 8B C6 EB 2A 8B 85 B2 05 00 00 8B 00 50 FF B5 AE 05 00 00 E8 11 02 00 00 85 C0 74 72 89 07 83 85 B2 05 00 00 04 83 C7 04 8B 85 B2 05 00 00 83 38 00 75 D1 EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD 92 05 00 00 83 C0 04 89 85 B2 05 00 00 80 3E 01 75 8D 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 B6 05 00 00 FF 95 2B 05 00 00 68 00 80 00 00 6A 00 FF B5 B6 05 00 00 FF 95 2B 05 00 00 E8 61 00 00 00 E8 5C 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_120_lzma_430 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.20 [LZMA 4.30]"
		pattern = "807C2408010F85AA01000060E8000000008B2C2483C404837C242801750C8B44242489859C0C0000EB0C8B85980C000089859C0C00008DB5C40C00008D9D8204000033FF6A4068001000006800200C006A00FF952D0C00008985940C0000E859010000EB20608B859C0C0000FFB5940C0000FF3437010424FF743704010424FFD36183C708833C370075DA83BDA80C000000740E83BDAC0C0000007405E8F20100008D743704536A40680010000068????????6A00FF952D0C00008985C00C00005B60FFB5940C000056FFB5C00C0000FFD3618BB5C00C00008BC6EB014080380175FA408B3803BD9C0C000083C0048985BC0C0000EB7256FF95250C00000BC07505E8E602000085C00F84AB0000008985B80C00008BC6EB2E8B85BC0C00008B0050FFB5B80C0000E82E02000085C00F848500000089078385BC0C00000483C7048B85BC0C000083380075CDEB0146803E0075FA4683C0048B3803BD9C0C000083C0048985BC0C0000803E017589680040000068????????FFB5C00C0000FF95310C000068008000006A00FFB5C00C0000FF95310C000068008000006A00FFB5940C0000FF95310C0000E861000000E85C01000061E9????????61C3"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 AA 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 9C 0C 00 00 EB 0C 8B 85 98 0C 00 00 89 85 9C 0C 00 00 8D B5 C4 0C 00 00 8D 9D 82 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 2D 0C 00 00 89 85 94 0C 00 00 E8 59 01 00 00 EB 20 60 8B 85 9C 0C 00 00 FF B5 94 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD A8 0C 00 00 00 74 0E 83 BD AC 0C 00 00 00 74 05 E8 F2 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 2D 0C 00 00 89 85 C0 0C 00 00 5B 60 FF B5 94 0C 00 00 56 FF B5 C0 0C 00 00 FF D3 61 8B B5 C0 0C 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 9C 0C 00 00 83 C0 04 89 85 BC 0C 00 00 EB 72 56 FF 95 25 0C 00 00 0B C0 75 05 E8 E6 02 00 00 85 C0 0F 84 AB 00 00 00 89 85 B8 0C 00 00 8B C6 EB 2E 8B 85 BC 0C 00 00 8B 00 50 FF B5 B8 0C 00 00 E8 2E 02 00 00 85 C0 0F 84 85 00 00 00 89 07 83 85 BC 0C 00 00 04 83 C7 04 8B 85 BC 0C 00 00 83 38 00 75 CD EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD 9C 0C 00 00 83 C0 04 89 85 BC 0C 00 00 80 3E 01 75 89 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 C0 0C 00 00 FF 95 31 0C 00 00 68 00 80 00 00 6A 00 FF B5 C0 0C 00 00 FF 95 31 0C 00 00 68 00 80 00 00 6A 00 FF B5 94 0C 00 00 FF 95 31 0C 00 00 E8 61 00 00 00 E8 5C 01 00 00 61 E9 ?? ?? ?? ?? 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_121_aplib_043_01 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.21 [aPlib 0.43]"
		pattern = "60E8000000008B2C2483C404837C242801750C8B4424248985D6050000EB0C8B85D20500008985D6050000E84C0100008DB5FE0500008D9D8504000033FFE877010000EB1B8B85D6050000FF743704010424FF3437010424FFD383C40883C708833C370075DF83BDE205000000740E83BDE6050000007405E8150200008D743704536A40680010000068????????6A00FF956B0500008985FA0500005BFFB5FA05000056FFD383C4088BB5FA0500008BC6EB014080380175FA408B3803BDD605000083C0048985F6050000EB6E56FF95630500000BC07505E80803000085C00F84950000008985F20500008BC6EB2A8B85F60500008B0050FFB5F2050000E85002000085C0747389078385F60500000483C7048B85F605000083380075D1EB0146803E0075FA4683C0048B3803BDD605000083C0048985F6050000803E01758D68????????68????????FFB5FA050000FF956F05000068????????6A00FFB5FA050000FF956F050000E8A0000000E89B01000061E9??????????61C3"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 D6 05 00 00 EB 0C 8B 85 D2 05 00 00 89 85 D6 05 00 00 E8 4C 01 00 00 8D B5 FE 05 00 00 8D 9D 85 04 00 00 33 FF E8 77 01 00 00 EB 1B 8B 85 D6 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD E2 05 00 00 00 74 0E 83 BD E6 05 00 00 00 74 05 E8 15 02 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 6B 05 00 00 89 85 FA 05 00 00 5B FF B5 FA 05 00 00 56 FF D3 83 C4 08 8B B5 FA 05 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD D6 05 00 00 83 C0 04 89 85 F6 05 00 00 EB 6E 56 FF 95 63 05 00 00 0B C0 75 05 E8 08 03 00 00 85 C0 0F 84 95 00 00 00 89 85 F2 05 00 00 8B C6 EB 2A 8B 85 F6 05 00 00 8B 00 50 FF B5 F2 05 00 00 E8 50 02 00 00 85 C0 74 73 89 07 83 85 F6 05 00 00 04 83 C7 04 8B 85 F6 05 00 00 83 38 00 75 D1 EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD D6 05 00 00 83 C0 04 89 85 F6 05 00 00 80 3E 01 75 8D 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF B5 FA 05 00 00 FF 95 6F 05 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 FA 05 00 00 FF 95 6F 05 00 00 E8 A0 00 00 00 E8 9B 01 00 00 61 E9 ?? ?? ?? ?? ?? 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_121_aplib_043_02 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.21 [aPlib 0.43]"
		pattern = "807C2408010F857401000060E8000000008B2C2483C404837C242801750C8B4424248985D6050000EB0C8B85D20500008985D6050000E84C0100008DB5FE0500008D9D8504000033FFE877010000EB1B8B85D6050000FF743704010424FF3437010424FFD383C40883C708833C370075DF83BDE205000000740E83BDE6050000007405E8150200008D743704536A40680010000068????????6A00FF956B0500008985FA0500005BFFB5FA05000056FFD383C4088BB5FA0500008BC6EB014080380175FA408B3803BDD605000083C0048985F6050000EB6E56FF95630500000BC07505E80803000085C00F84950000008985F20500008BC6EB2A8B85F60500008B0050FFB5F2050000E85002000085C0747389078385F60500000483C7048B85F605000083380075D1EB0146803E0075FA4683C0048B3803BDD605000083C0048985F6050000803E01758D68????????68????????FFB5FA050000FF956F05000068????????6A00FFB5FA050000FF956F050000E8A0000000E89B01000061E9??????????61C3"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 74 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 D6 05 00 00 EB 0C 8B 85 D2 05 00 00 89 85 D6 05 00 00 E8 4C 01 00 00 8D B5 FE 05 00 00 8D 9D 85 04 00 00 33 FF E8 77 01 00 00 EB 1B 8B 85 D6 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD E2 05 00 00 00 74 0E 83 BD E6 05 00 00 00 74 05 E8 15 02 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 6B 05 00 00 89 85 FA 05 00 00 5B FF B5 FA 05 00 00 56 FF D3 83 C4 08 8B B5 FA 05 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD D6 05 00 00 83 C0 04 89 85 F6 05 00 00 EB 6E 56 FF 95 63 05 00 00 0B C0 75 05 E8 08 03 00 00 85 C0 0F 84 95 00 00 00 89 85 F2 05 00 00 8B C6 EB 2A 8B 85 F6 05 00 00 8B 00 50 FF B5 F2 05 00 00 E8 50 02 00 00 85 C0 74 73 89 07 83 85 F6 05 00 00 04 83 C7 04 8B 85 F6 05 00 00 83 38 00 75 D1 EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD D6 05 00 00 83 C0 04 89 85 F6 05 00 00 80 3E 01 75 8D 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF B5 FA 05 00 00 FF 95 6F 05 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 FA 05 00 00 FF 95 6F 05 00 00 E8 A0 00 00 00 E8 9B 01 00 00 61 E9 ?? ?? ?? ?? ?? 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_121_lzma_430_01 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.21 [LZMA 4.30]"
		pattern = "60E8000000008B2C2483C404837C242801750C8B4424248985E00C0000EB0C8B85DC0C00008985E00C0000E8870100008DB5080D00008D9DC604000033FF6A4068001000006800200C006A00FF95710C00008985D80C0000E898010000EB20608B85E00C0000FFB5D80C0000FF3437010424FF743704010424FFD36183C708833C370075DA83BDEC0C000000740E83BDF00C0000007405E8310200008D743704536A40680010000068????????6A00FF95710C00008985040D00005B60FFB5D80C000056FFB5040D0000FFD3618BB5040D00008BC6EB014080380175FA408B3803BDE00C000083C0048985000D0000EB7256FF95690C00000BC07505E82503000085C00F84AC0000008985FC0C00008BC6EB2E8B85000D00008B0050FFB5FC0C0000E86D02000085C00F848600000089078385000D00000483C7048B85000D000083380075CDEB0146803E0075FA4683C0048B3803BDE00C000083C0048985000D0000803E01758968????????68????????FFB5040D0000FF95750C000068????????6A00FFB5040D0000FF95750C000068????????6A00FFB5D80C0000FF95750C0000E8A0000000E89B01000061E9??????????61C3"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 E0 0C 00 00 EB 0C 8B 85 DC 0C 00 00 89 85 E0 0C 00 00 E8 87 01 00 00 8D B5 08 0D 00 00 8D 9D C6 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 71 0C 00 00 89 85 D8 0C 00 00 E8 98 01 00 00 EB 20 60 8B 85 E0 0C 00 00 FF B5 D8 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD EC 0C 00 00 00 74 0E 83 BD F0 0C 00 00 00 74 05 E8 31 02 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 71 0C 00 00 89 85 04 0D 00 00 5B 60 FF B5 D8 0C 00 00 56 FF B5 04 0D 00 00 FF D3 61 8B B5 04 0D 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD E0 0C 00 00 83 C0 04 89 85 00 0D 00 00 EB 72 56 FF 95 69 0C 00 00 0B C0 75 05 E8 25 03 00 00 85 C0 0F 84 AC 00 00 00 89 85 FC 0C 00 00 8B C6 EB 2E 8B 85 00 0D 00 00 8B 00 50 FF B5 FC 0C 00 00 E8 6D 02 00 00 85 C0 0F 84 86 00 00 00 89 07 83 85 00 0D 00 00 04 83 C7 04 8B 85 00 0D 00 00 83 38 00 75 CD EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD E0 0C 00 00 83 C0 04 89 85 00 0D 00 00 80 3E 01 75 89 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF B5 04 0D 00 00 FF 95 75 0C 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 04 0D 00 00 FF 95 75 0C 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 D8 0C 00 00 FF 95 75 0C 00 00 E8 A0 00 00 00 E8 9B 01 00 00 61 E9 ?? ?? ?? ?? ?? 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_121_lzma_430_02 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.21 [LZMA 4.30]"
		pattern = "807C2408010F85AF01000060E8000000008B2C2483C404837C242801750C8B4424248985E00C0000EB0C8B85DC0C00008985E00C0000E8870100008DB5080D00008D9DC604000033FF6A4068001000006800200C006A00FF95710C00008985D80C0000E898010000EB20608B85E00C0000FFB5D80C0000FF3437010424FF743704010424FFD36183C708833C370075DA83BDEC0C000000740E83BDF00C0000007405E8310200008D743704536A40680010000068????????6A00FF95710C00008985040D00005B60FFB5D80C000056FFB5040D0000FFD3618BB5040D00008BC6EB014080380175FA408B3803BDE00C000083C0048985000D0000EB7256FF95690C00000BC07505E82503000085C00F84AC0000008985FC0C00008BC6EB2E8B85000D00008B0050FFB5FC0C0000E86D02000085C00F848600000089078385000D00000483C7048B85000D000083380075CDEB0146803E0075FA4683C0048B3803BDE00C000083C0048985000D0000803E017589680040000068????????FFB5040D0000FF95750C000068????????6A00FFB5040D0000FF95750C000068????????6A00FFB5D80C0000FF95750C0000E8A0000000E89B01000061E9??????????61C3"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 AF 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 E0 0C 00 00 EB 0C 8B 85 DC 0C 00 00 89 85 E0 0C 00 00 E8 87 01 00 00 8D B5 08 0D 00 00 8D 9D C6 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 71 0C 00 00 89 85 D8 0C 00 00 E8 98 01 00 00 EB 20 60 8B 85 E0 0C 00 00 FF B5 D8 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD EC 0C 00 00 00 74 0E 83 BD F0 0C 00 00 00 74 05 E8 31 02 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 ?? ?? ?? ?? 6A 00 FF 95 71 0C 00 00 89 85 04 0D 00 00 5B 60 FF B5 D8 0C 00 00 56 FF B5 04 0D 00 00 FF D3 61 8B B5 04 0D 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD E0 0C 00 00 83 C0 04 89 85 00 0D 00 00 EB 72 56 FF 95 69 0C 00 00 0B C0 75 05 E8 25 03 00 00 85 C0 0F 84 AC 00 00 00 89 85 FC 0C 00 00 8B C6 EB 2E 8B 85 00 0D 00 00 8B 00 50 FF B5 FC 0C 00 00 E8 6D 02 00 00 85 C0 0F 84 86 00 00 00 89 07 83 85 00 0D 00 00 04 83 C7 04 8B 85 00 0D 00 00 83 38 00 75 CD EB 01 46 80 3E 00 75 FA 46 83 C0 04 8B 38 03 BD E0 0C 00 00 83 C0 04 89 85 00 0D 00 00 80 3E 01 75 89 68 00 40 00 00 68 ?? ?? ?? ?? FF B5 04 0D 00 00 FF 95 75 0C 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 04 0D 00 00 FF 95 75 0C 00 00 68 ?? ?? ?? ?? 6A 00 FF B5 D8 0C 00 00 FF 95 75 0C 00 00 E8 A0 00 00 00 E8 9B 01 00 00 61 E9 ?? ?? ?? ?? ?? 61 C3 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_117_full_edition {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.17 Full Edition"
		pattern = "60E8000000008B2C2483C404??????????????????????????????8DB5????????8D9D????????33FF"
	strings:
		$1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF }
	condition:
		$1 at pe.entry_point
}

rule rlpack_11x_full_edition {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.1x Full Edition"
		pattern = "000000000000000000000000????????????????00000000000000000000000000000000000000006B65726E656C33322E646C6C00????????????????????????????????????????????????0000000000004C6F61644C69627261727941000047657450726F634164647265737300005669727475616C416C6C6F6300005669727475616C4672656500005669727475616C50726F7465637400004765744D6F64756C6548616E646C654100000010"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 10 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_120_121_full_edition_aplib_043 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.20 - 1.21 Full Edition [aPlib 0.43]"
		pattern = "000000000000000000000000????????????????00000000000000000000000000000000000000006B65726E656C33322E646C6C????????????????????????????????????????????????000000000000004765744D6F64756C6548616E646C654100004C6F61644C69627261727941000047657450726F634164647265737300005669727475616C416C6C6F6300005669727475616C50726F7465637400005669727475616C4672656500000010000008000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 10 00 00 08 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_120_121_full_edition_lzma_430 {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.20 - 1.21 Full Edition [LZMA 4.30]"
		pattern = "000000000000000000000000????????????????00000000000000000000000000000000000000006B65726E656C33322E646C6C????????????????????????????????????????????????000000000000004765744D6F64756C6548616E646C654100004C6F61644C69627261727941000047657450726F634164647265737300005669727475616C416C6C6F6300005669727475616C4672656500005669727475616C50726F7465637400000010000008000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 10 00 00 08 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule rlpack_120_121_full_edition {
	meta:
		tool = "P"
		name = "RLPack"
		version = "1.20 - 1.21 Full Edition"
		extra = "basic edition stub"
		pattern = "000000000000000000000000????????????????00000000000000000000000000000000000000006B65726E656C33322E646C6C????????????????????????????????????????000000000000004C6F61644C69627261727941000047657450726F634164647265737300005669727475616C416C6C6F6300005669727475616C4672656500005669727475616C50726F7465637400000010000008000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 10 00 00 08 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule rod_high_tech_uv {
	meta:
		tool = "P"
		name = "ROD High TECH"
		pattern = "608B151D134000F7E08D8283190000E8580C0000"
	strings:
		$1 = { 60 8B 15 1D 13 40 00 F7 E0 8D 82 83 19 00 00 E8 58 0C 00 00 }
	condition:
		$1 at pe.entry_point
}

rule rosasm_2050a {
	meta:
		tool = "P"
		name = "RosAsm"
		version = "2050a"
		pattern = "558BEC608B5D08B908000000BF????????83C707FD8AC3240F04303C3976020407AAC1EB04E2EEFC680010000068????????68????????6A00FF15????????618BE55DC20400"
	strings:
		$1 = { 55 8B EC 60 8B 5D 08 B9 08 00 00 00 BF ?? ?? ?? ?? 83 C7 07 FD 8A C3 24 0F 04 30 3C 39 76 02 04 07 AA C1 EB 04 E2 EE FC 68 00 10 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 61 8B E5 5D C2 04 00 }
	condition:
		$1 at pe.entry_point
}

rule rpolycrypt_uv {
	meta:
		tool = "P"
		name = "RPolyCrypt"
		pattern = "58??????????????E800000058E800??????????????????????????????????????????????????????????????????????????????????????????000000????04"
	strings:
		$1 = { 58 ?? ?? ?? ?? ?? ?? ?? E8 00 00 00 58 E8 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? 04 }
	condition:
		$1 at pe.entry_point
}

rule rpolycrypt_10 {
	meta:
		tool = "P"
		name = "RPolyCrypt"
		version = "1.0"
		pattern = "5058979760618B04248078F36AE80000000058E800000000589191EB000F856BF4766FE80000000083C404E8000000005890E80000000083C4048B04248078F1"
	strings:
		$1 = { 50 58 97 97 60 61 8B 04 24 80 78 F3 6A E8 00 00 00 00 58 E8 00 00 00 00 58 91 91 EB 00 0F 85 6B F4 76 6F E8 00 00 00 00 83 C4 04 E8 00 00 00 00 58 90 E8 00 00 00 00 83 C4 04 8B 04 24 80 78 F1 }
	condition:
		$1 at pe.entry_point
}

rule safe_20 {
	meta:
		tool = "P"
		name = "Safe"
		version = "2.0"
		pattern = "83EC10535657E8C40100"
	strings:
		$1 = { 83 EC 10 53 56 57 E8 C4 01 00 }
	condition:
		$1 at pe.entry_point
}

rule safedisc_uv {
	meta:
		tool = "P"
		name = "SafeDisc"
		pattern = "85C9740CB8????????2BC383E805EB0E51B9????????8BC12BC303410159C603E9894301"
	strings:
		$1 = { 85 C9 74 0C B8 ?? ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 ?? ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 }
	condition:
		$1 in (pe.entry_point + 17 .. pe.entry_point + 18)
}

rule safedisc_4 {
	meta:
		tool = "P"
		name = "SafeDisc"
		version = "4"
		pattern = "000000000000000000000000426F475F"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F }
	condition:
		$1 at pe.entry_point
}

rule safedisc_450 {
	meta:
		tool = "P"
		name = "SafeDisc"
		version = "4.50"
		pattern = "558BEC60BB6E??????B80D??????33C98A0885C9740CB8E4??????2BC383E805EB0E51B92B??????8BC12BC303410159C603E98943015168D9??????33C085C974058B4508EB0050E825FCFFFF83C4085983F800741CC603C2C643010C85C97409615DB800000000EB9650B8F9??????FF10615DEB47807C2408007540518B4C2404890D????????B902??????894C240459EB2950B8FD??????FF70088B400CFFD0B8FD??????FF308B4004FFD058B825??????FF30C372166113600DE9????????66833D??????????7405E991FEFFFFC3"
	strings:
		$1 = { 55 8B EC 60 BB 6E ?? ?? ?? B8 0D ?? ?? ?? 33 C9 8A 08 85 C9 74 0C B8 E4 ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 2B ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 D9 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 25 FC FF FF 83 C4 08 59 83 F8 00 74 1C C6 03 C2 C6 43 01 0C 85 C9 74 09 61 5D B8 00 00 00 00 EB 96 50 B8 F9 ?? ?? ?? FF 10 61 5D EB 47 80 7C 24 08 00 75 40 51 8B 4C 24 04 89 0D ?? ?? ?? ?? B9 02 ?? ?? ?? 89 4C 24 04 59 EB 29 50 B8 FD ?? ?? ?? FF 70 08 8B 40 0C FF D0 B8 FD ?? ?? ?? FF 30 8B 40 04 FF D0 58 B8 25 ?? ?? ?? FF 30 C3 72 16 61 13 60 0D E9 ?? ?? ?? ?? 66 83 3D ?? ?? ?? ?? ?? 74 05 E9 91 FE FF FF C3 }
	condition:
		$1 at pe.entry_point
}

rule safeguard_10x {
	meta:
		tool = "P"
		name = "SafeGuard"
		version = "1.0x"
		pattern = "E800000000EB29????????????????????????????????????????????????????599C81C1E2FFFFFFEB01??9DFFE1"
	strings:
		$1 = { E8 00 00 00 00 EB 29 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 59 9C 81 C1 E2 FF FF FF EB 01 ?? 9D FF E1 }
	condition:
		$1 at pe.entry_point
}

rule sc_obfuscator {
	meta:
		tool = "P"
		name = "SC Obfuscator"
		pattern = "6033C98B1D????????031D????????8A041984C074093C??740534??880419413B0D????????75E7A1????????0105????????61FF25"
	strings:
		$1 = { 60 33 C9 8B 1D ?? ?? ?? ?? 03 1D ?? ?? ?? ?? 8A 04 19 84 C0 74 09 3C ?? 74 05 34 ?? 88 04 19 41 3B 0D ?? ?? ?? ?? 75 E7 A1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 61 FF 25 }
	condition:
		$1 at pe.entry_point
}

rule scram_08a1 {
	meta:
		tool = "P"
		name = "SCRAM!"
		version = "0.8a1"
		pattern = "B430CD213C0277??CD20BC????B9????8BFCB2??584C"
	strings:
		$1 = { B4 30 CD 21 3C 02 77 ?? CD 20 BC ?? ?? B9 ?? ?? 8B FC B2 ?? 58 4C }
	condition:
		$1 at pe.entry_point
}

rule scram_c5 {
	meta:
		tool = "P"
		name = "SCRAM!"
		version = "C5"
		pattern = "B8????509D9C5825????75??BA????B409CD21CD20"
	strings:
		$1 = { B8 ?? ?? 50 9D 9C 58 25 ?? ?? 75 ?? BA ?? ?? B4 09 CD 21 CD 20 }
	condition:
		$1 at pe.entry_point
}

rule sdc_12 {
	meta:
		tool = "P"
		name = "SDC"
		version = "1.2"
		pattern = "5589E583EC08C7042401000000FF15A0914000E8DBFEFFFF5589E55383EC148B45088B008B003D910000C0773B3D8D0000C0724BBB01000000C744240400000000C7042408000000E8CE24000083F8010F84C400000085C00F85A900000031C083C4145B5DC204003D940000C074563D960000C0741E3D930000C075E1EBB53D050000C08DB4260000000074433D1D0000C075CAC744240400000000C7042404000000E87324000083F8010F849900000085C074A9C7042404000000FFD0B8FFFFFFFFEB9B31DB8D742600E969FFFFFFC744240400000000C704240B000000E83724000083F801747F85C00F846DFFFFFFC704240B0000008D7600FFD0B8FFFFFFFFE959FFFFFFC7042408000000FFD0B8FFFFFFFFE946FFFFFFC744240401000000C7042408000000E8ED230000B8FFFFFFFF85DB0F8425FFFFFFE8DB150000B8FFFFFFFFE916FFFFFFC744240401000000C7042404000000E8BD230000B8FFFFFFFFE9F8FEFFFFC744240401000000C704240B000000E89F230000B8FFFFFFFFE9DAFEFFFF"
	strings:
		$1 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 A0 91 40 00 E8 DB FE FF FF 55 89 E5 53 83 EC 14 8B 45 08 8B 00 8B 00 3D 91 00 00 C0 77 3B 3D 8D 00 00 C0 72 4B BB 01 00 00 00 C7 44 24 04 00 00 00 00 C7 04 24 08 00 00 00 E8 CE 24 00 00 83 F8 01 0F 84 C4 00 00 00 85 C0 0F 85 A9 00 00 00 31 C0 83 C4 14 5B 5D C2 04 00 3D 94 00 00 C0 74 56 3D 96 00 00 C0 74 1E 3D 93 00 00 C0 75 E1 EB B5 3D 05 00 00 C0 8D B4 26 00 00 00 00 74 43 3D 1D 00 00 C0 75 CA C7 44 24 04 00 00 00 00 C7 04 24 04 00 00 00 E8 73 24 00 00 83 F8 01 0F 84 99 00 00 00 85 C0 74 A9 C7 04 24 04 00 00 00 FF D0 B8 FF FF FF FF EB 9B 31 DB 8D 74 26 00 E9 69 FF FF FF C7 44 24 04 00 00 00 00 C7 04 24 0B 00 00 00 E8 37 24 00 00 83 F8 01 74 7F 85 C0 0F 84 6D FF FF FF C7 04 24 0B 00 00 00 8D 76 00 FF D0 B8 FF FF FF FF E9 59 FF FF FF C7 04 24 08 00 00 00 FF D0 B8 FF FF FF FF E9 46 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 08 00 00 00 E8 ED 23 00 00 B8 FF FF FF FF 85 DB 0F 84 25 FF FF FF E8 DB 15 00 00 B8 FF FF FF FF E9 16 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 04 00 00 00 E8 BD 23 00 00 B8 FF FF FF FF E9 F8 FE FF FF C7 44 24 04 01 00 00 00 C7 04 24 0B 00 00 00 E8 9F 23 00 00 B8 FF FF FF FF E9 DA FE FF FF }
	condition:
		$1 at pe.entry_point
}

rule sdprotector_uv {
	meta:
		tool = "P"
		name = "SDProtector"
		pattern = "558BEC6AFF68????????688888880864A10000000050648925000000005864A300000000585858588BE8E83B000000E801000000FF5805"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 }
	condition:
		$1 at pe.entry_point
}

rule sdprotector_11x {
	meta:
		tool = "P"
		name = "SDProtector"
		version = "1.1x"
		pattern = "558BEC6AFF68????????688888880864A1"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1 }
	condition:
		$1 at pe.entry_point
}

rule sdprotector_110_01 {
	meta:
		tool = "P"
		name = "SDProtector"
		version = "1.10 Basic or Pro Edition"
		pattern = "558BEC6AFF681D321305688888880864A10000000050648925000000005864A300000000585858588BE85083EC0864A10000000064FF35000000006489250000000083C4085064FF350000000064892500000000648F050000000064A30000000083C4085874077505193267E8E874277525EB00EBFC683944CD00599C50740F750DE859C20400558BECE9FAFFFF0EE8EFFFFFFF565753780F790DE8349947493433EF31345247"
	strings:
		$1 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 50 83 EC 08 64 A1 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 83 C4 08 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 64 A3 00 00 00 00 83 C4 08 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 }
	condition:
		$1 at pe.entry_point
}

rule sdprotector_110_02 {
	meta:
		tool = "P"
		name = "SDProtector"
		version = "1.10 Basic or Pro Edition"
		pattern = "558BEC6AFF681D321305688888880864A10000000050648925000000005864A300000000585858588BE85083EC0864A10000000064FF35000000006489250000000083C4085064FF35000000006489250000000064"
	strings:
		$1 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 50 83 EC 08 64 A1 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 83 C4 08 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 64 }
	condition:
		$1 at pe.entry_point
}

rule secupack_15 {
	meta:
		tool = "P"
		name = "SecuPack"
		version = "1.5"
		pattern = "558BEC83C4F053565733C08945F0B8CC3A40??E8E0FCFFFF33C05568EA3C40??64FF306489206A??6880??????6A036A??6A01??????80"
	strings:
		$1 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 ?? E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 ?? 64 FF 30 64 89 20 6A ?? 68 80 ?? ?? ?? 6A 03 6A ?? 6A 01 ?? ?? ?? 80 }
	condition:
		$1 at pe.entry_point
}

rule secureexe_30 {
	meta:
		tool = "P"
		name = "SecureEXE"
		version = "3.0"
		pattern = "E9B8000000??????00??????00??????000000000000"
	strings:
		$1 = { E9 B8 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule securepe_1x {
	meta:
		tool = "P"
		name = "SecurePE"
		version = "1.x"
		pattern = "8B0424E8000000005D81ED4C2F40008985612F40008D9D652F400053C3000000008DB5BA2F40008BFEBB652F4000B9C6010000AD2BC3C1C00333C3AB4381FB8E2F40007505BB652F4000E2E789AD1A31400089AD5534400089AD683440008D85BA2F400050C3"
	strings:
		$1 = { 8B 04 24 E8 00 00 00 00 5D 81 ED 4C 2F 40 00 89 85 61 2F 40 00 8D 9D 65 2F 40 00 53 C3 00 00 00 00 8D B5 BA 2F 40 00 8B FE BB 65 2F 40 00 B9 C6 01 00 00 AD 2B C3 C1 C0 03 33 C3 AB 43 81 FB 8E 2F 40 00 75 05 BB 65 2F 40 00 E2 E7 89 AD 1A 31 40 00 89 AD 55 34 40 00 89 AD 68 34 40 00 8D 85 BA 2F 40 00 50 C3 }
	condition:
		$1 at pe.entry_point
}

rule securom_7 {
	meta:
		tool = "P"
		name = "Securom"
		version = "7"
		pattern = "B8????????8B????????0A????????????E8"
	strings:
		$1 = { B8 ?? ?? ?? ?? 8B ?? ?? ?? ?? 0A ?? ?? ?? ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule securom_7x {
	meta:
		tool = "P"
		name = "Securom"
		version = "7.x"
		pattern = "9C9C83EC??C74424??????????C74424??????????89??24????????????C14C24??18"
	strings:
		$1 = { 9C 9C 83 EC ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 ?? 24 ?? ?? ?? ?? ?? ?? C1 4C 24 ?? 18 }
	condition:
		$1 at pe.entry_point
}

rule sen_debug_protector {
	meta:
		tool = "P"
		name = "SEN Debug Protector???"
		pattern = "BB????????00??????????29????4EE8"
	strings:
		$1 = { BB ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 29 ?? ?? 4E E8 }
	condition:
		$1 at pe.entry_point
}

rule sexe_crypter_11 {
	meta:
		tool = "P"
		name = "Sexe Crypter"
		version = "1.1"
		pattern = "558BEC83C4EC53565733C08945ECB8D8390010E830FAFFFF33C05568D43A001064FF306489????????E43A0010A10057001050E8CCFAFFFF8BD853A10057001050E8FEFAFFFF8BF853A10057001050E8C8FAFFFF8BD853E8C8FAFFFF8BF085F674268BD74AB814570010E8ADF6FFFFB814570010E89BF6FFFF8BCF8BD6E8DAFAFFFF53E884FAFFFF8D4DECBAF83A0010A114570010E80AFBFFFF8B55ECB814570010E865F5FFFFB814570010E863F6FFFFE852FCFFFF33C05A595964891068DB3A00108D45ECE8EDF4FFFFC3E983EFFFFFEBF05F5E5BE8EDF3FFFF0053455454494E475300000000FFFFFFFF120000006B7574683736676262673637347638386779"
	strings:
		$1 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 D8 39 00 10 E8 30 FA FF FF 33 C0 55 68 D4 3A 00 10 64 FF 30 64 89 ?? ?? ?? ?? E4 3A 00 10 A1 00 57 00 10 50 E8 CC FA FF FF 8B D8 53 A1 00 57 00 10 50 E8 FE FA FF FF 8B F8 53 A1 00 57 00 10 50 E8 C8 FA FF FF 8B D8 53 E8 C8 FA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 14 57 00 10 E8 AD F6 FF FF B8 14 57 00 10 E8 9B F6 FF FF 8B CF 8B D6 E8 DA FA FF FF 53 E8 84 FA FF FF 8D 4D EC BA F8 3A 00 10 A1 14 57 00 10 E8 0A FB FF FF 8B 55 EC B8 14 57 00 10 E8 65 F5 FF FF B8 14 57 00 10 E8 63 F6 FF FF E8 52 FC FF FF 33 C0 5A 59 59 64 89 10 68 DB 3A 00 10 8D 45 EC E8 ED F4 FF FF C3 E9 83 EF FF FF EB F0 5F 5E 5B E8 ED F3 FF FF 00 53 45 54 54 49 4E 47 53 00 00 00 00 FF FF FF FF 12 00 00 00 6B 75 74 68 37 36 67 62 62 67 36 37 34 76 38 38 67 79 }
	condition:
		$1 at pe.entry_point
}

rule shegerd_dongle_478 {
	meta:
		tool = "P"
		name = "Shegerd Dongle"
		version = "4.78"
		pattern = "E832000000B8????????8B18C1CB0589DA368B4C240C"
	strings:
		$1 = { E8 32 00 00 00 B8 ?? ?? ?? ?? 8B 18 C1 CB 05 89 DA 36 8B 4C 24 0C }
	condition:
		$1 at pe.entry_point
}

rule shellmodify_01 {
	meta:
		tool = "P"
		name = "ShellModify"
		version = "0.1"
		pattern = "558BEC6AFF6898664100683C3D410064A100000000"
	strings:
		$1 = { 55 8B EC 6A FF 68 98 66 41 00 68 3C 3D 41 00 64 A1 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule shrink_wrap_14 {
	meta:
		tool = "P"
		name = "Shrink Wrap"
		version = "1.4"
		pattern = "58608BE85533F6684801????E84901????EB"
	strings:
		$1 = { 58 60 8B E8 55 33 F6 68 48 01 ?? ?? E8 49 01 ?? ?? EB }
	condition:
		$1 at pe.entry_point
}

rule shrinker_uv_01 {
	meta:
		tool = "P"
		name = "Shrinker"
		pattern = "833D????????00558BEC565775656800010000E8??????0083C4048B7508A3????????85F6741D68FF0000005056FF15????????85C0740CC705"
	strings:
		$1 = { 83 3D ?? ?? ?? ?? 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 ?? ?? ?? 00 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 1D 68 FF 00 00 00 50 56 FF 15 ?? ?? ?? ?? 85 C0 74 0C C7 05 }
	condition:
		$1 at pe.entry_point
}

rule shrinker_uv_02 {
	meta:
		tool = "P"
		name = "Shrinker"
		pattern = "833D????????00558BEC5657756B6800010000E8??????0083C4048B7508A3????????85F67423837D0C03771D68FF0000005056FF15????????85C0740CC705"
	strings:
		$1 = { 83 3D ?? ?? ?? ?? 00 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? ?? ?? 00 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF 00 00 00 50 56 FF 15 ?? ?? ?? ?? 85 C0 74 0C C7 05 }
	condition:
		$1 at pe.entry_point
}

rule shrinker_32_01 {
	meta:
		tool = "P"
		name = "Shrinker"
		version = "3.2"
		pattern = "558BEC565775656800010000E8F1E6FFFF83C404"
	strings:
		$1 = { 55 8B EC 56 57 75 65 68 00 01 00 00 E8 F1 E6 FF FF 83 C4 04 }
	condition:
		$1 at pe.entry_point
}

rule shrinker_32_02 {
	meta:
		tool = "P"
		name = "Shrinker"
		version = "3.2"
		pattern = "833D??????????558BEC56577565680001????E8??E6FFFF83C4048B7508A3????????85F6741D68FF"
	strings:
		$1 = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 00 01 ?? ?? E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 1D 68 FF }
	condition:
		$1 at pe.entry_point
}

rule shrinker_33_01 {
	meta:
		tool = "P"
		name = "Shrinker"
		version = "3.3"
		pattern = "0000558BEC565775656800010000E8"
	strings:
		$1 = { 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }
	condition:
		$1 at pe.entry_point
}

rule shrinker_33_02 {
	meta:
		tool = "P"
		name = "Shrinker"
		version = "3.3"
		pattern = "833D??????0000558BEC565775656800010000E8"
	strings:
		$1 = { 83 3D ?? ?? ?? 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }
	condition:
		$1 at pe.entry_point
}

rule shrinker_34_01 {
	meta:
		tool = "P"
		name = "Shrinker"
		version = "3.4"
		pattern = "558BEC5657756B6800010000E8110B000083C404"
	strings:
		$1 = { 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 11 0B 00 00 83 C4 04 }
	condition:
		$1 at pe.entry_point
}

rule shrinker_34_02 {
	meta:
		tool = "P"
		name = "Shrinker"
		version = "3.4"
		pattern = "833DB4????????558BEC5657756B6800010000E8??0B000083C4048B7508A3B4??????85F67423837D0C03771D68FF"
	strings:
		$1 = { 83 3D B4 ?? ?? ?? ?? 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? 0B 00 00 83 C4 04 8B 75 08 A3 B4 ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF }
	condition:
		$1 at pe.entry_point
}

rule shrinker_34_03 {
	meta:
		tool = "P"
		name = "Shrinker"
		version = "3.4"
		pattern = "BB????BA????81C30700B840B4B104D3E803C38CD9498EC126030E03002B"
	strings:
		$1 = { BB ?? ?? BA ?? ?? 81 C3 07 00 B8 40 B4 B1 04 D3 E8 03 C3 8C D9 49 8E C1 26 03 0E 03 00 2B }
	condition:
		$1 at pe.entry_point
}

rule silicon_realms_install_stub_uv {
	meta:
		tool = "P"
		name = "Silicon Realms Install Stub"
		pattern = "558BEC6AFF68??92400068????400064A100000000506489250000000083EC585356578965E8FF15????400033D28AD48915????40008BC881E1FF000000890D????4000C1E10803CA890D????4000C1E810A3????400033F656E8????00005985C075086A1CE8B0000000598975FCE8????0000FF15??914000A3????4000E8????0000A3????4000E8????0000E8????0000E8????FFFF8975D08D45A450FF15??914000E8"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? 92 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D ?? ?? 40 00 C1 E1 08 03 CA 89 0D ?? ?? 40 00 C1 E8 10 A3 ?? ?? 40 00 33 F6 56 E8 ?? ?? 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 ?? ?? 00 00 FF 15 ?? 91 40 00 A3 ?? ?? 40 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 ?? ?? FF FF 89 75 D0 8D 45 A4 50 FF 15 ?? 91 40 00 E8 }
	condition:
		$1 at pe.entry_point
}

rule simbioz_uv {
	meta:
		tool = "P"
		name = "SimbiOZ"
		pattern = "5060E8000000005D81ED0710400068800B00008D851F10400050E8840B0000"
	strings:
		$1 = { 50 60 E8 00 00 00 00 5D 81 ED 07 10 40 00 68 80 0B 00 00 8D 85 1F 10 40 00 50 E8 84 0B 00 00 }
	condition:
		$1 at pe.entry_point
}

rule simbioz_13_2xx {
	meta:
		tool = "P"
		name = "SimbiOZ"
		version = "1.3 - 2.xx"
		pattern = "57578D7C240450B800??????AB585FC3"
	strings:
		$1 = { 57 57 8D 7C 24 04 50 B8 00 ?? ?? ?? AB 58 5F C3 }
	condition:
		$1 at pe.entry_point
}

rule simbioz_21_poly {
	meta:
		tool = "P"
		name = "SimbiOZ"
		version = "2.1 Poly"
		pattern = "55508BC483C004C700????????58C390"
	strings:
		$1 = { 55 50 8B C4 83 C0 04 C7 00 ?? ?? ?? ?? 58 C3 90 }
	condition:
		$1 at pe.entry_point
}

rule simbioz_polycryptor {
	meta:
		tool = "P"
		name = "SimbiOZ"
		version = "PolyCryptor"
		pattern = "5560E8000000005D81ED????????8D85????????68????????50E8"
	strings:
		$1 = { 55 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 }
	condition:
		$1 at pe.entry_point
}

rule simple_upx_cryptor_3042005 {
	meta:
		tool = "P"
		name = "Simple UPX Cryptor"
		version = "30.4.2005"
		pattern = "60B8????????B9????????????????E2FA6168????????C3"
	strings:
		$1 = { 60 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? ?? ?? ?? ?? E2 FA 61 68 ?? ?? ?? ?? C3 }
	condition:
		$1 at pe.entry_point
}

rule simplepack_10x {
	meta:
		tool = "P"
		name = "SimplePack"
		version = "1.0x"
		pattern = "60E8000000005B8D5BFA6A00FF93????000089C58B7D3C8D743D008DBEF80000008B868800000009C0"
	strings:
		$1 = { 60 E8 00 00 00 00 5B 8D 5B FA 6A 00 FF 93 ?? ?? 00 00 89 C5 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 8B 86 88 00 00 00 09 C0 }
	condition:
		$1 at pe.entry_point
}

rule simplepack_11x_2xx {
	meta:
		tool = "P"
		name = "SimplePack"
		version = "1.1x - 1.2x"
		pattern = "60E8000000005B8D5BFABD????????8B7D3C8D743D008DBEF80000000FB776064E8B471009C0"
	strings:
		$1 = { 60 E8 00 00 00 00 5B 8D 5B FA BD ?? ?? ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 }
	condition:
		$1 at pe.entry_point
}

rule simplepack_1x {
	meta:
		tool = "P"
		name = "SimplePack"
		version = "1.x"
		pattern = "4D5A90EB010052E9??010000504500004C010200"
	strings:
		$1 = { 4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00 }
	condition:
		$1 at pe.entry_point
}

rule skd_undetectabler_20_pro {
	meta:
		tool = "P"
		name = "SkD Undetectabler"
		version = "2.0 Pro"
		pattern = "558BEC83C4F0B8FC260010E8ECF3FFFF6A0FE815F5FFFFE864FDFFFFE8BBEDFFFF8D40"
	strings:
		$1 = { 55 8B EC 83 C4 F0 B8 FC 26 00 10 E8 EC F3 FF FF 6A 0F E8 15 F5 FF FF E8 64 FD FF FF E8 BB ED FF FF 8D 40 }
	condition:
		$1 at pe.entry_point
}

rule skd_undetectabler_30 {
	meta:
		tool = "P"
		name = "SkD Undetectabler"
		version = "3.0"
		pattern = "558BEC81EC1002000068000200008D85F8FDFFFF506A00FF153810000150FF153C1000018D8DF8FDFFFF51E84FFBFFFF83C4048B15??16000152A1??16000150E850FFFFFF83C408A3??160001C785F4FDFFFF00000000EB0F8B8DF4FDFFFF83C101898DF4FDFFFF8B95F4FDFFFF3B15??160001731C8B85F4FDFFFF8B0D??1600018D54010781FA741000017502EB02EBC78B85F4FDFFFF50E8??00000083C4048985F0FDFFFF8B8DF0FDFFFF894DFCC745F800000000EB098B55F883C2018955F88B45F83B85F4FDFFFF73158B4DFC034DF88B15??1600010355F88A028801EBD7833D??1600010074"
	strings:
		$1 = { 55 8B EC 81 EC 10 02 00 00 68 00 02 00 00 8D 85 F8 FD FF FF 50 6A 00 FF 15 38 10 00 01 50 FF 15 3C 10 00 01 8D 8D F8 FD FF FF 51 E8 4F FB FF FF 83 C4 04 8B 15 ?? 16 00 01 52 A1 ?? 16 00 01 50 E8 50 FF FF FF 83 C4 08 A3 ?? 16 00 01 C7 85 F4 FD FF FF 00 00 00 00 EB 0F 8B 8D F4 FD FF FF 83 C1 01 89 8D F4 FD FF FF 8B 95 F4 FD FF FF 3B 15 ?? 16 00 01 73 1C 8B 85 F4 FD FF FF 8B 0D ?? 16 00 01 8D 54 01 07 81 FA 74 10 00 01 75 02 EB 02 EB C7 8B 85 F4 FD FF FF 50 E8 ?? 00 00 00 83 C4 04 89 85 F0 FD FF FF 8B 8D F0 FD FF FF 89 4D FC C7 45 F8 00 00 00 00 EB 09 8B 55 F8 83 C2 01 89 55 F8 8B 45 F8 3B 85 F4 FD FF FF 73 15 8B 4D FC 03 4D F8 8B 15 ?? 16 00 01 03 55 F8 8A 02 88 01 EB D7 83 3D ?? 16 00 01 00 74 }
	condition:
		$1 at pe.entry_point
}

rule slvcodeprotector_060_01 {
	meta:
		tool = "P"
		name = "SLVc0deProtector"
		version = "0.60"
		pattern = "????????????????????????????????????????????????????????????????????????????????????????????????E84900000069E84900000095E84F00000068E81F00000049E8E9FFFFFF67E81F00000093E83100000078E8DDFFFFFF38E8E3FFFFFF66E80D00000004E8E3FFFFFF70E8CBFFFFFF69E8DDFFFFFF58E8DDFFFFFF69E8E3FFFFFF79E8BFFFFFFF6983C440E8000000005D81ED971140008DB5EF114000B9FE2D00008BFEACF8????????????90"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 97 11 40 00 8D B5 EF 11 40 00 B9 FE 2D 00 00 8B FE AC F8 ?? ?? ?? ?? ?? ?? 90 }
	condition:
		$1 at pe.entry_point
}

rule slvcodeprotector_060_02 {
	meta:
		tool = "P"
		name = "SLVc0deProtector"
		version = "0.60"
		pattern = "EB02FA04E84900000069E84900000095E84F00000068E81F00000049E8E9FFFFFF67E81F00000093E83100000078E8DD"
	strings:
		$1 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD }
	condition:
		$1 at pe.entry_point
}

rule slvcodeprotector_061 {
	meta:
		tool = "P"
		name = "SLVc0deProtector"
		version = "0.61"
		pattern = "????????????????????????????????????????????????????????????????????????????????????????????????EB02FA04E84900000069E84900000095E84F00000068E81F00000049E8E9FFFFFF67E81F00"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 }
	condition:
		$1 at pe.entry_point
}

rule slvcodeprotector_11_01 {
	meta:
		tool = "P"
		name = "SLVc0deProtector"
		version = "1.1"
		pattern = "E80000000058C600EBC6400108FFE0E94C"
	strings:
		$1 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C }
	condition:
		$1 at pe.entry_point
}

rule slvcodeprotector_11_02 {
	meta:
		tool = "P"
		name = "SLVc0deProtector"
		version = "1.1"
		pattern = "E801000000A05DEB016981ED5F1A40008D85921A4000F38D95831A40008BC08BD22BC283E805894201E8FBFFFFFF6983C408E80600000069E8F2FFFFFFF3B905000000518DB5BF1A40008BFEB958150000AC32C1F6D0EB0100D0C0FEC802C1AAE2EF59E2DEB7FEABE124C80C887AE1B16AF795831BA87FF8A8B01A8B0891476C5A886C653985DBCB543DB924CF4CAEC663742C63F0C8180B976B7963A8ABB878A9302F2BDA18AC"
	strings:
		$1 = { E8 01 00 00 00 A0 5D EB 01 69 81 ED 5F 1A 40 00 8D 85 92 1A 40 00 F3 8D 95 83 1A 40 00 8B C0 8B D2 2B C2 83 E8 05 89 42 01 E8 FB FF FF FF 69 83 C4 08 E8 06 00 00 00 69 E8 F2 FF FF FF F3 B9 05 00 00 00 51 8D B5 BF 1A 40 00 8B FE B9 58 15 00 00 AC 32 C1 F6 D0 EB 01 00 D0 C0 FE C8 02 C1 AA E2 EF 59 E2 DE B7 FE AB E1 24 C8 0C 88 7A E1 B1 6A F7 95 83 1B A8 7F F8 A8 B0 1A 8B 08 91 47 6C 5A 88 6C 65 39 85 DB CB 54 3D B9 24 CF 4C AE C6 63 74 2C 63 F0 C8 18 0B 97 6B 79 63 A8 AB B8 78 A9 30 2F 2B DA 18 AC }
	condition:
		$1 at pe.entry_point
}

rule smarte_uv {
	meta:
		tool = "P"
		name = "SmartE"
		pattern = "EB1503000000??0000000000000000000000680000000055E8000000005D81ED1D0000008BC555609C2B858F070000898583070000FF74242CE8BB0100000F822F060000E88E040000490F882306"
	strings:
		$1 = { EB 15 03 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 8F 07 00 00 89 85 83 07 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 2F 06 00 00 E8 8E 04 00 00 49 0F 88 23 06 }
	condition:
		$1 at pe.entry_point
}

rule smartloader {
	meta:
		tool = "P"
		name = "SmartLoader"
		pattern = "555657E8000000005D81EDE25F0010EB05E9670100008B85E561001085C0740A8B4424108985D96100108B85D961001003403C05800000008B08038DD9610010"
	strings:
		$1 = { 55 56 57 E8 00 00 00 00 5D 81 ED E2 5F 00 10 EB 05 E9 67 01 00 00 8B 85 E5 61 00 10 85 C0 74 0A 8B 44 24 10 89 85 D9 61 00 10 8B 85 D9 61 00 10 03 40 3C 05 80 00 00 00 8B 08 03 8D D9 61 00 10 }
	condition:
		$1 at pe.entry_point
}

rule smokescrypt_12 {
	meta:
		tool = "P"
		name = "SmokesCrypt"
		version = "1.2"
		pattern = "60B8????????B8????????8A140880F2??8814084183F9??75F1"
	strings:
		$1 = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }
	condition:
		$1 at pe.entry_point
}

rule soft_defender_10_11 {
	meta:
		tool = "P"
		name = "Soft Defender"
		version = "1.0 - 1.1"
		pattern = "74077505193267E8E8741F751DE8683944CD??599C50740A7508E859C204??558BECE8F4FFFFFF565753780F790DE8349947493433EF313452472368A2AF470159E8????????5805BA01????03C874BE75BCE8"
	strings:
		$1 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD ?? 59 9C 50 74 0A 75 08 E8 59 C2 04 ?? 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 ?? ?? ?? ?? 58 05 BA 01 ?? ?? 03 C8 74 BE 75 BC E8 }
	condition:
		$1 at pe.entry_point
}

rule soft_defender_12 {
	meta:
		tool = "P"
		name = "Soft Defender"
		version = "1.12"
		pattern = "74077505193267E8E8741F751DE8683944CD00599C50740A7508E859C20400558BECE8F4FFFFFF565753780F790DE8349947493433EF313452472368A2AF470159E801000000FF5805BE01000003C874BD75BBE8"
	strings:
		$1 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 BE 01 00 00 03 C8 74 BD 75 BB E8 }
	condition:
		$1 at pe.entry_point
}

rule soft_defender_11x {
	meta:
		tool = "P"
		name = "Soft Defender"
		version = "1.1x"
		pattern = "74077505??????????741F751D??68??????00599C50740A7508??59C20400??????E8F4FFFFFF??????780F790D"
	strings:
		$1 = { 74 07 75 05 ?? ?? ?? ?? ?? 74 1F 75 1D ?? 68 ?? ?? ?? 00 59 9C 50 74 0A 75 08 ?? 59 C2 04 00 ?? ?? ?? E8 F4 FF FF FF ?? ?? ?? 78 0F 79 0D }
	condition:
		$1 at pe.entry_point
}

rule soft_defender_1x {
	meta:
		tool = "P"
		name = "Soft Defender"
		version = "1.x"
		pattern = "74077505193267E8E8741F751DE8683944CD00599C50740A7508E859C20400558BECE8F4FFFFFF565753780F790DE8349947493433EF313452472368A2AF470159E801000000FF5805E601000003C874BD75BBE800"
	strings:
		$1 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 E6 01 00 00 03 C8 74 BD 75 BB E8 00 }
	condition:
		$1 at pe.entry_point
}

rule softcomp_1x {
	meta:
		tool = "P"
		name = "SoftComp"
		version = "1.x"
		pattern = "E800000000812C243A1041005DE800000000812C24310100008B852A0F41002904248B042489852A0F4100588B852A0F4100"
	strings:
		$1 = { E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 8B 04 24 89 85 2A 0F 41 00 58 8B 85 2A 0F 41 00 }
	condition:
		$1 at pe.entry_point
}

rule softprotect_uv_01 {
	meta:
		tool = "P"
		name = "SoftProtect"
		pattern = "E8????????8D??????????C70000000000E8????????E8????????8D??????????50E8????????83??????????01"
	strings:
		$1 = { E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? C7 00 00 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? 01 }
	condition:
		$1 at pe.entry_point
}

rule softprotect_uv_02 {
	meta:
		tool = "P"
		name = "SoftProtect"
		pattern = "EB01E360E803??????D2EB0B58EB014840EB0135FFE0E76160E803??????83EB0EEB010C58EB013540EB0136FFE00B61EB01839CEB01D5EB08359DEB0189EB030BEBF7E8????????58E8????????5983010180395C75F233C4740C23C40BC4C60159C60159EBE290E84414????8D85CF13????C7??????????E8610E????E82E14????8D85E401????50E8E215????83BD2301????017507E8210D????EB098D85CF13????8308"
	strings:
		$1 = { EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 60 E8 03 ?? ?? ?? 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 EB 01 83 9C EB 01 D5 EB 08 35 9D EB 01 89 EB 03 0B EB F7 E8 ?? ?? ?? ?? 58 E8 ?? ?? ?? ?? 59 83 01 01 80 39 5C 75 F2 33 C4 74 0C 23 C4 0B C4 C6 01 59 C6 01 59 EB E2 90 E8 44 14 ?? ?? 8D 85 CF 13 ?? ?? C7 ?? ?? ?? ?? ?? E8 61 0E ?? ?? E8 2E 14 ?? ?? 8D 85 E4 01 ?? ?? 50 E8 E2 15 ?? ?? 83 BD 23 01 ?? ?? 01 75 07 E8 21 0D ?? ?? EB 09 8D 85 CF 13 ?? ?? 83 08 }
	condition:
		$1 at pe.entry_point
}

rule softsentry_211 {
	meta:
		tool = "P"
		name = "SoftSentry"
		version = "2.11"
		pattern = "558BEC83EC??535657E950"
	strings:
		$1 = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }
	condition:
		$1 at pe.entry_point
}

rule softsentry_300 {
	meta:
		tool = "P"
		name = "SoftSentry"
		version = "3.00"
		pattern = "558BEC83EC??535657E9B006"
	strings:
		$1 = { 55 8B EC 83 EC ?? 53 56 57 E9 B0 06 }
	condition:
		$1 at pe.entry_point
}

rule software_compress_12 {
	meta:
		tool = "P"
		name = "Software Compress"
		version = "1.2"
		pattern = "E9BE000000608B7424248B7C2428FCB28033DBA4B302E86D0000"
	strings:
		$1 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 }
	condition:
		$1 at pe.entry_point
}

rule software_compress_14_lite {
	meta:
		tool = "P"
		name = "Software Compress"
		version = "1.4 LITE"
		pattern = "E800000000812C24AA1A41005DE800000000832C246E8B855D1A41002904248B042489855D1A4100588B855D1A41008B503C03D08B928000000003D08B4A58898D491A41008B4A5C898D4D1A41008B4A60898D551A"
	strings:
		$1 = { E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00 29 04 24 8B 04 24 89 85 5D 1A 41 00 58 8B 85 5D 1A 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 03 D0 8B 4A 58 89 8D 49 1A 41 00 8B 4A 5C 89 8D 4D 1A 41 00 8B 4A 60 89 8D 55 1A }
	condition:
		$1 at pe.entry_point
}

rule softwrap_uv {
	meta:
		tool = "P"
		name = "SoftWrap"
		pattern = "525351565755E8????????5D81ED36??????E8??01????60BA????????E8????????5F"
	strings:
		$1 = { 52 53 51 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 36 ?? ?? ?? E8 ?? 01 ?? ?? 60 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F }
	condition:
		$1 at pe.entry_point
}

rule solidshield_protector_1x_01 {
	meta:
		tool = "P"
		name = "Solidshield Protector"
		version = "1.x"
		pattern = "68????????FF35????????C3006089000A00000046330000000000000000"
	strings:
		$1 = { 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 00 60 89 00 0A 00 00 00 46 33 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule solidshield_protector_1x_02 {
	meta:
		tool = "P"
		name = "Solidshield Protector"
		version = "1.x"
		pattern = "8B44240848750AFF742404E8????????5933C040C20C00558BEC568B750885F6752868????????BE????????56FF15????????59596A??68????????566A??FF??????????E98000000083FE0175075E5DE9D2F6FFFF83FE02578B7D107553FF7524FF7520FF751CFF751868????????68????????FF15????????BE????????5657E8????????83C4203C0175048BC6EB6A57FF750CE8????????57E8????????5657E8????????83C4143C0174DF6A035E83FE03751B57E8????????C70424????????E8????????596A00FF15????????83FE04750DFF752CFF7528E8????????595983FE057511FF7530FF752CFF7528E8????????83C40C33C05F5E5DC3"
	strings:
		$1 = { 8B 44 24 08 48 75 0A FF 74 24 04 E8 ?? ?? ?? ?? 59 33 C0 40 C2 0C 00 55 8B EC 56 8B 75 08 85 F6 75 28 68 ?? ?? ?? ?? BE ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 59 59 6A ?? 68 ?? ?? ?? ?? 56 6A ?? FF ?? ?? ?? ?? ?? E9 80 00 00 00 83 FE 01 75 07 5E 5D E9 D2 F6 FF FF 83 FE 02 57 8B 7D 10 75 53 FF 75 24 FF 75 20 FF 75 1C FF 75 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? BE ?? ?? ?? ?? 56 57 E8 ?? ?? ?? ?? 83 C4 20 3C 01 75 04 8B C6 EB 6A 57 FF 75 0C E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 56 57 E8 ?? ?? ?? ?? 83 C4 14 3C 01 74 DF 6A 03 5E 83 FE 03 75 1B 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 6A 00 FF 15 ?? ?? ?? ?? 83 FE 04 75 0D FF 75 2C FF 75 28 E8 ?? ?? ?? ?? 59 59 83 FE 05 75 11 FF 75 30 FF 75 2C FF 75 28 E8 ?? ?? ?? ?? 83 C4 0C 33 C0 5F 5E 5D C3 }
	condition:
		$1 at pe.entry_point
}

rule spec_b2 {
	meta:
		tool = "P"
		name = "SPEC"
		version = "b2"
		pattern = "55575153E8????????5D8BC581ED????????2B85????????83E8098985????????0FB6"
	strings:
		$1 = { 55 57 51 53 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 09 89 85 ?? ?? ?? ?? 0F B6 }
	condition:
		$1 at pe.entry_point
}

rule spec_b3 {
	meta:
		tool = "P"
		name = "SPEC"
		version = "b3"
		pattern = "5B535045435DE8????????5D8BC581ED412440??2B85892640??83E80B89858D2640??0FB6B5912640??8BFD"
	strings:
		$1 = { 5B 53 50 45 43 5D E8 ?? ?? ?? ?? 5D 8B C5 81 ED 41 24 40 ?? 2B 85 89 26 40 ?? 83 E8 0B 89 85 8D 26 40 ?? 0F B6 B5 91 26 40 ?? 8B FD }
	condition:
		$1 at pe.entry_point
}

rule special_exe_password_protector_101 {
	meta:
		tool = "P"
		name = "Special EXE Pasword Protector"
		version = "1.01"
		pattern = "60E8000000005D81ED0600000089AD8C0100008BC52B85FE75000089853E"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E }
	condition:
		$1 at pe.entry_point
}

rule splash_bitmap_100_01 {
	meta:
		tool = "P"
		name = "Splash Bitmap"
		version = "1.00"
		extra = "with unpack code"
		pattern = "E800000000608B6C24205581ED????????8DBD????????8D8D????????29F931C0FCF3AA8B042448662500F06681384D5A75F48B483C813C015045000075E88985????????6A40"
	strings:
		$1 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 6A 40 }
	condition:
		$1 at pe.entry_point
}

rule splash_bitmap_100_02 {
	meta:
		tool = "P"
		name = "Splash Bitmap"
		version = "1.00"
		pattern = "E800000000608B6C24205581ED????????8DBD????????8D8D????????29F931C0FCF3AA8B042448662500F06681384D5A75F48B483C813C015045000075E88985????????8DBD????????6A00"
	strings:
		$1 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 6A 00 }
	condition:
		$1 at pe.entry_point
}

rule splasher_10_30 {
	meta:
		tool = "P"
		name = "Splasher"
		version = "1.0 - 3.0"
		pattern = "9C608B442424E8????????5D81ED????????50E8ED02????8CC00F84"
	strings:
		$1 = { 9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84 }
	condition:
		$1 at pe.entry_point
}

rule splayer_008 {
	meta:
		tool = "P"
		name = "SPLayer"
		version = "0.08"
		pattern = "8D4000B9????????6A??58C00C????48????6613F0913BD9????????????????00000000"
	strings:
		$1 = { 8D 40 00 B9 ?? ?? ?? ?? 6A ?? 58 C0 0C ?? ?? 48 ?? ?? 66 13 F0 91 3B D9 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule splice_11 {
	meta:
		tool = "P"
		name = "Splice"
		version = "1.1"
		pattern = "68001A4000E8EEFFFFFF000000000000300000004000000000000000????????????????????????????????00000000000001000000????????????50726F6A6563743100??????????????0000000006000000AC29400007000000BC2840000700000074284000070000002C2840000700000008234000010000003821400000000000FFFFFFFFFFFFFFFF000000008C21400008??400001000000AC194000000000000000000000000000AC1940004F00430050000000E7AF582F9A4C174DB7A9CA3E576FF776"
	strings:
		$1 = { 68 00 1A 40 00 E8 EE FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 ?? ?? ?? ?? ?? ?? 50 72 6F 6A 65 63 74 31 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 06 00 00 00 AC 29 40 00 07 00 00 00 BC 28 40 00 07 00 00 00 74 28 40 00 07 00 00 00 2C 28 40 00 07 00 00 00 08 23 40 00 01 00 00 00 38 21 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 8C 21 40 00 08 ?? 40 00 01 00 00 00 AC 19 40 00 00 00 00 00 00 00 00 00 00 00 00 00 AC 19 40 00 4F 00 43 00 50 00 00 00 E7 AF 58 2F 9A 4C 17 4D B7 A9 CA 3E 57 6F F7 76 }
	condition:
		$1 at pe.entry_point
}

rule st_protector_15 {
	meta:
		tool = "P"
		name = "ST Protector"
		version = "1.5"
		pattern = "000000004B65526E456C33322E644C6C000047657450726F634164647265737300004C6F61644C696272617279410000"
	strings:
		$1 = { 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 }
	condition:
		$1 at pe.entry_point
}

rule stabstr_uv {
	meta:
		tool = "P"
		name = "STABSTR"
		pattern = "5589E583EC14538B4D088B450C8B5510BB0100000083F801740E724483F802746F83F8037472EB7E890D????????C705????????010000008915????????83C4F8"
	strings:
		$1 = { 55 89 E5 83 EC 14 53 8B 4D 08 8B 45 0C 8B 55 10 BB 01 00 00 00 83 F8 01 74 0E 72 44 83 F8 02 74 6F 83 F8 03 74 72 EB 7E 89 0D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 89 15 ?? ?? ?? ?? 83 C4 F8 }
	condition:
		$1 at pe.entry_point
}

rule starforce_11 {
	meta:
		tool = "P"
		name = "StarForce"
		version = "1.1"
		extra = "ProActive"
		pattern = "68????????FF25????57"
	strings:
		$1 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 57 }
	condition:
		$1 at pe.entry_point
}

rule starforce_30 {
	meta:
		tool = "P"
		name = "StarForce"
		version = "3.0"
		pattern = "68????????FF25????63"
	strings:
		$1 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 63 }
	condition:
		$1 at pe.entry_point
}

rule starforce_3x {
	meta:
		tool = "P"
		name = "StarForce"
		version = "3.x"
		pattern = "E8????????000000000000"
	strings:
		$1 = { E8 ?? ?? ?? ?? 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule starforce_1x_5x {
	meta:
		tool = "P"
		name = "StarForce"
		version = "1.x - 5.x"
		pattern = "68????????FF25????????0000000000"
	strings:
		$1 = { 68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule starforce_protection_driver {
	meta:
		tool = "P"
		name = "StarForce"
		extra = "Protection Driver"
		pattern = "5768??0D01006800????00E850??FFFF68??????0068??????0068??????0068??????0068??????00"
	strings:
		$1 = { 57 68 ?? 0D 01 00 68 00 ?? ?? 00 E8 50 ?? FF FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule stealth_uv_01 {
	meta:
		tool = "P"
		name = "Ste@lth"
		pattern = "??????????B8??????0050C3"
	strings:
		$1 = { ?? ?? ?? ?? ?? B8 ?? ?? ?? 00 50 C3 }
	condition:
		$1 at pe.entry_point
}

rule stealth_uv_02 {
	meta:
		tool = "P"
		name = "Ste@lth"
		pattern = "??????????B9??????0051C3"
	strings:
		$1 = { ?? ?? ?? ?? ?? B9 ?? ?? ?? 00 51 C3 }
	condition:
		$1 at pe.entry_point
}

rule stealth_uv_03 {
	meta:
		tool = "P"
		name = "Ste@lth"
		pattern = "??????????BB??????0053C3"
	strings:
		$1 = { ?? ?? ?? ?? ?? BB ?? ?? ?? 00 53 C3 }
	condition:
		$1 at pe.entry_point
}

rule stealth_101 {
	meta:
		tool = "P"
		name = "Ste@lth"
		version = "1.01"
		pattern = "??????????BA??????00"
	strings:
		$1 = { ?? ?? ?? ?? ?? BA ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule stealth_pe_11 {
	meta:
		tool = "P"
		name = "Stealth PE"
		version = "1.1"
		pattern = "BA??????00FFE2BA??????00B8????????890283C203B8????????890283C2FDFFE2"
	strings:
		$1 = { BA ?? ?? ?? 00 FF E2 BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 03 B8 ?? ?? ?? ?? 89 02 83 C2 FD FF E2 }
	condition:
		$1 at pe.entry_point
}

rule stones_pe_encryptor_10_113 {
	meta:
		tool = "P"
		name = "Stone's PE Encryptor"
		version = "1.0 - 1.13"
		pattern = "555756525153E8????????5D8BD581"
	strings:
		$1 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 }
	condition:
		$1 at pe.entry_point
}

rule stones_pe_encryptor_20 {
	meta:
		tool = "P"
		name = "Stone's PE Encryptor"
		version = "2.0"
		pattern = "535152565755E8????????5D81ED423040??FF95323540??B8373040??03C52B851B3440??8985273440??83"
	strings:
		$1 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83 }
	condition:
		$1 at pe.entry_point
}

rule stud_rc4_10 {
	meta:
		tool = "P"
		name = "STUD RC4"
		version = "1.0 Jamie Edition"
		pattern = "682C114000E8F0FFFFFF00000000000030000000380000000000000037BB71ECA4E1984C9BFE8F0FFA6A07F6000000000000010000002020466F7220737475640020546F0000000006000000CC1A400007000000D4184000070000007C184000070000002C18400007000000E017400056423521F01F2A000000000000000000000000007E000000000000000000000000000A000904000000000000E8134000F413400000F0300000FFFFFF080000000100000000000000E90000000411400004114000C8104000780000007C00000081000000820000000000000000000000000000000000000061616100537475640000737475640000010001003016400000000000FFFFFFFFFFFFFFFF00000000B41640001030400007000000241240000E002000000000001C9E2100EC1140005C104000E41A40002C3440006817400058174000781740008C1740008C1040006210400092104000F81A400024194000981040009E104000770418FF041CFF0500002401000D1400781C400048214000"
	strings:
		$1 = { 68 2C 11 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30 00 00 00 38 00 00 00 00 00 00 00 37 BB 71 EC A4 E1 98 4C 9B FE 8F 0F FA 6A 07 F6 00 00 00 00 00 00 01 00 00 00 20 20 46 6F 72 20 73 74 75 64 00 20 54 6F 00 00 00 00 06 00 00 00 CC 1A 40 00 07 00 00 00 D4 18 40 00 07 00 00 00 7C 18 40 00 07 00 00 00 2C 18 40 00 07 00 00 00 E0 17 40 00 56 42 35 21 F0 1F 2A 00 00 00 00 00 00 00 00 00 00 00 00 00 7E 00 00 00 00 00 00 00 00 00 00 00 00 00 0A 00 09 04 00 00 00 00 00 00 E8 13 40 00 F4 13 40 00 00 F0 30 00 00 FF FF FF 08 00 00 00 01 00 00 00 00 00 00 00 E9 00 00 00 04 11 40 00 04 11 40 00 C8 10 40 00 78 00 00 00 7C 00 00 00 81 00 00 00 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 61 61 61 00 53 74 75 64 00 00 73 74 75 64 00 00 01 00 01 00 30 16 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 B4 16 40 00 10 30 40 00 07 00 00 00 24 12 40 00 0E 00 20 00 00 00 00 00 1C 9E 21 00 EC 11 40 00 5C 10 40 00 E4 1A 40 00 2C 34 40 00 68 17 40 00 58 17 40 00 78 17 40 00 8C 17 40 00 8C 10 40 00 62 10 40 00 92 10 40 00 F8 1A 40 00 24 19 40 00 98 10 40 00 9E 10 40 00 77 04 18 FF 04 1C FF 05 00 00 24 01 00 0D 14 00 78 1C 40 00 48 21 40 00 }
	condition:
		$1 at pe.entry_point
}

rule superdat_uv {
	meta:
		tool = "P"
		name = "SuperDAT"
		pattern = "558BEC6AFF6840F3420068A4BF420064A100000000506489250000000083EC585356578965E8FF1508F2420033D28AD48915604243008BC881E1FF000000890D"
	strings:
		$1 = { 55 8B EC 6A FF 68 40 F3 42 00 68 A4 BF 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 08 F2 42 00 33 D2 8A D4 89 15 60 42 43 00 8B C8 81 E1 FF 00 00 00 89 0D }
	condition:
		$1 at pe.entry_point
}

rule svk_protector_1051 {
	meta:
		tool = "P"
		name = "SVK-Protector"
		version = "1.051"
		pattern = "60EB03C784E8EB03C7849AE8000000005D81ED10000000EB03C784E964A023000000EB"
	strings:
		$1 = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB }
	condition:
		$1 at pe.entry_point
}

rule svk_protector_11 {
	meta:
		tool = "P"
		name = "SVK-Protector"
		version = "1.11"
		pattern = "60E8????????5D81ED06??????64A023"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23 }
	condition:
		$1 at pe.entry_point
}

rule svk_protector_13x {
	meta:
		tool = "P"
		name = "SVK-Protector"
		version = "1.3x"
		pattern = "60E8000000005D81ED06000000EB05B8????420064A023"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? 42 00 64 A0 23 }
	condition:
		$1 at pe.entry_point
}

rule svk_protector_143 {
	meta:
		tool = "P"
		name = "SVK-Protector"
		version = "1.43"
		pattern = "784E884C0EB03C784E97567B9490000008DB5C502000056?"
	strings:
		$1 = { 78 4E 88 4C 0E B0 3C 78 4E 97 56 7B 94 90 00 00 08 DB 5C 50 20 00 05 6? }
	condition:
		$1 at pe.entry_point
}

rule svk_protector_uv {
	meta:
		tool = "P"
		name = "SVK-Protector"
		pattern = "60E8????????5D81ED06000000EB05B8????????64A023000000EB03C784E8????????C784E9"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? ?? ?? 64 A0 23 00 00 00 EB 03 C7 84 E8 ?? ?? ?? ?? C7 84 E9 }
	condition:
		$1 at pe.entry_point
}

rule symantec_file_uv_01 {
	meta:
		tool = "P"
		name = "SYMANTEC FILE"
		pattern = "EB08????????00000000??0B??????????05E8??00000052FF7424??FF7424??FF7424CCFF7424??E806000000??0890??05??C21000"
	strings:
		$1 = { EB 08 ?? ?? ?? ?? 00 00 00 00 ?? 0B ?? ?? ?? ?? ?? 05 E8 ?? 00 00 00 52 FF 74 24 ?? FF 74 24 ?? FF 74 24 CC FF 74 24 ?? E8 06 00 00 00 ?? 08 90 ?? 05 ?? C2 10 00 }
	condition:
		$1 in (pe.entry_point .. pe.entry_point + 4)
}

rule symantec_file_uv_02 {
	meta:
		tool = "P"
		name = "SYMANTEC FILE"
		pattern = "EB08????????000000006A17E80D0000006A30E8060000007A08907B0569C204004152780B51525A597905E80200000053FF7424F4FF742438FF74246C"
	strings:
		$1 = { EB 08 ?? ?? ?? ?? 00 00 00 00 6A 17 E8 0D 00 00 00 6A 30 E8 06 00 00 00 7A 08 90 7B 05 69 C2 04 00 41 52 78 0B 51 52 5A 59 79 05 E8 02 00 00 00 53 FF 74 24 F4 FF 74 24 38 FF 74 24 6C }
	condition:
		$1 in (pe.entry_point .. pe.entry_point + 4)
}

rule tpack_05c_m1 {
	meta:
		tool = "P"
		name = "T-PACK"
		version = "0.5c -m1"
		pattern = "68????FD60BE????BF????B9????F3A48BF7BF????FC46E98EFE"
	strings:
		$1 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 8E FE }
	condition:
		$1 at pe.entry_point
}

rule tpack_05c_m2 {
	meta:
		tool = "P"
		name = "T-PACK"
		version = "0.5c -m2"
		pattern = "68????FD60BE????BF????B9????F3A48BF7BF????FC46E9CEFD"
	strings:
		$1 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 CE FD }
	condition:
		$1 at pe.entry_point
}

rule taishanziangyu_locksoft_10_01 {
	meta:
		tool = "P"
		name = "TaiShanXiangYu LockSoft"
		version = "1.0"
		pattern = "E803000000EB01??BB55000000E803000000EB01??E88F000000E803000000EB01??E882000000E803000000EB01??E8B8000000E803000000EB01??E8AB000000E803000000EB01??83FB55E803000000EB01??752EE803000000EB01??C360E8000000005D81EDE30042008BD581C23201420052E801000000C3C3E803000000EB01??E80E000000E8D1FFFFFFC3E803000000EB01??33C064FF30648920CCC3E803000000EB01??33C064FF306489204BCCC3E803000000EB01??33DBB9????????81??????????8BD581??????????8D3A8BF733C0E803000000EB01??E817000000??????E9????????33C064FF3064892043CCC3"
	strings:
		$1 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED E3 00 42 00 8B D5 81 C2 32 01 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 8B D5 81 ?? ?? ?? ?? ?? 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 64 FF 30 64 89 20 43 CC C3 }
	condition:
		$1 at pe.entry_point
}

rule taishanziangyu_locksoft_10_02 {
	meta:
		tool = "P"
		name = "TaiShanXiangYu LockSoft"
		version = "1.0"
		pattern = "60E8000000005D81EDE30042008BD581C23201420052E801000000C3C3E803000000EB01??E80E000000E8D1FFFFFFC3E803000000EB01??33C064FF30648920CCC3E803000000EB01??33C064FF306489204BCCC3E803000000EB01??33DBB9AF28420081E9DD0142008BD581C2DD0142008D3A8BF733C0E803000000EB01??E817000000909090E97820000033C064FF3064892043CCC390EB01??AC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED E3 00 42 00 8B D5 81 C2 32 01 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 AF 28 42 00 81 E9 DD 01 42 00 8B D5 81 C2 DD 01 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 78 20 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 90 EB 01 ?? AC }
	condition:
		$1 at pe.entry_point
}

rule tarma_uv {
	meta:
		tool = "P"
		name = "TARMA"
		pattern = "54495A31"
	strings:
		$1 = { 54 49 5A 31 }
	condition:
		$1 at pe.entry_point
}

rule telock_041x {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.41x"
		pattern = "668BC08D2424EB01EB60EB01EB9CE8000000005E83C6508BFE687801????59EB01EBAC54E803??????5CEB08"
	strings:
		$1 = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 50 8B FE 68 78 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }
	condition:
		$1 at pe.entry_point
}

rule telock_042 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.42"
		pattern = "C1EE00668BC9EB01EB60EB01EB9CE8000000005E83C6528BFE68790159EB01EBAC54E8035CEB08"
	strings:
		$1 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 52 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }
	condition:
		$1 at pe.entry_point
}

rule telock_051_01 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.51"
		pattern = "C1EE00668BC9EB01EB60EB01EB9CE8000000005E83C65E8BFE687901000059EB01EBAC54E8030000005CEB088D642404FF6424FC6A05D02C247201E80124245CF7DCEB02CD208D6424FEF7DCEB02CD20FEC8E80000000032C1EB02820DAAEB03820D58EB021D7A49EB05E8010000007FAE147EA077767574"
	strings:
		$1 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 00 00 59 EB 01 EB AC 54 E8 03 00 00 00 5C EB 08 8D 64 24 04 FF 64 24 FC 6A 05 D0 2C 24 72 01 E8 01 24 24 5C F7 DC EB 02 CD 20 8D 64 24 FE F7 DC EB 02 CD 20 FE C8 E8 00 00 00 00 32 C1 EB 02 82 0D AA EB 03 82 0D 58 EB 02 1D 7A 49 EB 05 E8 01 00 00 00 7F AE 14 7E A0 77 76 75 74 }
	condition:
		$1 at pe.entry_point
}

rule telock_051_02 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.51"
		pattern = "C1EE00668BC9EB01EB60EB01EB9CE8000000005E83C65E8BFE68790159EB01EBAC54E8035CEB08"
	strings:
		$1 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }
	condition:
		$1 at pe.entry_point
}

rule telock_060 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.60"
		pattern = "E90000000060E8000000005883C008"
	strings:
		$1 = { E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 }
	condition:
		$1 at pe.entry_point
}

rule telock_070 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.70"
		pattern = "60E8BD100000C383E200F975FA70"
	strings:
		$1 = { 60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70 }
	condition:
		$1 at pe.entry_point
}

rule telock_071 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.71"
		pattern = "60E8ED100000C383"
	strings:
		$1 = { 60 E8 ED 10 00 00 C3 83 }
	condition:
		$1 at pe.entry_point
}

rule telock_071b2 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.71b2"
		pattern = "60E844110000C383"
	strings:
		$1 = { 60 E8 44 11 00 00 C3 83 }
	condition:
		$1 at pe.entry_point
}

rule telock_071b7 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.71b7"
		pattern = "60E848110000C383"
	strings:
		$1 = { 60 E8 48 11 00 00 C3 83 }
	condition:
		$1 at pe.entry_point
}

rule telock_07x_084 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.7x - 0.84"
		pattern = "60E80000C383"
	strings:
		$1 = { 60 E8 00 00 C3 83 }
	condition:
		$1 at pe.entry_point
}

rule telock_80 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.80"
		pattern = "60E8F9110000C383"
	strings:
		$1 = { 60 E8 F9 11 00 00 C3 83 }
	condition:
		$1 at pe.entry_point
}

rule telock_085f {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.85f"
		pattern = "60E802000000CD20E8000000005E2BC9587402"
	strings:
		$1 = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02 }
	condition:
		$1 at pe.entry_point
}

rule telock_090 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.90"
		pattern = "????E802000000E800E8000000005E2B"
	strings:
		$1 = { ?? ?? E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B }
	condition:
		$1 at pe.entry_point
}

rule telock_092a {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.92a"
		pattern = "E97EE9FFFF00"
	strings:
		$1 = { E9 7E E9 FF FF 00 }
	condition:
		$1 at pe.entry_point
}

rule telock_095 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.95"
		pattern = "E9D5E4FFFF00"
	strings:
		$1 = { E9 D5 E4 FF FF 00 }
	condition:
		$1 at pe.entry_point
}

rule telock_096 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.96"
		pattern = "E959E4FFFF00000000000000????????EE????0000000000000000000E????00FE????00F6????0000000000000000001B????0006????00000000000000000000000000000000000000000026????000000000039????000000000026????000000000039????00000000006B65726E656C33322E646C6C"
	strings:
		$1 = { E9 59 E4 FF FF 00 00 00 00 00 00 00 ?? ?? ?? ?? EE ?? ?? 00 00 00 00 00 00 00 00 00 0E ?? ?? 00 FE ?? ?? 00 F6 ?? ?? 00 00 00 00 00 00 00 00 00 1B ?? ?? 00 06 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C }
	condition:
		$1 at pe.entry_point
}

rule telock_098_10 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.98 - 1.0"
		pattern = "E9????FFFF000000??????????????000000000000000000"
	strings:
		$1 = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule telock_098_special_build {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.98 special build"
		pattern = "E999D7FFFF000000????????AA????000000000000000000CA"
	strings:
		$1 = { E9 99 D7 FF FF 00 00 00 ?? ?? ?? ?? AA ?? ?? 00 00 00 00 00 00 00 00 00 CA }
	condition:
		$1 at pe.entry_point
}

rule telock_098 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.98"
		pattern = "E925E4FFFF000000????????1E????0000000000000000003E????002E????0026????0000000000000000004B????0036????00000000000000000000000000000000000000000056????000000000069????000000000056????000000000069????00000000006B65726E656C33322E646C6C00757365"
	strings:
		$1 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E ?? ?? 00 00 00 00 00 00 00 00 00 3E ?? ?? 00 2E ?? ?? 00 26 ?? ?? 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 36 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }
	condition:
		$1 at pe.entry_point
}

rule telock_098b2 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.98b2"
		pattern = "E91BE4FFFF"
	strings:
		$1 = { E9 1B E4 FF FF }
	condition:
		$1 at pe.entry_point
}

rule telock_099_special_build {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.99 special build"
		pattern = "E95EDFFFFF000000????????E5????00000000000000000005????00F5????00ED????00000000000000000012????00FD????0000000000000000000000000000000000000000001D????000000000030????00000000001D????000000000030????0000000000"
	strings:
		$1 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 ?? ?? 00 F5 ?? ?? 00 ED ?? ?? 00 00 00 00 00 00 00 00 00 12 ?? ?? 00 FD ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule telock_099 {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.99"
		pattern = "E95EDFFFFF000000????????E5????00000000000000000005"
	strings:
		$1 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 }
	condition:
		$1 at pe.entry_point
}

rule telock_099c_private_eclipse {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.99c private ECLIPSE"
		pattern = "E93FDFFFFF000000????????04????00000000000000000024????0014????000C????00000000000000000031????001C????0000000000000000000000000000000000000000003C????00000000004F????00000000003C????00000000004F????00000000006B65726E656C33322E646C6C00757365"
	strings:
		$1 = { E9 3F DF FF FF 00 00 00 ?? ?? ?? ?? 04 ?? ?? 00 00 00 00 00 00 00 00 00 24 ?? ?? 00 14 ?? ?? 00 0C ?? ?? 00 00 00 00 00 00 00 00 00 31 ?? ?? 00 1C ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }
	condition:
		$1 at pe.entry_point
}

rule telock_100 {
	meta:
		tool = "P"
		name = "tElock"
		version = "1.00"
		pattern = "E9E5E2FFFF"
	strings:
		$1 = { E9 E5 E2 FF FF }
	condition:
		$1 at pe.entry_point
}

rule themida_1000_1800 {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.0.0.0 - 1.8.0.0"
		pattern = "B80000????600BC07458E8????????5805??0000008038E9??????????E8"
	strings:
		$1 = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 ?? ?? ?? ?? 58 05 ?? 00 00 00 80 38 E9 ?? ?? ?? ?? ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule themida_10x_18x {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.0.x - 1.8.x"
		pattern = "B8????????600BC07458E8000000005805????????8038E9750361EB35E800000000582500F0FFFF33FF66BB????6683????66391875120FB7503C03D0BB????????83C3??391A74072D00100000EBDA8BF8B8????????03C7B9????????03CFEB0AB8????????B9????????5051E884000000E800000000582D????????B9????????C600E983E9??89480161E9"
	strings:
		$1 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? ?? ?? ?? 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 ?? 89 48 01 61 E9 }
	condition:
		$1 at pe.entry_point
}

rule themida_10x_10x_no_comp {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.0.x - 1.8.x no compression"
		pattern = "558BEC83C4D860E8000000005A81EA????????8BDAC745D8000000008B45D8408945D8817DD880000000740F8B45088983????????FF450843EBE18945DC618B45DCC9C20400558BEC81C47CFFFFFF60E800000000"
	strings:
		$1 = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule themida_1x {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.x"
		pattern = "8BC58BD460E8000000005D81ED????????8995????????89B5????????8985????????83BD??????????740C8BE88BE2B801000000C20C008B4424248985????????6A45E8A3000000689A748307E8DF00000068254B890AE8D5000000E9????????0000000000000000000000000000000000000000"
	strings:
		$1 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? ?? ?? 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule themida_1802_winlicense {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.8.0.2 or higher WinLicense"
		pattern = "B80000????600BC07468E8????????5805??0000008038E9??????????DB2D??????????????FFFFFFFFFF"
	strings:
		$1 = { B8 00 00 ?? ?? 60 0B C0 74 68 E8 ?? ?? ?? ?? 58 05 ?? 00 00 00 80 38 E9 ?? ?? ?? ?? ?? DB 2D ?? ?? ?? ?? ?? ?? ?? FF FF FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule themida_18x_2x_winlicense {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.8.x - 2.x WinLicense"
		pattern = "B8????????600BC07468E8000000005805530000008038E9751361EB45DB2D????????FFFFFFFFFFFFFFFF3D????????0000582500F0FFFF33FF66BB????6683????66391875120FB7503C03D0BB????????83C3??391A74072D????????EBDA8BF8B8????????03C7B9????????03CFEB0AB8????????B9????????5051E8????????E8????????58"
	strings:
		$1 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 }
	condition:
		$1 at pe.entry_point
}

rule themida_2010_winlicense {
	meta:
		tool = "P"
		name = "Themida"
		version = "2.0.1.0 or higher WinLicense"
		pattern = "00000000????????000000006B65726E656C33322E646C6C00????????0000000000000000????????????????00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1
}

rule thewrap_uv {
	meta:
		tool = "P"
		name = "theWRAP"
		pattern = "558BEC83C4F053565733C08945F0B848D24B00E8BC87F4FFBB040B4D0033C05568E8D54B0064FF30648920E89CF4FFFFE8F7FBFFFF6A408D55F0A1F0ED4B008B00E8422EF7FF8B4DF0B201A1F4C24000E8F720F5FF8BF0B201A1B4C34000E8F15BF4FF890333D28B03E8421EF5FF66B90200BAFCFFFFFF8BC68B38FF570CBAB8A74D00B9040000008BC68B38FF5704833DB8A74D00000F845E0100008B15B8A74D0083C204F7DA66B902008BC68B38FF570C8B0DB8A74D008BD68B03E82B1FF5FF8BC6E8B45BF4FF33D28B03E8DF1DF5FFBAF0444E00B9010000008B038B30FF5604803DF0444E000A753FBAB8A74D00B9040000008B038B30FF56048B15B8A7"
	strings:
		$1 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 48 D2 4B 00 E8 BC 87 F4 FF BB 04 0B 4D 00 33 C0 55 68 E8 D5 4B 00 64 FF 30 64 89 20 E8 9C F4 FF FF E8 F7 FB FF FF 6A 40 8D 55 F0 A1 F0 ED 4B 00 8B 00 E8 42 2E F7 FF 8B 4D F0 B2 01 A1 F4 C2 40 00 E8 F7 20 F5 FF 8B F0 B2 01 A1 B4 C3 40 00 E8 F1 5B F4 FF 89 03 33 D2 8B 03 E8 42 1E F5 FF 66 B9 02 00 BA FC FF FF FF 8B C6 8B 38 FF 57 0C BA B8 A7 4D 00 B9 04 00 00 00 8B C6 8B 38 FF 57 04 83 3D B8 A7 4D 00 00 0F 84 5E 01 00 00 8B 15 B8 A7 4D 00 83 C2 04 F7 DA 66 B9 02 00 8B C6 8B 38 FF 57 0C 8B 0D B8 A7 4D 00 8B D6 8B 03 E8 2B 1F F5 FF 8B C6 E8 B4 5B F4 FF 33 D2 8B 03 E8 DF 1D F5 FF BA F0 44 4E 00 B9 01 00 00 00 8B 03 8B 30 FF 56 04 80 3D F0 44 4E 00 0A 75 3F BA B8 A7 4D 00 B9 04 00 00 00 8B 03 8B 30 FF 56 04 8B 15 B8 A7 }
	condition:
		$1 at pe.entry_point
}

rule thunderbolt_002 {
	meta:
		tool = "P"
		name = "Thunderbolt"
		version = "0.02"
		pattern = "E90000000060E8140000005D81ED000000006A45E8A30000006800000000E85861E8AA000000????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????5D6800FE9F0753E85D000000EBFF71E8C25000EBD65EF36889742448742458FF8D7424585E83C64C75F4598D71E8750981F6EBFF51B9010083EEFC49FF71C775198B74240000813650568B36EBFF77C43681F6EB8734248B8B1C2483ECFCEB01E883ECFCE9E70000005BEBFFF3EBFFC3"
	strings:
		$1 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 E8 AA 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5D 68 00 FE 9F 07 53 E8 5D 00 00 00 EB FF 71 E8 C2 50 00 EB D6 5E F3 68 89 74 24 48 74 24 58 FF 8D 74 24 58 5E 83 C6 4C 75 F4 59 8D 71 E8 75 09 81 F6 EB FF 51 B9 01 00 83 EE FC 49 FF 71 C7 75 19 8B 74 24 00 00 81 36 50 56 8B 36 EB FF 77 C4 36 81 F6 EB 87 34 24 8B 8B 1C 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 5B EB FF F3 EB FF C3 }
	condition:
		$1 at pe.entry_point
}

rule tpav_cryptor_11 {
	meta:
		tool = "P"
		name = "TPAV Cryptor"
		version = "1.1"
		pattern = "8D8508FFFFFF508D85C4FEFFFF506A006A006A046A006A006A008D95C0FEFFFF33C0E8????FFFF8B85C0FEFFFFE8????FFFF506A00FF152C????70"
	strings:
		$1 = { 8D 85 08 FF FF FF 50 8D 85 C4 FE FF FF 50 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 8D 95 C0 FE FF FF 33 C0 E8 ?? ?? FF FF 8B 85 C0 FE FF FF E8 ?? ?? FF FF 50 6A 00 FF 15 2C ?? ?? 70 }
	condition:
		$1 at pe.entry_point
}

rule tpppack_uv {
	meta:
		tool = "P"
		name = "TPPpack"
		pattern = "E8000000005D81EDF58F40006033??E8"
	strings:
		$1 = { E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 ?? E8 }
	condition:
		$1 at pe.entry_point
}

rule trainer_creation_kit_5 {
	meta:
		tool = "P"
		name = "Trainer Creation Kit"
		version = "5"
		pattern = "6A0068800000006A026A006A0068000000406825454000E83C020000506A0068404540006800100000680030400050E8540200005850E8170200006A00E82E020000A3704540006825454000E82B020000A3304540"
	strings:
		$1 = { 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 68 25 45 40 00 E8 3C 02 00 00 50 6A 00 68 40 45 40 00 68 00 10 00 00 68 00 30 40 00 50 E8 54 02 00 00 58 50 E8 17 02 00 00 6A 00 E8 2E 02 00 00 A3 70 45 40 00 68 25 45 40 00 E8 2B 02 00 00 A3 30 45 40 }
	condition:
		$1
}

rule trivial173_uv {
	meta:
		tool = "P"
		name = "Trivial173"
		pattern = "EB????285472697669616C31373320627920534D542F534D4629"
	strings:
		$1 = { EB ?? ?? 28 54 72 69 76 69 61 6C 31 37 33 20 62 79 20 53 4D 54 2F 53 4D 46 29 }
	condition:
		$1 at pe.entry_point
}

rule ug2002_cruncher_03b3 {
	meta:
		tool = "P"
		name = "UG2002 Cruncher"
		version = "0.3b3"
		pattern = "60E8????????5D81ED????????E80D????????????????????????????????58"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? E8 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58 }
	condition:
		$1 at pe.entry_point
}

rule ultrapro_10 {
	meta:
		tool = "P"
		name = "UltraPro"
		version = "1.0"
		pattern = "A1????????85C00F853B0600005556C705????????01000000FF15"
	strings:
		$1 = { A1 ?? ?? ?? ?? 85 C0 0F 85 3B 06 00 00 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 }
	condition:
		$1 at pe.entry_point
}

rule underdround_crypter_uv {
	meta:
		tool = "P"
		name = "UnderGround Crypter"
		pattern = "558BEC83C4F0B8743C0011E894F9FFFFE8BFFEFFFFE80AF3FFFF8BC0"
	strings:
		$1 = { 55 8B EC 83 C4 F0 B8 74 3C 00 11 E8 94 F9 FF FF E8 BF FE FF FF E8 0A F3 FF FF 8B C0 }
	condition:
		$1 at pe.entry_point
}

rule unicops_uv {
	meta:
		tool = "P"
		name = "UNICOPS"
		pattern = "68F136ADB6871C2460E8000000005F8DB7EAF7FFFF81C7320000008B0E8AD183C604C1E908740B8A0732C32AF8AAD3D3E2F580FA007407011F83C704EBDD615B"
	strings:
		$1 = { 68 F1 36 AD B6 87 1C 24 60 E8 00 00 00 00 5F 8D B7 EA F7 FF FF 81 C7 32 00 00 00 8B 0E 8A D1 83 C6 04 C1 E9 08 74 0B 8A 07 32 C3 2A F8 AA D3 D3 E2 F5 80 FA 00 74 07 01 1F 83 C7 04 EB DD 61 5B }
	condition:
		$1 at pe.entry_point
}

rule unnamed_scrambler_10 {
	meta:
		tool = "P"
		name = "Unnamed Scrambler"
		version = "1.0"
		pattern = "558BEC83C4EC535633C08945????????4000E811F4FFFFBE306B400033C05568C942400064FF30648920E8C9FAFFFFBAD84240008B????????FFFF8BD8B8286B40008B16E837F0FFFFB82C6B40008B16E82BF0FFFFB8286B4000E819F0FFFF8BD08BC38B0EE842E3FFFFBADC4240008BC6E82AFAFFFF8BD8B8206B40008B16E8FCEFFFFFB8246B40008B16E8F0EFFFFFB8206B4000E8DEEFFFFF8BD08BC38B0EE807E3FFFF6A006A196A006A32A1286B4000E859EFFFFF83E80503C08D55ECE894FEFFFF8B55ECB9246B4000A1206B4000E8E2F6FFFF6A006A196A006A32"
	strings:
		$1 = { 55 8B EC 83 C4 EC 53 56 33 C0 89 45 ?? ?? ?? ?? 40 00 E8 11 F4 FF FF BE 30 6B 40 00 33 C0 55 68 C9 42 40 00 64 FF 30 64 89 20 E8 C9 FA FF FF BA D8 42 40 00 8B ?? ?? ?? ?? FF FF 8B D8 B8 28 6B 40 00 8B 16 E8 37 F0 FF FF B8 2C 6B 40 00 8B 16 E8 2B F0 FF FF B8 28 6B 40 00 E8 19 F0 FF FF 8B D0 8B C3 8B 0E E8 42 E3 FF FF BA DC 42 40 00 8B C6 E8 2A FA FF FF 8B D8 B8 20 6B 40 00 8B 16 E8 FC EF FF FF B8 24 6B 40 00 8B 16 E8 F0 EF FF FF B8 20 6B 40 00 E8 DE EF FF FF 8B D0 8B C3 8B 0E E8 07 E3 FF FF 6A 00 6A 19 6A 00 6A 32 A1 28 6B 40 00 E8 59 EF FF FF 83 E8 05 03 C0 8D 55 EC E8 94 FE FF FF 8B 55 EC B9 24 6B 40 00 A1 20 6B 40 00 E8 E2 F6 FF FF 6A 00 6A 19 6A 00 6A 32 }
	condition:
		$1 at pe.entry_point
}

rule unnamed_scrambler_11c {
	meta:
		tool = "P"
		name = "Unnamed Scrambler"
		version = "1.1c"
		pattern = "558BEC83C4E4535633C08945E48945E88945ECB8C0470010E84FF3FFFFBE5C67001033C05568D24A001064FF30648920E8EBDEFFFFE8C6F8FFFFBAE04A0010B8CC670010E85FF8FFFF8BD88BD68BC38B0DCC670010E83ADDFFFF8B46508BD0B8D4670010E85BEFFFFFB8D4670010E809EFFFFF8BD08D46148B4E50E814DDFFFF8B46488BD0B8D86700??????????FFB8D8670010E8E3EEFFFF8BD08BC68B4E48E8EFDCFFFFFF765CFF7658FF7664FF7660B9D46700108B15D8670010A1D4670010E876F6FFFFA1D4670010E85CEEFFFF8BD0B8CC670010E8CCF7FFFF8BD8B8DC670010"
	strings:
		$1 = { 55 8B EC 83 C4 E4 53 56 33 C0 89 45 E4 89 45 E8 89 45 EC B8 C0 47 00 10 E8 4F F3 FF FF BE 5C 67 00 10 33 C0 55 68 D2 4A 00 10 64 FF 30 64 89 20 E8 EB DE FF FF E8 C6 F8 FF FF BA E0 4A 00 10 B8 CC 67 00 10 E8 5F F8 FF FF 8B D8 8B D6 8B C3 8B 0D CC 67 00 10 E8 3A DD FF FF 8B 46 50 8B D0 B8 D4 67 00 10 E8 5B EF FF FF B8 D4 67 00 10 E8 09 EF FF FF 8B D0 8D 46 14 8B 4E 50 E8 14 DD FF FF 8B 46 48 8B D0 B8 D8 67 00 ?? ?? ?? ?? ?? FF B8 D8 67 00 10 E8 E3 EE FF FF 8B D0 8B C6 8B 4E 48 E8 EF DC FF FF FF 76 5C FF 76 58 FF 76 64 FF 76 60 B9 D4 67 00 10 8B 15 D8 67 00 10 A1 D4 67 00 10 E8 76 F6 FF FF A1 D4 67 00 10 E8 5C EE FF FF 8B D0 B8 CC 67 00 10 E8 CC F7 FF FF 8B D8 B8 DC 67 00 10 }
	condition:
		$1 at pe.entry_point
}

rule unnamed_scrambler_12b {
	meta:
		tool = "P"
		name = "Unnamed Scrambler"
		version = "1.2b"
		pattern = "558BEC83C4D853565733C08945D88945DC8945E08945E48945E8B8703A4000E8C4ECFFFF33C055685C3F400064FF30648920E8C5D7FFFFE85CF5FFFFB82065400033C9BA04010000E8D3DBFFFF680401000068206540006A00FF1510554000BA6C3F4000B814554000E85AF4FFFF85C00F841B040000BA185540008B0D14554000E816D7FFFF8B05886140008BD0B854624000E8D4E3FFFFB854624000E8F2E2FFFF8BD0B8185540008B0D88614000E8E8D6FFFFFF3534624000FF3530624000FF353C624000FF35386240008D55E8A188614000E8E3F0FFFF8B55E8"
	strings:
		$1 = { 55 8B EC 83 C4 D8 53 56 57 33 C0 89 45 D8 89 45 DC 89 45 E0 89 45 E4 89 45 E8 B8 70 3A 40 00 E8 C4 EC FF FF 33 C0 55 68 5C 3F 40 00 64 FF 30 64 89 20 E8 C5 D7 FF FF E8 5C F5 FF FF B8 20 65 40 00 33 C9 BA 04 01 00 00 E8 D3 DB FF FF 68 04 01 00 00 68 20 65 40 00 6A 00 FF 15 10 55 40 00 BA 6C 3F 40 00 B8 14 55 40 00 E8 5A F4 FF FF 85 C0 0F 84 1B 04 00 00 BA 18 55 40 00 8B 0D 14 55 40 00 E8 16 D7 FF FF 8B 05 88 61 40 00 8B D0 B8 54 62 40 00 E8 D4 E3 FF FF B8 54 62 40 00 E8 F2 E2 FF FF 8B D0 B8 18 55 40 00 8B 0D 88 61 40 00 E8 E8 D6 FF FF FF 35 34 62 40 00 FF 35 30 62 40 00 FF 35 3C 62 40 00 FF 35 38 62 40 00 8D 55 E8 A1 88 61 40 00 E8 E3 F0 FF FF 8B 55 E8 }
	condition:
		$1 at pe.entry_point
}

rule unnamed_scrambler_12c_12d {
	meta:
		tool = "P"
		name = "Unnamed Scrambler"
		version = "1.2c, 1.2d"
		pattern = "558BECB9050000006A006A004975F951535657B8??3A????E8??ECFFFF33C05568????????64FF30648920E8??D7FFFFE8????FFFFB820??????33C9BA04010000E8??DBFFFF68040100006820??????6A00FF1510??????BA????????B814??????E8????FFFF85C00F84??040000BA18??????8B0D14??????E8????FFFF8B0588??????8BD0B854??????E8??E3FFFFB854??????E8??E2FFFF8BD0B818??????8B0D88??????E8??D6FFFFFF3534??????FF3530??????FF353C??????FF3538??????8D55E8A188??????E8??F0FFFF8B55E8B954"
	strings:
		$1 = { 55 8B EC B9 05 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? 3A ?? ?? E8 ?? EC FF FF 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 E8 ?? D7 FF FF E8 ?? ?? FF FF B8 20 ?? ?? ?? 33 C9 BA 04 01 00 00 E8 ?? DB FF FF 68 04 01 00 00 68 20 ?? ?? ?? 6A 00 FF 15 10 ?? ?? ?? BA ?? ?? ?? ?? B8 14 ?? ?? ?? E8 ?? ?? FF FF 85 C0 0F 84 ?? 04 00 00 BA 18 ?? ?? ?? 8B 0D 14 ?? ?? ?? E8 ?? ?? FF FF 8B 05 88 ?? ?? ?? 8B D0 B8 54 ?? ?? ?? E8 ?? E3 FF FF B8 54 ?? ?? ?? E8 ?? E2 FF FF 8B D0 B8 18 ?? ?? ?? 8B 0D 88 ?? ?? ?? E8 ?? D6 FF FF FF 35 34 ?? ?? ?? FF 35 30 ?? ?? ?? FF 35 3C ?? ?? ?? FF 35 38 ?? ?? ?? 8D 55 E8 A1 88 ?? ?? ?? E8 ?? F0 FF FF 8B 55 E8 B9 54 }
	condition:
		$1 at pe.entry_point
}

rule unnamed_scrambler_13b {
	meta:
		tool = "P"
		name = "Unnamed Scrambler"
		version = "1.3b"
		pattern = "558BECB9080000006A006A004975F9535657B898560010E848EBFFFF33C05568AC5D001064FF306489206A0068BC5D001068C45D00106A00E823ECFFFFE8C6CEFFFF6A0068BC5D001068????????6A00E80BECFFFFE8F2F4FFFFB808BC001033C9BA04010000E8C1D2FFFF6A0068BC5D001068E45D00106A00E8E2EBFFFF68040100006808BC00106A00FF15687700106A0068BC5D001068FC5D00106A00E8BDEBFFFFBA105E0010B870770010E8CAF3FFFF85C00F84F7050000BA747700108B0D70770010E8FECDFFFF6A00"
	strings:
		$1 = { 55 8B EC B9 08 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 98 56 00 10 E8 48 EB FF FF 33 C0 55 68 AC 5D 00 10 64 FF 30 64 89 20 6A 00 68 BC 5D 00 10 68 C4 5D 00 10 6A 00 E8 23 EC FF FF E8 C6 CE FF FF 6A 00 68 BC 5D 00 10 68 ?? ?? ?? ?? 6A 00 E8 0B EC FF FF E8 F2 F4 FF FF B8 08 BC 00 10 33 C9 BA 04 01 00 00 E8 C1 D2 FF FF 6A 00 68 BC 5D 00 10 68 E4 5D 00 10 6A 00 E8 E2 EB FF FF 68 04 01 00 00 68 08 BC 00 10 6A 00 FF 15 68 77 00 10 6A 00 68 BC 5D 00 10 68 FC 5D 00 10 6A 00 E8 BD EB FF FF BA 10 5E 00 10 B8 70 77 00 10 E8 CA F3 FF FF 85 C0 0F 84 F7 05 00 00 BA 74 77 00 10 8B 0D 70 77 00 10 E8 FE CD FF FF 6A 00 }
	condition:
		$1 at pe.entry_point
}

rule unnamed_scrambler_20 {
	meta:
		tool = "P"
		name = "Unnamed Scrambler"
		version = "2.0"
		pattern = "558BECB90A0000006A006A004975F9535657B81C2F4000E8C8F1FFFF33C05568FB33400064FF30648920BA0C344000B8E4544000E8EFFEFFFF8BD885DB75076A00E85AF2FFFFBAE85440008BC38B0DE4544000E874E2FFFFC705206B400009000000BB98694000C745ECE8544000C745E831574000C745E443604000BED36A4000BFE06A4000837B0400750B833B000F86AA030000EB060F8EA20300008B038BD0B80C6B4000E8C1EEFFFFB80C6B4000E86FEEFFFF8BD08B45EC8B0BE80BE2FFFF6A006A1E6A006A2CA10C6B4000E825EDFFFF8D55E0E815FEFFFF8B55E0B9106B4000A10C6B4000"
	strings:
		$1 = { 55 8B EC B9 0A 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 1C 2F 40 00 E8 C8 F1 FF FF 33 C0 55 68 FB 33 40 00 64 FF 30 64 89 20 BA 0C 34 40 00 B8 E4 54 40 00 E8 EF FE FF FF 8B D8 85 DB 75 07 6A 00 E8 5A F2 FF FF BA E8 54 40 00 8B C3 8B 0D E4 54 40 00 E8 74 E2 FF FF C7 05 20 6B 40 00 09 00 00 00 BB 98 69 40 00 C7 45 EC E8 54 40 00 C7 45 E8 31 57 40 00 C7 45 E4 43 60 40 00 BE D3 6A 40 00 BF E0 6A 40 00 83 7B 04 00 75 0B 83 3B 00 0F 86 AA 03 00 00 EB 06 0F 8E A2 03 00 00 8B 03 8B D0 B8 0C 6B 40 00 E8 C1 EE FF FF B8 0C 6B 40 00 E8 6F EE FF FF 8B D0 8B 45 EC 8B 0B E8 0B E2 FF FF 6A 00 6A 1E 6A 00 6A 2C A1 0C 6B 40 00 E8 25 ED FF FF 8D 55 E0 E8 15 FE FF FF 8B 55 E0 B9 10 6B 40 00 A1 0C 6B 40 00 }
	condition:
		$1 at pe.entry_point
}
rule unnamed_scrambler_211 {
	meta:
		tool = "P"
		name = "Unnamed Scrambler"
		version = "2.1.1"
		pattern = "558BECB9150000006A006A004975F9535657B8??3A????E8??EEFFFF33C05568??43????64FF30648920BA??43????B8E464????E80FFDFFFF8BD885DB75076A00E8??EEFFFFBAE864????8BC38B0DE464????E8??D7FFFFB8F8??????BA04000000E8??EFFFFF33C0A3F8??????BB????????C745ECE864????C745E8????????C745E4????????BE????????BF????????B8E0??????BA04000000E8??EFFFFF68F4010000E8??EEFFFF837B0400750B833B000F86??070000EB060F8E??0700008B038BD0B8E4??????E8??E5FFFFB8E4??????E8??E3FFFF8BD08B45EC8B0BE8"
	strings:
		$1 = { 55 8B EC B9 15 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? 3A ?? ?? E8 ?? EE FF FF 33 C0 55 68 ?? 43 ?? ?? 64 FF 30 64 89 20 BA ?? 43 ?? ?? B8 E4 64 ?? ?? E8 0F FD FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? EE FF FF BA E8 64 ?? ?? 8B C3 8B 0D E4 64 ?? ?? E8 ?? D7 FF FF B8 F8 ?? ?? ?? BA 04 00 00 00 E8 ?? EF FF FF 33 C0 A3 F8 ?? ?? ?? BB ?? ?? ?? ?? C7 45 EC E8 64 ?? ?? C7 45 E8 ?? ?? ?? ?? C7 45 E4 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? B8 E0 ?? ?? ?? BA 04 00 00 00 E8 ?? EF FF FF 68 F4 01 00 00 E8 ?? EE FF FF 83 7B 04 00 75 0B 83 3B 00 0F 86 ?? 07 00 00 EB 06 0F 8E ?? 07 00 00 8B 03 8B D0 B8 E4 ?? ?? ?? E8 ?? E5 FF FF B8 E4 ?? ?? ?? E8 ?? E3 FF FF 8B D0 8B 45 EC 8B 0B E8 }
	condition:
		$1 at pe.entry_point
}
rule unnamed_scrambler_252 {
	meta:
		tool = "P"
		name = "Unnamed Scrambler"
		version = "2.5.2"
		pattern = "558BECB9??0000006A006A004975F9535657B8????4000E8??EAFFFF33C05568????400064FF30648920BA????4000B8????4000E863F3FFFF8BD885DB75076A00E8????FFFFBA????40008BC38B0D????4000E8????FFFFC705????40000A000000BB????4000BE????4000BF????4000B8????4000BA04000000E8??EBFFFF833B00740433C089038BD78BC6E80AF3FFFF8903833B000F84F7040000B8????40008B16E8??E1FFFFB8????4000E8??E0FFFF8BD08B038B0EE8????FFFF8BC7A3????40008D55EC33C0E8??D3FFFF8B45ECB9????4000BA????4000E88BEDFFFF3C01752BA1"
	strings:
		$1 = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? ?? 40 00 E8 ?? EA FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 BA ?? ?? 40 00 B8 ?? ?? 40 00 E8 63 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? ?? FF FF BA ?? ?? 40 00 8B C3 8B 0D ?? ?? 40 00 E8 ?? ?? FF FF C7 05 ?? ?? 40 00 0A 00 00 00 BB ?? ?? 40 00 BE ?? ?? 40 00 BF ?? ?? 40 00 B8 ?? ?? 40 00 BA 04 00 00 00 E8 ?? EB FF FF 83 3B 00 74 04 33 C0 89 03 8B D7 8B C6 E8 0A F3 FF FF 89 03 83 3B 00 0F 84 F7 04 00 00 B8 ?? ?? 40 00 8B 16 E8 ?? E1 FF FF B8 ?? ?? 40 00 E8 ?? E0 FF FF 8B D0 8B 03 8B 0E E8 ?? ?? FF FF 8B C7 A3 ?? ?? 40 00 8D 55 EC 33 C0 E8 ?? D3 FF FF 8B 45 EC B9 ?? ?? 40 00 BA ?? ?? 40 00 E8 8B ED FF FF 3C 01 75 2B A1 }
	condition:
		$1 at pe.entry_point
}

rule unnamed_scrambler_25a {
	meta:
		tool = "P"
		name = "Unnamed Scrambler"
		version = "2.5a"
		pattern = "558BECB90B0000006A006A004975F951535657B86C3E4000E8F7EAFFFF33C055686044400064FF30648920BA70444000B8B86C4000E862F3FFFF8BD885DB75076A00E8A1EBFFFFBAE86440008BC38B0DB86C4000E837D3FFFFC705BC6C40000A000000BB686C4000BE906C4000BFE8644000B8C06C4000BA04000000E807ECFFFF833B00740433C089038BD78BC6E809F3FFFF8903833B000F84BB040000B8C06C40008B16E806E2FFFFB8C06C4000E824E1FFFF8BD08B038B0EE8D1D2FFFF8BC7A3206E40008D55EC33C0E80CD4FFFF8B45ECB91C6E4000BA186E4000"
	strings:
		$1 = { 55 8B EC B9 0B 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 6C 3E 40 00 E8 F7 EA FF FF 33 C0 55 68 60 44 40 00 64 FF 30 64 89 20 BA 70 44 40 00 B8 B8 6C 40 00 E8 62 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 A1 EB FF FF BA E8 64 40 00 8B C3 8B 0D B8 6C 40 00 E8 37 D3 FF FF C7 05 BC 6C 40 00 0A 00 00 00 BB 68 6C 40 00 BE 90 6C 40 00 BF E8 64 40 00 B8 C0 6C 40 00 BA 04 00 00 00 E8 07 EC FF FF 83 3B 00 74 04 33 C0 89 03 8B D7 8B C6 E8 09 F3 FF FF 89 03 83 3B 00 0F 84 BB 04 00 00 B8 C0 6C 40 00 8B 16 E8 06 E2 FF FF B8 C0 6C 40 00 E8 24 E1 FF FF 8B D0 8B 03 8B 0E E8 D1 D2 FF FF 8B C7 A3 20 6E 40 00 8D 55 EC 33 C0 E8 0C D4 FF FF 8B 45 EC B9 1C 6E 40 00 BA 18 6E 40 00 }
	condition:
		$1 at pe.entry_point
}

rule unopix_075 {
	meta:
		tool = "P"
		name = "UnoPiX"
		version = "0.75"
		pattern = "60E8070000006168????4000C383042418C32083B8ED2037EFC6B979379E61"
	strings:
		$1 = { 60 E8 07 00 00 00 61 68 ?? ?? 40 00 C3 83 04 24 18 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 61 }
	condition:
		$1 at pe.entry_point
}

rule unopix_103_110 {
	meta:
		tool = "P"
		name = "UnoPiX"
		version = "1.03 - 1.10"
		pattern = "83EC04C7042400??????C300????000000000000000000000000????00100000000200000100000000000000040000000000000000????000010000000000000020000??0000??0000????0000001000001000000000000010"
	strings:
		$1 = { 83 EC 04 C7 04 24 00 ?? ?? ?? C3 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 10 00 00 00 00 00 00 02 00 00 ?? 00 00 ?? 00 00 ?? ?? 00 00 00 10 00 00 10 00 00 00 00 00 00 10 }
	condition:
		$1 at pe.entry_point
}

rule unsorted_packer_uv_01 {
	meta:
		tool = "P"
		name = "UNSORTED PACKER"
		pattern = "5589E583EC146A01FF15????????E8????????905589E55383EC048B45088B008B003D910000C077373D8D0000C07248BB0100000083EC086A006A08E8"
	strings:
		$1 = { 55 89 E5 83 EC 14 6A 01 FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 55 89 E5 53 83 EC 04 8B 45 08 8B 00 8B 00 3D 91 00 00 C0 77 37 3D 8D 00 00 C0 72 48 BB 01 00 00 00 83 EC 08 6A 00 6A 08 E8 }
	condition:
		$1 at pe.entry_point
}

rule unsorted_packer_uv_02 {
	meta:
		tool = "P"
		name = "UNSORTED PACKER"
		pattern = "60E9C5000000608B7424248B7C2428FCB28033DBA4B302E86D00000073F633C9E864000000731C33C0E85B0000007323B30241B010E84F00000012C073F7753F"
	strings:
		$1 = { 60 E9 C5 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F }
	condition:
		$1 at pe.entry_point
}

rule unsorted_packer_uv_03 {
	meta:
		tool = "P"
		name = "UNSORTED PACKER"
		pattern = "9C505152535455565783BCE42C000000010F858A010000E8000000005E81EE6500000089F781EF????????89F18B0901F9FF3168????????B9????????01F951"
	strings:
		$1 = { 9C 50 51 52 53 54 55 56 57 83 BC E4 2C 00 00 00 01 0F 85 8A 01 00 00 E8 00 00 00 00 5E 81 EE 65 00 00 00 89 F7 81 EF ?? ?? ?? ?? 89 F1 8B 09 01 F9 FF 31 68 ?? ?? ?? ?? B9 ?? ?? ?? ?? 01 F9 51 }
	condition:
		$1 at pe.entry_point
}

rule unsorted_packer_uv_04 {
	meta:
		tool = "P"
		name = "UNSORTED PACKER"
		pattern = "9C6060E8000000005E81C6????0000566467FF360000646789260000EA????????C3E8010000006983C404FAE8010000008B83C404F00FC7C8EB03C7848B5558"
	strings:
		$1 = { 9C 60 60 E8 00 00 00 00 5E 81 C6 ?? ?? 00 00 56 64 67 FF 36 00 00 64 67 89 26 00 00 EA ?? ?? ?? ?? C3 E8 01 00 00 00 69 83 C4 04 FA E8 01 00 00 00 8B 83 C4 04 F0 0F C7 C8 EB 03 C7 84 8B 55 58 }
	condition:
		$1 at pe.entry_point
}

rule unsorted_packer_uv_05 {
	meta:
		tool = "P"
		name = "UNSORTED PACKER"
		pattern = "9C68????00007?1?810424????????90810424C3"
	strings:
		$1 = { 9C 68 ?? ?? 00 00 7? 1? 81 04 24 ?? ?? ?? ?? 90 81 04 24 C3 }
	condition:
		$1 at pe.entry_point
}

rule unsorted_packer_uv_06 {
	meta:
		tool = "P"
		name = "UNSORTED PACKER"
		pattern = "9C68????00007?1?8104241F??????????810424C20000"
	strings:
		$1 = { 9C 68 ?? ?? 00 00 7? 1? 81 04 24 1F ?? ?? ?? ?? ?? 81 04 24 C2 00 00 }
	condition:
		$1 at pe.entry_point
}

rule unsorted_packer_uv_07 {
	meta:
		tool = "P"
		name = "UNSORTED PACKER"
		pattern = "FCB8????????B9????????81F9????????750681C1270000003001C1C0034181F9????????75E4"
	strings:
		$1 = { FC B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 81 F9 ?? ?? ?? ?? 75 06 81 C1 27 00 00 00 30 01 C1 C0 03 41 81 F9 ?? ?? ?? ?? 75 E4 }
	condition:
		$1 at pe.entry_point
}

rule upack_uv {
	meta:
		tool = "P"
		name = "Upack"
		pattern = "813A0000000200000000"
	strings:
		$1 = { 81 3A 00 00 00 02 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule upack_010_011 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.10 - 0.11"
		pattern = "BE????????AD8BF895A533C033C9AB48ABF7D8B1??F3ABC1E0??B5??F3ABAD509751AD87F5588D54865CFFD5725A2C??73??B0??3C??72022C??500FB65FFFC1E3??B3??8D1C5B8D????????????B0??67E3298BD72B560C8A2A33D284E90F95C652FEC68AD08D1493FFD5"
	strings:
		$1 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 ?? F3 AB C1 E0 ?? B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C ?? 73 ?? B0 ?? 3C ?? 72 02 2C ?? 50 0F B6 5F FF C1 E3 ?? B3 ?? 8D 1C 5B 8D ?? ?? ?? ?? ?? ?? B0 ?? 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5 }
	condition:
		$1 at pe.entry_point
}

rule upack_010_012 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.10 - 0.12"
		pattern = "BE????????AD8BF895A533C033C9AB48ABF7D8B104F3ABC1E00AB5??F3ABAD509751AD87F5588D54865CFFD5725A2C037302B0003C0772022C03500FB65FFFC1E3??B3008D1C5B8D9C9E0C100000B00167E3298BD72B560C8A2A33D284E90F95C652FEC68AD08D1493FFD55A9F12C0D0E9740E9E1AF274E4B40033C9B501FF55CC33C9E9DF0000008B5E0C83C230FFD5735083C230FFD5721B83C230FFD5722B3C07B0097202B00B508BC72B460CB1808A00EBCF83C260FFD5875E10730D83C230FFD5875E147303875E183C07B0087202B00B50538D967C070000FF55D05B91EB773C07B0077202B00A50875E10875E14895E188D96C40B0000FF55D0"
	strings:
		$1 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9E 0C 10 00 00 B0 01 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 55 CC 33 C9 E9 DF 00 00 00 8B 5E 0C 83 C2 30 FF D5 73 50 83 C2 30 FF D5 72 1B 83 C2 30 FF D5 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 46 0C B1 80 8A 00 EB CF 83 C2 60 FF D5 87 5E 10 73 0D 83 C2 30 FF D5 87 5E 14 73 03 87 5E 18 3C 07 B0 08 72 02 B0 0B 50 53 8D 96 7C 07 00 00 FF 55 D0 5B 91 EB 77 3C 07 B0 07 72 02 B0 0A 50 87 5E 10 87 5E 14 89 5E 18 8D 96 C4 0B 00 00 FF 55 D0 }
	condition:
		$1 at pe.entry_point
}

rule upack_011 {
	meta:
		tool = "P"
		name = "UPack"
		version = "0.11"
		pattern = "BE48014000AD8BF895A533C033C9AB48ABF7D8B104F3ABC1E00AB51CF3ABAD509751AD87F5588D54865CFFD5725A2C037302B0003C0772022C03500FB65FFFC1E303B3008D1C5B8D9C9E0C100000B00167E3298BD7"
	strings:
		$1 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 1C F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 03 B3 00 8D 1C 5B 8D 9C 9E 0C 10 00 00 B0 01 67 E3 29 8B D7 }
	condition:
		$1 at pe.entry_point
}

rule upack_012b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.12b"
		pattern = "BE48014000AD??????A5??C033C9??????????????F3AB????0A????????AD509751??87F5588D54865C??D572??????????????????????????????B65FFFC1"
	strings:
		$1 = { BE 48 01 40 00 AD ?? ?? ?? A5 ?? C0 33 C9 ?? ?? ?? ?? ?? ?? ?? F3 AB ?? ?? 0A ?? ?? ?? ?? AD 50 97 51 ?? 87 F5 58 8D 54 86 5C ?? D5 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B6 5F FF C1 }
	condition:
		$1 at pe.entry_point
}

rule upack_02b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.2b"
		pattern = "BE8801????AD8BF895A533C033"
	strings:
		$1 = { BE 88 01 ?? ?? AD 8B F8 95 A5 33 C0 33 }
	condition:
		$1 at pe.entry_point
}

rule upack_020_01 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.20"
		pattern = "BE????????AD8BF895A533C033C9AB48ABF7D8B104F3ABC1E00A????F3ABAD509751588D54855CFF16725A2C037302B0003C0772022C03500FB65FFFC1????B3008D1C5B8D9C9D0C100000B00167E3298BD72B550C8A2A33D284E90F95C652FEC68AD08D1493FF165A9F12C0D0E9740E9E1AF274E4B40033C9B501FF560833C9E9070100008B5D0C83C230FF16735383C230FF16721B83C230FF16722B3C07B0097202B00B508BC72B450CB1808A00EBCF83C260FF16875D10730D83C230FF16875D147303875D183C07B0087202B00B50538D957C070000FF560C5B91E99C000000"
	strings:
		$1 = { BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A ?? ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 ?? ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 67 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 E9 07 01 00 00 8B 5D 0C 83 C2 30 FF 16 73 53 83 C2 30 FF 16 72 1B 83 C2 30 FF 16 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C B1 80 8A 00 EB CF 83 C2 60 FF 16 87 5D 10 73 0D 83 C2 30 FF 16 87 5D 14 73 03 87 5D 18 3C 07 B0 08 72 02 B0 0B 50 53 8D 95 7C 07 00 00 FF 56 0C 5B 91 E9 9C 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule upack_020_02 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.20"
		pattern = "E90602000033C95E870EE3F42BF18BDEAD2BD8AD03C35097AD91F3A55EAD5691011EADE2FB"
	strings:
		$1 = { E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB }
	condition:
		$1 at pe.entry_point
}

rule upack_021 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.21"
		pattern = "BE????????AD8BF8????????33C0AB48ABF7D859F3ABC1E00A????F3ABAD509751588D54855CFF16725A2C037302B0003C0772022C03500FB65FFF??????B3008D1C5B8D9C9D0C100000B00167E3298BD72B550C8A2A33D284E90F95C652FEC68AD08D1493FF165A9F12C0D0E9740E9E1AF274E4B40033C9B501FF560833C9E9070100008B5D0C83C230FF16735383C230FF16721B83C230FF16722B3C07B0097202B00B508BC72B450CB1808A00EBCF83C260FF16875D10730D83C230FF16875D147303875D183C07B0087202B00B50538D957C070000FF560C5B91E99C000000"
	strings:
		$1 = { BE ?? ?? ?? ?? AD 8B F8 ?? ?? ?? ?? 33 C0 AB 48 AB F7 D8 59 F3 AB C1 E0 0A ?? ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF ?? ?? ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 67 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 E9 07 01 00 00 8B 5D 0C 83 C2 30 FF 16 73 53 83 C2 30 FF 16 72 1B 83 C2 30 FF 16 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C B1 80 8A 00 EB CF 83 C2 60 FF 16 87 5D 10 73 0D 83 C2 30 FF 16 87 5D 14 73 03 87 5D 18 3C 07 B0 08 72 02 B0 0B 50 53 8D 95 7C 07 00 00 FF 56 0C 5B 91 E9 9C 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule upack_022b_023b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.22b - 0.23b"
		pattern = "??????????????AD8BF85995F3A5ADB5??F3ABAD509751588D54855CFF1672??2C037302B0003C0772022C03500FB65FFFC1E3??B3008D1C5B8D9C9D0C100000"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 ?? 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 }
	condition:
		$1 at pe.entry_point
}

rule upack_024a_028a {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.24a - 0.28a"
		pattern = "BE88014000AD????95AD91F3A5AD"
	strings:
		$1 = { BE 88 01 40 00 AD ?? ?? 95 AD 91 F3 A5 AD }
	condition:
		$1 at pe.entry_point
}

rule upack_024_031 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.24 - 0.31"
		pattern = "BE????????AD8BF895AD91F3A5AD????F3ABAD509751588D54855CFF1672572C037302B0003C0772022C03500FB65FFF??????B3008D1C5B8D9C9D0C100000B001E3298BD72B550C8A2A33D284E90F95C652FEC68AD08D1493FF165A9F12C0D0E9740E9E1AF274E4B40033C9B501FF560833C9FF6624B1308B5D0C03D1FF16734B03D1FF16721903D1FF1672293C07B0097202B00B508BC72B450C8A00FF662083C260FF16875D10730C03D1FF16875D147303875D183C07B0087202B00B50538BD5035614FF560C5B91FF663C07B0077202B00A50875D10875D14895D188BD5035618FF560C6A035950483BC172028BC1C1E006B1408D9C857C030000FF56043C048BD8725F33DBD1E813DB48439143D3E380F9058D949D7C010000762E80E90433C08B5500D16D088B120FCA2B550403C03B550872078B550840015504FF5610"
	strings:
		$1 = { BE ?? ?? ?? ?? AD 8B F8 95 AD 91 F3 A5 AD ?? ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF ?? ?? ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 E3 29 8B D7 2B 55 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E4 B4 00 33 C9 B5 01 FF 56 08 33 C9 FF 66 24 B1 30 8B 5D 0C 03 D1 FF 16 73 4B 03 D1 FF 16 72 19 03 D1 FF 16 72 29 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C 8A 00 FF 66 20 83 C2 60 FF 16 87 5D 10 73 0C 03 D1 FF 16 87 5D 14 73 03 87 5D 18 3C 07 B0 08 72 02 B0 0B 50 53 8B D5 03 56 14 FF 56 0C 5B 91 FF 66 3C 07 B0 07 72 02 B0 0A 50 87 5D 10 87 5D 14 89 5D 18 8B D5 03 56 18 FF 56 0C 6A 03 59 50 48 3B C1 72 02 8B C1 C1 E0 06 B1 40 8D 9C 85 7C 03 00 00 FF 56 04 3C 04 8B D8 72 5F 33 DB D1 E8 13 DB 48 43 91 43 D3 E3 80 F9 05 8D 94 9D 7C 01 00 00 76 2E 80 E9 04 33 C0 8B 55 00 D1 6D 08 8B 12 0F CA 2B 55 04 03 C0 3B 55 08 72 07 8B 55 08 40 01 55 04 FF 56 10 }
	condition:
		$1 at pe.entry_point
}

rule upack_024b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.24b"
		pattern = "BE88014000AD8BF895AD91F3A5ADB5??F3ABAD509751588D54855CFF1672572C037302B0003C0772022C03500FB65FFFC1E3??B3008D1C5B8D9C9D0C100000B0"
	strings:
		$1 = { BE 88 01 40 00 AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 }
	condition:
		$1 at pe.entry_point
}

rule upack_029b_031bs {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.29b - 0.31b"
		pattern = "BE8801????AD8BF895AD91F3A5ADB5??F3"
	strings:
		$1 = { BE 88 01 ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 }
	condition:
		$1 at pe.entry_point
}

rule upack_029b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.29b"
		pattern = "E9????????42794477696E6740000000504500004C0102????????????????????????????????????????29"
	strings:
		$1 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 29 }
	condition:
		$1 at pe.entry_point
}

rule upack_029 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.29"
		pattern = "BE8801????AD8BF895AD91F3A5ADB5??F3ABAD509751588D54855CFF1672572C037302B0003C0772022C03500FB65FFFC1E3"
	strings:
		$1 = { BE 88 01 ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 }
	condition:
		$1 at pe.entry_point
}

rule upack_030b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.30b"
		pattern = "E9????????42794477696E6740000000504500004C0102????????????????????????????????????????30"
	strings:
		$1 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30 }
	condition:
		$1 at pe.entry_point
}

rule upack_031b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.31b"
		pattern = "E9????????42794477696E6740000000504500004C0102????????????????????????????????????????31"
	strings:
		$1 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 }
	condition:
		$1 at pe.entry_point
}

rule upack_032b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.32b"
		pattern = "E9????????42794477696E6740000000504500004C0102????????????????????????????????????????32"
	strings:
		$1 = { E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 }
	condition:
		$1 at pe.entry_point
}

rule upack_032 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.32"
		pattern = "BE????????????????????????????????????????????8D54855CFF1672572C037302????3C0772022C03500FB65FFF??????????8D1C5B8D9C9D0C100000B001E3298B??????????????????????????????????????????FF165A9F12C0D0E9740E??????????????????B501FF5608????FF6624B1308B5D0C03D1FF16734B03D1FF16721903D1FF1672293C07B0097202B00B508BC72B450C8A00FF662083C260FF16875D10730C03D1FF16875D147303875D183C07B0087202B00B50538BD5035614FF560C5B91FF663C07B0077202B00A50875D10875D14895D188BD5035618FF560C6A035950483BC172028BC1C1E006B1408D9C857C030000FF56043C048BD8725F????D1E813DB48439143D3E380F9058D949D7C010000762E80E904????8B5500D16D088B120FCA2B550403C03B550872078B550840015504FF5610E2E0"
	strings:
		$1 = { BE ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D 54 85 5C FF 16 72 57 2C 03 73 02 ?? ?? 3C 07 72 02 2C 03 50 0F B6 5F FF ?? ?? ?? ?? ?? 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 01 E3 29 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF 16 5A 9F 12 C0 D0 E9 74 0E ?? ?? ?? ?? ?? ?? ?? ?? ?? B5 01 FF 56 08 ?? ?? FF 66 24 B1 30 8B 5D 0C 03 D1 FF 16 73 4B 03 D1 FF 16 72 19 03 D1 FF 16 72 29 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 45 0C 8A 00 FF 66 20 83 C2 60 FF 16 87 5D 10 73 0C 03 D1 FF 16 87 5D 14 73 03 87 5D 18 3C 07 B0 08 72 02 B0 0B 50 53 8B D5 03 56 14 FF 56 0C 5B 91 FF 66 3C 07 B0 07 72 02 B0 0A 50 87 5D 10 87 5D 14 89 5D 18 8B D5 03 56 18 FF 56 0C 6A 03 59 50 48 3B C1 72 02 8B C1 C1 E0 06 B1 40 8D 9C 85 7C 03 00 00 FF 56 04 3C 04 8B D8 72 5F ?? ?? D1 E8 13 DB 48 43 91 43 D3 E3 80 F9 05 8D 94 9D 7C 01 00 00 76 2E 80 E9 04 ?? ?? 8B 55 00 D1 6D 08 8B 12 0F CA 2B 55 04 03 C0 3B 55 08 72 07 8B 55 08 40 01 55 04 FF 56 10 E2 E0 }
	condition:
		$1 at pe.entry_point
}

rule upack_033b_034b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.33b - 0.34b"
		pattern = "????????59F3A583C8FF8BDFAB40AB40"
	strings:
		$1 = { ?? ?? ?? ?? 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 }
	condition:
		$1 at pe.entry_point
}

rule upack_033_034 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.33 - 0.34"
		pattern = "5751588D548358FF16725C2C037302B0003C0772022C03500FB66FFFC1ED??C1E5088D6C6D008DACAB08100000B001E32A8BD72B53088A2A33D284E90F95C652FEC68AD08D549500FF165A9F12C0D0E9740E9E1AF274E3B40033C9B501FF56AC33C9E903010000B1308B6B0803D1FF16735103D1FF16721B03D1FF16722B3C07B0097202B00B508BC72B43088A00E9D500000083C260FF16876B0C730C03D1FF16876B107303876B143C07B0087202B00B50558D9378070000FF56B05D91E9990000003C07B0077202B00A50876B0C876B10896B148D93C00B0000FF56B06A035950483BC172028BC1C1E006B1408DAC8378030000FF56A83C048BE8725C33EDD1E813ED48459145D3E580F9058D94AB78010000762B80E90433C08B53FCD12B8B120FCA2B530403C03B1372068B1340015304FF5688E2E3"
	strings:
		$1 = { 57 51 58 8D 54 83 58 FF 16 72 5C 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 6F FF C1 ED ?? C1 E5 08 8D 6C 6D 00 8D AC AB 08 10 00 00 B0 01 E3 2A 8B D7 2B 53 08 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 54 95 00 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E3 B4 00 33 C9 B5 01 FF 56 AC 33 C9 E9 03 01 00 00 B1 30 8B 6B 08 03 D1 FF 16 73 51 03 D1 FF 16 72 1B 03 D1 FF 16 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 43 08 8A 00 E9 D5 00 00 00 83 C2 60 FF 16 87 6B 0C 73 0C 03 D1 FF 16 87 6B 10 73 03 87 6B 14 3C 07 B0 08 72 02 B0 0B 50 55 8D 93 78 07 00 00 FF 56 B0 5D 91 E9 99 00 00 00 3C 07 B0 07 72 02 B0 0A 50 87 6B 0C 87 6B 10 89 6B 14 8D 93 C0 0B 00 00 FF 56 B0 6A 03 59 50 48 3B C1 72 02 8B C1 C1 E0 06 B1 40 8D AC 83 78 03 00 00 FF 56 A8 3C 04 8B E8 72 5C 33 ED D1 E8 13 ED 48 45 91 45 D3 E5 80 F9 05 8D 94 AB 78 01 00 00 76 2B 80 E9 04 33 C0 8B 53 FC D1 2B 8B 12 0F CA 2B 53 04 03 C0 3B 13 72 06 8B 13 40 01 53 04 FF 56 88 E2 E3 }
	condition:
		$1 at pe.entry_point
}

rule upack_035a {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.35a"
		pattern = "8BF28BCA034C191C03541A20"
	strings:
		$1 = { 8B F2 8B CA 03 4C 19 1C 03 54 1A 20 }
	condition:
		$1 at pe.entry_point
}

rule upack_035 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.35"
		pattern = "588D548358FF16725C2C037302B0003C0772022C03500FB66FFF????????????8D6C6D008DACAB08100000B001E32A8BD72B53088A2A33D284E90F95C652FEC68AD08D549500FF165A9F12C0D0E9740E9E1AF274E3B40033C9B501FF56AC33C9E903010000B1308B6B0803D1FF16735103D1FF16721B03D1FF16722B3C07B0097202B00B508BC72B43088A00E9D500000083C260FF16876B0C730C03D1FF16876B107303876B143C07B0087202B00B50558D9378070000FF56B05D91E9990000003C07B0077202B00A50876B0C876B10896B148D93C00B0000FF56B06A035950483BC172028BC1C1E006B1408DAC8378030000FF56A83C048BE8725C33EDD1E813ED48459145D3E580F9058D94AB78010000762B80E90433C08B53FCD12B8B120FCA2B530403C03B1372068B1340015304FF5688E2E3B104D3E003E88D531833C0554051D3E08BEA91FF56A8"
	strings:
		$1 = { 58 8D 54 83 58 FF 16 72 5C 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 6F FF ?? ?? ?? ?? ?? ?? 8D 6C 6D 00 8D AC AB 08 10 00 00 B0 01 E3 2A 8B D7 2B 53 08 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 54 95 00 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E3 B4 00 33 C9 B5 01 FF 56 AC 33 C9 E9 03 01 00 00 B1 30 8B 6B 08 03 D1 FF 16 73 51 03 D1 FF 16 72 1B 03 D1 FF 16 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 43 08 8A 00 E9 D5 00 00 00 83 C2 60 FF 16 87 6B 0C 73 0C 03 D1 FF 16 87 6B 10 73 03 87 6B 14 3C 07 B0 08 72 02 B0 0B 50 55 8D 93 78 07 00 00 FF 56 B0 5D 91 E9 99 00 00 00 3C 07 B0 07 72 02 B0 0A 50 87 6B 0C 87 6B 10 89 6B 14 8D 93 C0 0B 00 00 FF 56 B0 6A 03 59 50 48 3B C1 72 02 8B C1 C1 E0 06 B1 40 8D AC 83 78 03 00 00 FF 56 A8 3C 04 8B E8 72 5C 33 ED D1 E8 13 ED 48 45 91 45 D3 E5 80 F9 05 8D 94 AB 78 01 00 00 76 2B 80 E9 04 33 C0 8B 53 FC D1 2B 8B 12 0F CA 2B 53 04 03 C0 3B 13 72 06 8B 13 40 01 53 04 FF 56 88 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 A8 }
	condition:
		$1 at pe.entry_point
}

rule upack_036a {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.36a"
		pattern = "ABE2E55D598B7668515946AD85C0"
	strings:
		$1 = { AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0 }
	condition:
		$1 at pe.entry_point
}

rule upack_036b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.36b"
		pattern = "BEE011????FF36E9C30000004801????0B014B45524E454C33322E444C4C"
	strings:
		$1 = { BE E0 11 ?? ?? FF 36 E9 C3 00 00 00 48 01 ?? ?? 0B 01 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C }
	condition:
		$1 at pe.entry_point
}

rule upack_036_01 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.36"
		pattern = "0B01????????????????????????????1810000010000000????????????????0010000000020000????????????36??????????00000000????????????????????????????????????????????????????????????????000000000A0000000000000000000000????????14000000????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????47657450726F634164647265737300FF7608FF760CBE1C01"
	strings:
		$1 = { 0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 10 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 02 00 00 ?? ?? ?? ?? ?? ?? 36 ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 FF 76 08 FF 76 0C BE 1C 01 }
	condition:
		$1 at pe.entry_point
}

rule upack_036_02 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.36"
		pattern = "588D548358FF16725C2C037302B0003C0772022C03500FB66FFF??????C1E5088D6C6D008DACAB08100000B001E32A8BD72B53088A2A33D284E90F95C652FEC68AD08D549500FF165A9F12C0D0E9740E9E1AF274E3B40033C9B501FF561833C9E903010000B1308B6B0803D1FF16735103D1FF16721B03D1FF16722B3C07B0097202B00B508BC72B43088A00E9D500000083C260FF16876B0C730C03D1FF16876B107303876B143C07B0087202B00B50558D9378070000FF561C5D91E9990000003C07B0077202B00A50876B0C876B10896B148D93C00B0000FF561C6A035950483BC172028BC1C1E006B1408DAC8378030000FF56143C048BE8725C33EDD1E813ED48459145D3E580F9058D94AB78010000762B80E90433C08B53FCD12B8B120FCA2B530403C03B1372068B1340015304FF563CE2E3"
	strings:
		$1 = { 58 8D 54 83 58 FF 16 72 5C 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 6F FF ?? ?? ?? C1 E5 08 8D 6C 6D 00 8D AC AB 08 10 00 00 B0 01 E3 2A 8B D7 2B 53 08 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 54 95 00 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E3 B4 00 33 C9 B5 01 FF 56 18 33 C9 E9 03 01 00 00 B1 30 8B 6B 08 03 D1 FF 16 73 51 03 D1 FF 16 72 1B 03 D1 FF 16 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 43 08 8A 00 E9 D5 00 00 00 83 C2 60 FF 16 87 6B 0C 73 0C 03 D1 FF 16 87 6B 10 73 03 87 6B 14 3C 07 B0 08 72 02 B0 0B 50 55 8D 93 78 07 00 00 FF 56 1C 5D 91 E9 99 00 00 00 3C 07 B0 07 72 02 B0 0A 50 87 6B 0C 87 6B 10 89 6B 14 8D 93 C0 0B 00 00 FF 56 1C 6A 03 59 50 48 3B C1 72 02 8B C1 C1 E0 06 B1 40 8D AC 83 78 03 00 00 FF 56 14 3C 04 8B E8 72 5C 33 ED D1 E8 13 ED 48 45 91 45 D3 E5 80 F9 05 8D 94 AB 78 01 00 00 76 2B 80 E9 04 33 C0 8B 53 FC D1 2B 8B 12 0F CA 2B 53 04 03 C0 3B 13 72 06 8B 13 40 01 53 04 FF 56 3C E2 E3 }
	condition:
		$1 at pe.entry_point
}

rule upack_036 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.36"
		pattern = "BE????????FF36E9C3000000"
	strings:
		$1 = { BE ?? ?? ?? ?? FF 36 E9 C3 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule upack_037b_038b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.37b - 0.38b"
		extra = "strip base relocation table option"
		pattern = "531833C0554051D3E08BEA91FF564C33"
	strings:
		$1 = { 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 }
	condition:
		$1 at pe.entry_point
}

rule upack_037b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.37b"
		pattern = "BEB011????AD50FF7634EB7C4801????0B014C6F61644C696272617279410000181000001000000000??????0000????001000000002000004000000000037"
	strings:
		$1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 }
	condition:
		$1 at pe.entry_point
}

rule upack_037_01 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.37"
		pattern = "0B01????????????????????????????1810000010000000????????????????0010000000020000????????????37??????????00000000????????????????????????????????????????????????????????????????000000000A0000000000000000000000????????14000000????????????????????????????????????????????????????????????????????????????????47657450726F63416464726573730000"
	strings:
		$1 = { 0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 10 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 02 00 00 ?? ?? ?? ?? ?? ?? 37 ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 14 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 }
	condition:
		$1 at pe.entry_point
}

rule upack_037_02 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.37"
		pattern = "588D548358FF16725C2C037302B0003C0772022C03500FB66FFF??????C1E5088D6C6D008DACAB08100000B001E32A8BD72B53088A2A33D284E90F95C652FEC68AD08D549500FF165A9F12C0D0E9740E9E1AF274E3B40033C9B501FF565033C9E903010000B1308B6B0803D1FF16735103D1FF16721B03D1FF16722B3C07B0097202B00B508BC72B43088A00E9D500000083C260FF16876B0C730C03D1FF16876B107303876B143C07B0087202B00B50558D9378070000FF56545D91E9990000003C07B0077202B00A50876B0C876B10896B148D93C00B0000FF56546A035950483BC172028BC1C1E006B1408DAC8378030000FF564C3C048BE8725C33EDD1E813ED48459145D3E580F9058D94AB78010000762B80E90433C08B53FCD12B8B120FCA2B530403C03B1372068B1340015304FF5610"
	strings:
		$1 = { 58 8D 54 83 58 FF 16 72 5C 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 6F FF ?? ?? ?? C1 E5 08 8D 6C 6D 00 8D AC AB 08 10 00 00 B0 01 E3 2A 8B D7 2B 53 08 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 54 95 00 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E3 B4 00 33 C9 B5 01 FF 56 50 33 C9 E9 03 01 00 00 B1 30 8B 6B 08 03 D1 FF 16 73 51 03 D1 FF 16 72 1B 03 D1 FF 16 72 2B 3C 07 B0 09 72 02 B0 0B 50 8B C7 2B 43 08 8A 00 E9 D5 00 00 00 83 C2 60 FF 16 87 6B 0C 73 0C 03 D1 FF 16 87 6B 10 73 03 87 6B 14 3C 07 B0 08 72 02 B0 0B 50 55 8D 93 78 07 00 00 FF 56 54 5D 91 E9 99 00 00 00 3C 07 B0 07 72 02 B0 0A 50 87 6B 0C 87 6B 10 89 6B 14 8D 93 C0 0B 00 00 FF 56 54 6A 03 59 50 48 3B C1 72 02 8B C1 C1 E0 06 B1 40 8D AC 83 78 03 00 00 FF 56 4C 3C 04 8B E8 72 5C 33 ED D1 E8 13 ED 48 45 91 45 D3 E5 80 F9 05 8D 94 AB 78 01 00 00 76 2B 80 E9 04 33 C0 8B 53 FC D1 2B 8B 12 0F CA 2B 53 04 03 C0 3B 13 72 06 8B 13 40 01 53 04 FF 56 10 }
	condition:
		$1 at pe.entry_point
}

rule upack_037_03 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.37"
		pattern = "BE????????AD50FF????EB"
	strings:
		$1 = { BE ?? ?? ?? ?? AD 50 FF ?? ?? EB }
	condition:
		$1 at pe.entry_point
}

rule upack_038b {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.38b"
		pattern = "BEB011????AD50FF7634EB7C4801????0B014C6F61644C696272617279410000181000001000000000??????0000????001000000002000004000000000038"
	strings:
		$1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 }
	condition:
		$1 at pe.entry_point
}

rule upack_038 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.38"
		pattern = "588D548358FF16725B2C037302B0003C0772022C03500FB66FFF??????69ED000C00008DAC2B08100000B001E32A8BD72B53088A2A33D284E90F95C652FEC68AD08D549500FF165A9F12C0D0E9740E9E1AF274E3B40033C9B501FF565033C9E9FB00000004F91AC0B1308B6B0803D1FF16734903D1FF16721703D1FF16722724020409508BC72B43088A00E9CD00000083C260FF16876B0C730C03D1FF16876B107303876B142403040850558D9378070000FF56545D91E9950000002403040750876B0C876B10896B148D93C00B0000FF56546A035950483BC172028BC1C1E006B1408DAC8378030000FF564C3C048BE8725C33EDD1E813ED48459145D3E580F9058D94AB78010000762B80E90433C08B53FCD12B8B120FCA2B530403C03B1372068B1340015304FF5610"
	strings:
		$1 = { 58 8D 54 83 58 FF 16 72 5B 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 6F FF ?? ?? ?? 69 ED 00 0C 00 00 8D AC 2B 08 10 00 00 B0 01 E3 2A 8B D7 2B 53 08 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 54 95 00 FF 16 5A 9F 12 C0 D0 E9 74 0E 9E 1A F2 74 E3 B4 00 33 C9 B5 01 FF 56 50 33 C9 E9 FB 00 00 00 04 F9 1A C0 B1 30 8B 6B 08 03 D1 FF 16 73 49 03 D1 FF 16 72 17 03 D1 FF 16 72 27 24 02 04 09 50 8B C7 2B 43 08 8A 00 E9 CD 00 00 00 83 C2 60 FF 16 87 6B 0C 73 0C 03 D1 FF 16 87 6B 10 73 03 87 6B 14 24 03 04 08 50 55 8D 93 78 07 00 00 FF 56 54 5D 91 E9 95 00 00 00 24 03 04 07 50 87 6B 0C 87 6B 10 89 6B 14 8D 93 C0 0B 00 00 FF 56 54 6A 03 59 50 48 3B C1 72 02 8B C1 C1 E0 06 B1 40 8D AC 83 78 03 00 00 FF 56 4C 3C 04 8B E8 72 5C 33 ED D1 E8 13 ED 48 45 91 45 D3 E5 80 F9 05 8D 94 AB 78 01 00 00 76 2B 80 E9 04 33 C0 8B 53 FC D1 2B 8B 12 0F CA 2B 53 04 03 C0 3B 13 72 06 8B 13 40 01 53 04 FF 56 10 }
	condition:
		$1 at pe.entry_point
}

rule upack_039_0399 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.39 - 0.399"
		pattern = "588D548358FF16724F04FD1AD222C23C0773F6500FB66FFF??????6669ED00038DACAB0810000057B001E31F2B7B08840F0F95C4FEC48D548500FF1612C0D0E9740E2AE080E40175E633C9B501FF565033C95FE9F200000004F91AC0B13024038B6B08040803D1FF16734203D1FF16721403D1FF1672240C01508BC72B4308B1808A00EBCE83C260FF16876B0C730C03D1FF16876B107303876B1450558D9378070000FF56545D91E98F00000048876B0C50876B108D93C00B0000896B14FF56546A035950483BC172028BC1B140F6E18DAC8378030000FF564C3C048BE8725A33EDD1E883D5024891D3E580F9058D94AB78010000762B80E90433C08B53FCD12B8B120FCA2B530403C03B1372068B1340015304FF"
	strings:
		$1 = { 58 8D 54 83 58 FF 16 72 4F 04 FD 1A D2 22 C2 3C 07 73 F6 50 0F B6 6F FF ?? ?? ?? 66 69 ED 00 03 8D AC AB 08 10 00 00 57 B0 01 E3 1F 2B 7B 08 84 0F 0F 95 C4 FE C4 8D 54 85 00 FF 16 12 C0 D0 E9 74 0E 2A E0 80 E4 01 75 E6 33 C9 B5 01 FF 56 50 33 C9 5F E9 F2 00 00 00 04 F9 1A C0 B1 30 24 03 8B 6B 08 04 08 03 D1 FF 16 73 42 03 D1 FF 16 72 14 03 D1 FF 16 72 24 0C 01 50 8B C7 2B 43 08 B1 80 8A 00 EB CE 83 C2 60 FF 16 87 6B 0C 73 0C 03 D1 FF 16 87 6B 10 73 03 87 6B 14 50 55 8D 93 78 07 00 00 FF 56 54 5D 91 E9 8F 00 00 00 48 87 6B 0C 50 87 6B 10 8D 93 C0 0B 00 00 89 6B 14 FF 56 54 6A 03 59 50 48 3B C1 72 02 8B C1 B1 40 F6 E1 8D AC 83 78 03 00 00 FF 56 4C 3C 04 8B E8 72 5A 33 ED D1 E8 83 D5 02 48 91 D3 E5 80 F9 05 8D 94 AB 78 01 00 00 76 2B 80 E9 04 33 C0 8B 53 FC D1 2B 8B 12 0F CA 2B 53 04 03 C0 3B 13 72 06 8B 13 40 01 53 04 FF }
	condition:
		$1 at pe.entry_point
}

rule upack_039f_01 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.39f"
		pattern = "5610E2E3B104D3E003E88D531833C0554051D3E08BEA91"
	strings:
		$1 = { 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 }
	condition:
		$1 at pe.entry_point
}

rule upack_039f_02 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.39f"
		pattern = "FF7638AD508B3EBEF0??????6A2759F3A5FF760483C8FF"
	strings:
		$1 = { FF 76 38 AD 50 8B 3E BE F0 ?? ?? ?? 6A 27 59 F3 A5 FF 76 04 83 C8 FF }
	condition:
		$1 at pe.entry_point
}

rule upack_039 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.39"
		pattern = "????????????????????E90602000033C95E870EE3F42BF18BDEAD2BD8AD03C35097AD91F3A55EAD5691011EADE2FB"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB }
	condition:
		$1 at pe.entry_point
}

rule upack_0399_01 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.399"
		pattern = "0B01????????????????????????????1810000010000000????????????????0010000000020000????????????3A00040000000000000000????000002000000000000??0000000000100000??00000000100000100000000000000A0000000000000000000000EE????001400000000????00????0000FF7638AD508B3EBEF0????006A2759F3A5FF760483C8FF8BDFABEB1C0000000047657450726F63416464726573730000??????00??00000040AB40B104F3ABC1E00AB5"
	strings:
		$1 = { 0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 10 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 02 00 00 ?? ?? ?? ?? ?? ?? 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? 00 00 02 00 00 00 00 00 00 ?? 00 00 00 00 00 10 00 00 ?? 00 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE ?? ?? 00 14 00 00 00 00 ?? ?? 00 ?? ?? 00 00 FF 76 38 AD 50 8B 3E BE F0 ?? ?? 00 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? 00 ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 }
	condition:
		$1 at pe.entry_point
}

rule upack_0399_02 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.399"
		pattern = "BEB011????AD50FF7634EB7C4801????0B014C6F61644C696272617279410000181000001000000000??????0000????00100000000200000400000000003A"
	strings:
		$1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A }
	condition:
		$1 at pe.entry_point
}

rule upack_0399_03 {
	meta:
		tool = "P"
		name = "Upack"
		version = "0.399"
		pattern = "60E809000000????????E90602000033C95E870EE3F42BF18BDEAD2BD8AD03C35097AD91F3A55EAD5691011EADE2FBAD8D6E10015D008D7D1CB5??F3AB5EAD53505197588D54855CFF1672572C037302B0003C0772022C03500FB65FFFC1E3??B3008D1C"
	strings:
		$1 = { 60 E8 09 00 00 00 ?? ?? ?? ?? E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C }
	condition:
		$1 at pe.entry_point
}

rule upolyx_05_01 {
	meta:
		tool = "P"
		name = "UPolyX"
		version = "0.5"
		pattern = "558BEC??00BD46008B??B9??00000080????51????????00????????????????????????????????????????????????????0000000000000000000000000000000000000000000000000000000000000000000000"
	strings:
		$1 = { 55 8B EC ?? 00 BD 46 00 8B ?? B9 ?? 00 00 00 80 ?? ?? 51 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule upolyx_05_02 {
	meta:
		tool = "P"
		name = "UPolyX"
		version = "0.5"
		pattern = "83EC0489142459BA??00000052????????????????????????????????????????????????????????????????????????????????????????????????????????????????00??????????????????????????00"
	strings:
		$1 = { 83 EC 04 89 14 24 59 BA ?? 00 00 00 52 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule upolyx_05_03 {
	meta:
		tool = "P"
		name = "UPolyX"
		version = "0.5"
		pattern = "BB00BD460083EC04891C24??B9??0000008033????????????00??????????????????????????00????????????????????????000000000000000000000000000000000000000000000000000000000000000000"
	strings:
		$1 = { BB 00 BD 46 00 83 EC 04 89 1C 24 ?? B9 ?? 00 00 00 80 33 ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule upolyx_05_04 {
	meta:
		tool = "P"
		name = "UPolyX"
		version = "0.5"
		pattern = "E8000000005983C10751C3C3??00BD460083EC0489??24B9??00000081????????00??????????????????????????????????????????000??00BD4600??B9??000000??????????????????????????????????????????????????????0000000000000000000000000000000000000000000000000000000000000000000000?"
	strings:
		$1 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 ?? 00 BD 46 00 83 EC 04 89 ?? 24 B9 ?? 00 00 00 81 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 0? ?0 0B D4 60 0? ?B 9? ?0 00 00 0? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0? }
	condition:
		$1 at pe.entry_point
}

rule upolyx_05_05 {
	meta:
		tool = "P"
		name = "UPolyX"
		version = "0.5"
		pattern = "E8000000005983C10751C3C3??00BD460083EC0489??24B9??00000081????????00??????????????????????????????????????????000000000000000000000000000000000000000000000000000000000000"
	strings:
		$1 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 ?? 00 BD 46 00 83 EC 04 89 ?? 24 B9 ?? 00 00 00 81 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule upolyx_05_06 {
	meta:
		tool = "P"
		name = "UPolyX"
		version = "0.5"
		pattern = "EB01C3??00BD4600????????????????????????????????????????????????????????????????????????????????????????????00000000000000000000000000000000000000000000000000000000000000"
	strings:
		$1 = { EB 01 C3 ?? 00 BD 46 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule upx_eclipse_layer {
	meta:
		tool = "P"
		name = "UPX"
		extra = "+ ECLiPSE layer"
		pattern = "B8????????B9????????33D2EB010F56EB010FE803000000EB010FEB010F5EEB01"
	strings:
		$1 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }
	condition:
		$1 at pe.entry_point
}

rule upx_060_061 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.60 - 0.61"
		pattern = "60E8000000005883E83D508DB8??????FF578DB0E8"
	strings:
		$1 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 8D B0 E8 }
	condition:
		$1 at pe.entry_point
}

rule upx_062_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.62"
		pattern = "807C2408010F859501000060E80000000058"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 58 }
	condition:
		$1 at pe.entry_point
}

rule upx_062_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.62"
		pattern = "60E8000000005883E83D508DB8??????FF57668187????????????8DB0F001????83CDFF31DB909090EB0890908A064688074701DB7507"
	strings:
		$1 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 F0 01 ?? ?? 83 CD FF 31 DB 90 90 90 EB 08 90 90 8A 06 46 88 07 47 01 DB 75 07 }
	condition:
		$1 at pe.entry_point
}

rule upx_070 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.70"
		pattern = "60E8000000005883E83D508DB8??????FF57668187????????????8DB0EC01????83CDFF31DBEB07908A064688074701DB7507"
	strings:
		$1 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 ?? ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 8D B0 EC 01 ?? ?? 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75 07 }
	condition:
		$1 at pe.entry_point
}

rule upx_071 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.71"
		pattern = "807C2408010F859501000060E80000000083"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83 }
	condition:
		$1 at pe.entry_point
}

rule upx_072 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.72"
		pattern = "60E8????????83????31DB5E8D??????????5766????????????????81??????????EB"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 83 ?? ?? 31 DB 5E 8D ?? ?? ?? ?? ?? 57 66 ?? ?? ?? ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? EB }
	condition:
		$1 at pe.entry_point
}

rule upx_0761 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.76.1"
		pattern = "60BE????????8D??????????66????????????5783????31DBEB"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 57 83 ?? ?? 31 DB EB }
	condition:
		$1 at pe.entry_point
}

rule upx_080_084 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.80 - 0.84"
		pattern = "????????????????????????????????????????????????8A064688074701DB75078B1E83EEFC11DB72EDB801??????01DB75078B1E83EEFC11DB11C001DB77EF75098B1E83EEFC"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF 75 09 8B 1E 83 EE FC }
	condition:
		$1 at pe.entry_point
}

rule upx_080_or_higher_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.80 or higher"
		pattern = "8A06??????470?DB75078B1E83EEFC????72E?????????????DB75078B1E83EEFC??????C00?DB????????8B1E83EEFC"
	strings:
		$1 = { 8A 06 ?? ?? ?? 47 0? DB 75 07 8B 1E 83 EE FC ?? ?? 72 E? ?? ?? ?? ?? ?? ?? DB 75 07 8B 1E 83 EE FC ?? ?? ?? C0 0? DB ?? ?? ?? ?? 8B 1E 83 EE FC }
	condition:
		$1 in (pe.entry_point .. pe.entry_point + 192)
}

rule upx_080_or_higher_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.80 or higher"
		pattern = "8A06??????4701DB75078B1E83EEFC????????72E?????????????DB75078B1E83EEFC??????C00?DB????????8B1E83EEFC"
	strings:
		$1 = { 8A 06 ?? ?? ?? 47 01 DB 75 07 8B 1E 83 EE FC ?? ?? ?? ?? 72 E? ?? ?? ?? ?? ?? ?? DB 75 07 8B 1E 83 EE FC ?? ?? ?? C0 0? DB ?? ?? ?? ?? 8B 1E 83 EE FC }
	condition:
		$1 in (pe.entry_point .. pe.entry_point + 192)
}

rule upx_080_or_higher_03 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.80 or higher"
		pattern = "8A06??????4701DB75088B1E83EEFC??????72E?????????????DB75088B1E83EEFC????????C00?DB????????8B1E83EEFC"
	strings:
		$1 = { 8A 06 ?? ?? ?? 47 01 DB 75 08 8B 1E 83 EE FC ?? ?? ?? 72 E? ?? ?? ?? ?? ?? ?? DB 75 08 8B 1E 83 EE FC ?? ?? ?? ?? C0 0? DB ?? ?? ?? ?? 8B 1E 83 EE FC }
	condition:
		$1 in (pe.entry_point .. pe.entry_point + 192)
}

rule upx_081_084_modf {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.81 - 0.84 modified"
		pattern = "01DB??078B1E83EEFC11DB??EDB80100000001DB??078B1E83EEFC11DB11C001DB77EF"
	strings:
		$1 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 77 EF }
	condition:
		$1 at pe.entry_point
}

rule upx_089_3xx {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.89 - 3.xx"
		pattern = "60BE????????8DBE"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE }
	condition:
		$1 at pe.entry_point
}

rule upx_0896_102_105_122_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.89.6 - 1.02, 1.05 - 1.22"
		extra = "Delphi stub"
		pattern = "60BE????????8DBE????????C787????????????????5783CDFFEB0E????????8A064688074701DB75078B"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF EB 0E ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B }
	condition:
		$1 at pe.entry_point
}

rule upx_0896_102_105_122_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.89.6 - 1.02, 1.05 - 1.22"
		pattern = "807C2408010F85??????0060BE????????8DBE????????5783CDFF"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
	condition:
		$1 at pe.entry_point
}

rule upx_0896_102_105_122_03 {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.89.6 - 1.02, 1.05 - 1.22"
		pattern = "????????????????????????????????????????????????8A064688074701DB75078B1E83EEFC11DB72EDB801??????01DB75078B1E83EEFC11DB11C001DB73??75??8B1E83EEFC"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 ?? ?? ?? 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }
	condition:
		$1 at pe.entry_point
}

rule upx_0896_102_105_122_modf {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.89.6 - 1.02, 1.05 - 1.22 modified"
		pattern = "01DB??078B1E83EEFC11DB??EDB80100000001DB??078B1E83EEFC11DB11C001DB73??75"
	strings:
		$1 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 }
	condition:
		$1 at pe.entry_point
}

rule upx_103_104_modf {
	meta:
		tool = "P"
		name = "UPX"
		version = "1.03 - 1.04 modified"
		pattern = "01DB??078B1E83EEFC11DB8A07??EBB80100000001DB??078B1E83EEFC11DB11C001DB73EF"
	strings:
		$1 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }
	condition:
		$1 at pe.entry_point
}

rule upx_103_104 {
	meta:
		tool = "P"
		name = "UPX"
		version = "1.03 - 1.04"
		pattern = "????????????????????????????????????????????????8A064688074701DB75078B1E83EEFC11DB8A0772EBB80100000001DB75078B1E83EEFC11DB11C001DB73??75??8B1E83EEFC"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }
	condition:
		$1 at pe.entry_point
}

rule upx_12 {
	meta:
		tool = "P"
		name = "UPX"
		version = "1.2"
		pattern = "60BE????????8DBE????????5783CDFFEB05A401DB75078B1E83EEFC11DB72F231C04001DB75078B1E83EEFC11DB11C001DB75078B1E83EEFC11DB73E631C983"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 05 A4 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 F2 31 C0 40 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 E6 31 C9 83 }
	condition:
		$1 at pe.entry_point
}

rule upx_121 {
	meta:
		tool = "P"
		name = "UPX"
		version = "1.21"
		pattern = "60BE????????8DBE????????668187??????000?005783CDFFEB0F90909090908A064688074701DB75078B1E83EEFC11DB72"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 66 81 87 ?? ?? ?? 00 0? 00 57 83 CD FF EB 0F 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 }
	condition:
		$1 at pe.entry_point
}

rule upx_12x {
	meta:
		tool = "P"
		name = "UPX"
		version = "1.2x"
		pattern = "60BE????????8DBE????????5783CDFFEB109090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }
	condition:
		$1 at pe.entry_point
}

rule upx_20 {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.0"
		pattern = "55FF96????????09C07407890383C304EB??FF96????????8BAE????????8DBE00F0FFFFBB0010000050546A045357FFD58D87????000080207F8060287F585054505357FFD558618D4424806A0039C475FA83EC80E9"
	strings:
		$1 = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }
	condition:
		$1 at pe.entry_point
}

rule upx_290_lzma_delphi_stub {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.90 [LZMA]"
		extra = "Delphi stub"
		pattern = "60BE????????8DBE????????C787????????????????5783CDFF89E58D9C24????????31C05039DC75FB46465368????????5783C3045368????????5683C304"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 }
	condition:
		$1 at pe.entry_point
}

rule upx_290_lzma_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.90 [LZMA]"
		pattern = "60BE????????8DBE????????5783CDFF89E58D9C24????????31C05039DC75FB46465368????????5783C3045368????????5683C3045350C703????????9090"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 }
	condition:
		$1 at pe.entry_point
}

rule upx_290_lzma_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.90 [LZMA]"
		pattern = "60BE????????8DBE????????5783CDFFEB109090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
	condition:
		$1 at pe.entry_point
}

rule upx_291_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.91"
		pattern = "680004F50FE80200000050C35589E581EC0C020000C785F4FDFFFF48757920C785F8FDFFFF76616D2166C785FCFDFFFF2121"
	strings:
		$1 = { 68 00 04 F5 0F E8 02 00 00 00 50 C3 55 89 E5 81 EC 0C 02 00 00 C7 85 F4 FD FF FF 48 75 79 20 C7 85 F8 FD FF FF 76 61 6D 21 66 C7 85 FC FD FF FF 21 21 }
	condition:
		$1 at pe.entry_point
}

rule upx_291_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.91"
		pattern = "E8100000006AFF6A006823010000E80A00000050C3C8000004C958EBE85589E581ECF4030000C7850CFCFFFF31323334"
	strings:
		$1 = { E8 10 00 00 00 6A FF 6A 00 68 23 01 00 00 E8 0A 00 00 00 50 C3 C8 00 00 04 C9 58 EB E8 55 89 E5 81 EC F4 03 00 00 C7 85 0C FC FF FF 31 32 33 34 }
	condition:
		$1 at pe.entry_point
}

rule upx_293_300_lzma {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.93 - 3.00 [LZMA]"
		pattern = "60BE????????8DBE????????5789E58D9C24????????31C05039DC75FB46465368????????5783C3045368????????5683C3045350C703030002009090909090"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule upx_30_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.0"
		pattern = "5557565383EC7C8B942490000000C744247400000000C6442473008BAC249C0000008D420489442478B8010000000FB64A0289C3D3E389D949894C246C0FB64A01D3E048894424688B8424A80000000FB632"
	strings:
		$1 = { 55 57 56 53 83 EC 7C 8B 94 24 90 00 00 00 C7 44 24 74 00 00 00 00 C6 44 24 73 00 8B AC 24 9C 00 00 00 8D 42 04 89 44 24 78 B8 01 00 00 00 0F B6 4A 02 89 C3 D3 E3 89 D9 49 89 4C 24 6C 0F B6 4A 01 D3 E0 48 89 44 24 68 8B 84 24 A8 00 00 00 0F B6 32 }
	condition:
		$1 in (pe.entry_point + 48 .. pe.entry_point + 80)
}

rule upx_30_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.0"
		pattern = "E8????????5883D80589C383C3308B433905000040008B4B3D89C689C78CD88EC0B400AC30E088C4AAE2F88B430850C3"
	strings:
		$1 = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 83 C3 30 8B 43 39 05 00 00 40 00 8B 4B 3D 89 C6 89 C7 8C D8 8E C0 B4 00 AC 30 E0 88 C4 AA E2 F8 8B 43 08 50 C3 }
	condition:
		$1 at pe.entry_point
}

rule upx_modofied_stub_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified stub"
		pattern = "01DB078B1E83EEFC11DBEDB80100000001DB078B1E83EEFC11DB11C001DB730B"
	strings:
		$1 = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }
	condition:
		$1 at pe.entry_point
}

rule upx_modofied_stub_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified stub"
		pattern = "60BE????????8DBE????????5783CDFFFCB28031DBA4B302E86D00000073F631C9E864000000731C31C0E85B0000007323B30241B010E84F00000010C073F7753FAAEBD4E84D00000029D97510E842000000EB28ACD1E8744D11C9EB1C9148C1E008ACE82C0000003D007D0000730A80FC05730683F87F770241419589E8B3015689FE29C6F3A45EEB8E00D275058A164610D2C331C941E8EEFFFFFF11C9E8E7FFFFFF72F2C331"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 }
	condition:
		$1 at pe.entry_point
}

rule upx_modofied_stub_03 {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified stub"
		pattern = "60BE????????8DBE????????5783CDFFFCB280E8000000005B83C366A4FFD373FB31C9FFD3731431C0FFD3731D41B010FFD310C073FA753CAAEBE2E84A00000049E210E840000000EB28ACD1E8744511C9EB1C9148C1E008ACE82A0000003D007D0000730A80FC05730683F87F770241419589E85689FE29C6F3A45EEB9F00D275058A164610D2C331C941FFD311C9FFD372F8C331C031DB31C95E89F7B9????????8A07472CE8"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2A 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 56 89 FE 29 C6 F3 A4 5E EB 9F 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 FF D3 11 C9 FF D3 72 F8 C3 31 C0 31 DB 31 C9 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 }
	condition:
		$1 at pe.entry_point
}

rule upx_modofied_stub_04 {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified stub"
		pattern = "79070FB707475047B95748F2AE55FF9684??000009C07407890383C304EBD8FF9688??000061E9??????FF"
	strings:
		$1 = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 ?? ?? ?? FF }
	condition:
		$1 at pe.entry_point
}

rule upx_modified_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified"
		pattern = "558BEC83C4F860C645FF00C745F8000000008B7D088B750C8B55108B5D1C33C9EB2C8BC103C33B452077735156"
	strings:
		$1 = { 55 8B EC 83 C4 F8 60 C6 45 FF 00 C7 45 F8 00 00 00 00 8B 7D 08 8B 75 0C 8B 55 10 8B 5D 1C 33 C9 EB 2C 8B C1 03 C3 3B 45 20 77 73 51 56 }
	condition:
		$1 in (pe.entry_point .. pe.entry_point + 192)
}

rule upx_modified_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified"
		pattern = "807C2408010F85??01000060BE00????108DBE00????FF5783CDFFEB0F9090908A0634554688074701DB750950B020E8??0000005872E9B80100000050B001E8"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 BE 00 ?? ?? 10 8D BE 00 ?? ?? FF 57 83 CD FF EB 0F 90 90 90 8A 06 34 55 46 88 07 47 01 DB 75 09 50 B0 20 E8 ?? 00 00 00 58 72 E9 B8 01 00 00 00 50 B0 01 E8 }
	condition:
		$1 at pe.entry_point
}

rule upx_modified_03 {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified"
		pattern = "E800000000558B6C2404816C2404????0000E8????00008BC8E8??0100002BC13D000100000F83??0000008B5C240881E300F0FFFF81ED05104000803B4D7513"
	strings:
		$1 = { E8 00 00 00 00 55 8B 6C 24 04 81 6C 24 04 ?? ?? 00 00 E8 ?? ?? 00 00 8B C8 E8 ?? 01 00 00 2B C1 3D 00 01 00 00 0F 83 ?? 00 00 00 8B 5C 24 08 81 E3 00 F0 FF FF 81 ED 05 10 40 00 80 3B 4D 75 13 }
	condition:
		$1 at pe.entry_point
}

rule upx_10x_protector {
	meta:
		tool = "P"
		name = "UPX"
		version = "1.0x Protector"
		pattern = "EB??????????8A064688074701DB75078B1E83EEFC11DB"
	strings:
		$1 = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }
	condition:
		$1 at pe.entry_point
}

rule upx_10_inliner {
	meta:
		tool = "P"
		name = "UPX"
		version = "1.0 Inliner"
		pattern = "9C60E8000000005DB8B38540002DAC8540002BE88DB5D5FEFFFF8B0683F80074118DB5E1FEFFFF8B0683F8010F84F1010000C706010000008BD58B85B1FEFFFF2BD08995B1FEFFFF0195C9FEFFFF8DB5E5FEFFFF01168B368BFD606A40680010000068001000006A00FF9505FFFFFF85C00F84060300008985C5FEFFFFE8000000005BB93189400081E92E86400003D95053E83D0200006103BDA9FEFFFF8BDF833F00750A83C7"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 05 FF FF FF 85 C0 0F 84 06 03 00 00 89 85 C5 FE FF FF E8 00 00 00 00 5B B9 31 89 40 00 81 E9 2E 86 40 00 03 D9 50 53 E8 3D 02 00 00 61 03 BD A9 FE FF FF 8B DF 83 3F 00 75 0A 83 C7 }
	condition:
		$1 at pe.entry_point
}

rule upx_upxshit_001_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "UPX$HiT 0.0.1"
		pattern = "94BC??????00B9??00000080340C??E2FA94FFE061"
	strings:
		$1 = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }
	condition:
		$1
}

rule upx_upxshit_001_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "UPX$HiT 0.0.1"
		pattern = "E2FA94FFE06100000000000000"
	strings:
		$1 = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }
	condition:
		$1
}

rule upx_upxshit_001_03 {
	meta:
		tool = "P"
		name = "UPX"
		version = "UPX$HiT 0.0.1"
		pattern = "E8????????5E83C6??AD89C7AD89C1AD300747E2??ADFFE0C3"
	strings:
		$1 = { E8 ?? ?? ?? ?? 5E 83 C6 ?? AD 89 C7 AD 89 C1 AD 30 07 47 E2 ?? AD FF E0 C3 }
	condition:
		$1 at pe.entry_point
}

rule upx_upxshit_006 {
	meta:
		tool = "P"
		name = "UPX"
		version = "UPX$HiT 0.06"
		pattern = "B8????4300B915000000803408??E2FAE9D6FFFFFF"
	strings:
		$1 = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule upx_306_scrambler {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.06 Scrambler"
		pattern = "E8000000005983C10751C3C3BE????????83EC04893424B9800000008136????????50B80400000050033424585883E903E2E9EBD6"
	strings:
		$1 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE ?? ?? ?? ?? 83 EC 04 89 34 24 B9 80 00 00 00 81 36 ?? ?? ?? ?? 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6 }
	condition:
		$1 at pe.entry_point
}

rule upx_1x_scrambler_rc {
	meta:
		tool = "P"
		name = "UPX"
		version = "1.x Scrambler RC"
		pattern = "9061BE????????8DBE????????5783CDFF"
	strings:
		$1 = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
	condition:
		$1 at pe.entry_point
}

rule upx_upxcrypter {
	meta:
		tool = "P"
		name = "UPX"
		version = "UPXcrypter"
		pattern = "BF??????0081FF??????007410812F??00000083C704BB05????00FFE3BE??????00FFE600000000"
	strings:
		$1 = { BF ?? ?? ?? 00 81 FF ?? ?? ?? 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 ?? ?? 00 FF E3 BE ?? ?? ?? 00 FF E6 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule upx_upxlock_10_12 {
	meta:
		tool = "P"
		name = "UPX"
		version = "UpxLock 1.0 - 1.2"
		pattern = "60E8000000005D81ED4812400060E82B03000061"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_lzma_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [LZMA]"
		source = "Made by Retdec Team"
		pattern = "60BE????????8DBE????????5789E58D9C24????????31C05039DC75FB46465368????????5783C3045368????????5683C3045350C703????????90909090905557565383EC7C8B942490000000C744247400000000C6442473008BAC249C0000008D420489442478B8010000000FB64A0289C3D3E389D949894C246C0FB64A"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 90 90 90 55 57 56 53 83 EC 7C 8B 94 24 90 00 00 00 C7 44 24 74 00 00 00 00 C6 44 24 73 00 8B AC 24 9C 00 00 00 8D 42 04 89 44 24 78 B8 01 00 00 00 0F B6 4A 02 89 C3 D3 E3 89 D9 49 89 4C 24 6C 0F B6 4A }
	condition:
		$1 at pe.entry_point
}

rule upx_391_lzma_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [LZMA]"
		source = "Made by Retdec Team"
		pattern = "807C2408010F85????????60BE????????8DBE????????5789E58D9C24????????31C05039DC75FB46465368????????5783C3045368????????5683C3045350C703????????90905557565383EC7C8B942490000000C744247400000000C6442473008BAC249C0000008D420489442478B8010000000FB64A0289C3D3E389D949894C246C0FB64A"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 55 57 56 53 83 EC 7C 8B 94 24 90 00 00 00 C7 44 24 74 00 00 00 00 C6 44 24 73 00 8B AC 24 9C 00 00 00 8D 42 04 89 44 24 78 B8 01 00 00 00 0F B6 4A 02 89 C3 D3 E3 89 D9 49 89 4C 24 6C 0F B6 4A }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2b_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "60BE????????8DBE????????5783CDFFEB109090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73EF7509"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB ( 73 | 77 ) EF 75 09 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2b_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "60BE????????8DBE????????57EB10908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73EF7509"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 10 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB ( 73 | 77 ) EF 75 09 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2b_03 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "807C2408010F85????????60BE????????8DBE????????5783CDFFEB0D9090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73EF7509"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0D 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB ( 73 | 77 ) EF 75 09 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2d_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2D]"
		source = "Made by Retdec Team"
		pattern = "60BE????????8DBE????????57EB0B908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB730B7519"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB ( 73 | 77 ) 0B 75 19 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2d_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2D]"
		source = "Made by Retdec Team"
		pattern = "60BE????????8DBE????????5783CDFFEB109090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB730B7519"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB ( 73 | 77 ) 0B 75 19 }
	condition:
		$1 at pe.entry_point
}
rule upx_391_nrv2d_03 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2D]"
		source = "Made by Retdec Team"
		pattern = "807C2408010F85????????60BE????????8DBE????????5783CDFFEB0D9090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB730B7519"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0D 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB ( 73 | 77 ) 0B 75 19 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2e_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2E]"
		source = "Made by Retdec Team"
		pattern = "60BE????????8DBE????????57EB0B908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB730B7528"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB ( 73 | 77 ) 0B 75 28 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2e_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2E]"
		source = "Made by Retdec Team"
		pattern = "60BE????????8DBE????????5783CDFFEB109090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB730B7528"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB ( 73 | 77 ) 0B 75 28 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2e_03 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2E]"
		source = "Made by Retdec Team"
		pattern = "807C2408010F85????????60BE????????8DBE????????5783CDFFEB0D9090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB730B7528"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0D 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB ( 73 | 77 ) 0B 75 28 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2b_modf {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2B] modified"
		source = "Made by Retdec Team"
		pattern = "807C2408010F85????????60BE????????8DBE????????C787????????????????57EB0E909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73EF7509"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2d_modf {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2D] modified"
		source = "Made by Retdec Team"
		pattern = "807C2408010F85????????60BE????????8DBE????????C787????????????????57EB0E909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB730B7519"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2e_modf_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2E] modified"
		source = "Made by Retdec Team"
		pattern = "807C2408010F85????????60BE????????8DBE????????C787????????????????57EB0E909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB730B7528"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 28 }
	condition:
		$1 at pe.entry_point
}

rule upx_391_nrv2e_modf_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.9x [NRV2E] modified"
		source = "Made by Retdec Team"
		pattern = "807C2408010F85????????60BE????????8DBE????????C787????????????????57EB11909090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB730B7528"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 EB 11 90 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 28 }
	condition:
		$1 at pe.entry_point
}

rule upx_394_lzma {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.94 [LZMA]"
		source = "Made by Retdec Team"
		pattern = "60BE00?04?008DBE00?0F?FF5789E58D9C2480C1FFFF31C05039DC75FB46465368????0?005783C3045368????0?005683C3045350C703030002005557565383EC7C8B942490000000C744247400000000C6442473008BAC249C0000008D420489442478"
	strings:
		$1 = { 60 BE 00 ?0 4? 00 8D BE 00 ?0 F? FF 57 89 E5 8D 9C 24 80 C1 FF FF 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? 0? 00 57 83 C3 04 53 68 ?? ?? 0? 00 56 83 C3 04 53 50 C7 03 03 00 02 00 55 57 56 53 83 EC 7C 8B 94 24 90 00 00 00 C7 44 24 74 00 00 00 00 C6 44 24 73 00 8B AC 24 9C 00 00 00 8D 42 04 89 44 24 78 }
	condition:
		$1 at pe.entry_point
}

rule upx_394_nrv2b_01 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.94 [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "60BE00?04?008DBE00?0F?FF5783CDFFEB109090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73EF75098B1E83EEFC11DB73E431C983E803720DC1E0088A064683F0FF747489C501DB7507"
	strings:
		$1 = { 60 BE 00 ?0 4? 00 8D BE 00 ?0 F? FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 }
	condition:
		$1 at pe.entry_point
}

rule upx_394_nrv2b_02 {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.94 [NRV2B]"
		source = "Made by Retdec Team"
		pattern = "60BE00?04?008DBE00?0F?FF57EB0B908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73EF75098B1E83EEFC11DB73E431C983E803720DC1E0088A064683F0FF747489C501DB75078B1E83EEFC11DB11"
	strings:
		$1 = { 60 BE 00 ?0 4? 00 8D BE 00 ?0 F? FF 57 EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 }
	condition:
		$1 at pe.entry_point
}

rule upx_freak {
	meta:
		tool = "P"
		name = "UPXFreak"
		version = "0.1"
		extra = "for Borland Delphi"
		pattern = "BE????????83C601FFE6000000??????0003000000????????001000000000????????0000??F6??00B24F4500??F9??00EF4F4500??F6??008CD14200??56??00??????00??????00??????00??24??00??????00"
	strings:
		$1 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule ussr_031_01 {
	meta:
		tool = "P"
		name = "USSR"
		version = "0.31"
		pattern = "000000000000000000000000400000C02E5553535200000000100000????????00100000????????000000000000000000000000400000C0000000000000000000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 2E 55 53 53 52 00 00 00 00 10 00 00 ?? ?? ?? ?? 00 10 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule ussr_031_02 {
	meta:
		tool = "P"
		name = "USSR"
		version = "0.31"
		pattern = "E8000000005D83C51255C32083B8ED2037EFC6B979379E8CC930C9E301C3BE32??????B0??30068A064681FE00??????7CF3"
	strings:
		$1 = { E8 00 00 00 00 5D 83 C5 12 55 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 8C C9 30 C9 E3 01 C3 BE 32 ?? ?? ?? B0 ?? 30 06 8A 06 46 81 FE 00 ?? ?? ?? 7C F3 }
	condition:
		$1 at pe.entry_point
}

rule vbox_42_mte {
	meta:
		tool = "P"
		name = "VBOX"
		version = "4.2 MTE"
		pattern = "8CE00BC58CE00BC403C5740074008BC5"
	strings:
		$1 = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5 }
	condition:
		$1 at pe.entry_point
}

rule vbox_43_46_01 {
	meta:
		tool = "P"
		name = "VBOX"
		version = "4.3 - 4.6"
		pattern = "????????9003C433C433C52BC533C58BC5????2BC548????0BC086E08CE0????8CE086E003C440"
	strings:
		$1 = { ?? ?? ?? ?? 90 03 C4 33 C4 33 C5 2B C5 33 C5 8B C5 ?? ?? 2B C5 48 ?? ?? 0B C0 86 E0 8C E0 ?? ?? 8C E0 86 E0 03 C4 40 }
	condition:
		$1 at pe.entry_point
}

rule vbox_43_46_02 {
	meta:
		tool = "P"
		name = "VBOX"
		version = "4.3 - 4.6"
		pattern = "8BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC5"
	strings:
		$1 = { 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 }
	condition:
		$1 at pe.entry_point
}

rule vcasm_protector_10e {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.0e"
		pattern = "EB0A5B5650726F746563745D"
	strings:
		$1 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D }
	condition:
		$1 at pe.entry_point
}

rule vcasm_protector_10x_01 {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.0x"
		pattern = "558BEC6AFF68????????68????????64A1000000005064892500000000E803000000"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule vcasm_protector_10x_02 {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.0x"
		pattern = "558BEC6AFF68????????68????????64A1000000005064892500000000E803000000C7840058EB01E983C00750"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }
	condition:
		$1 at pe.entry_point
}

rule vcasm_protector_11_12 {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.1 - 1.2"
		pattern = "EB0B5B5650726F746563745D"
	strings:
		$1 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D }
	condition:
		$1 at pe.entry_point
}

rule vcasm_protector_11 {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.1"
		pattern = "B81AED4100B9ECEB41005051E874000000E8516A00005883E810B9B3000000"
	strings:
		$1 = { B8 1A ED 41 00 B9 EC EB 41 00 50 51 E8 74 00 00 00 E8 51 6A 00 00 58 83 E8 10 B9 B3 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule vcasm_protector_11a_12 {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.1a - 1.2"
		pattern = "00005669727475616C416C6C6F630000000000766361736D5F70726F746563745F323030355F335F31380000000000000000000000000000000000000000000000000033F6E8100000008B642408648F050000000058EB13C78364FF350000000064892500000000ADCD20EB010F31F0EB0C33C8EB03EB090F59740575F851EBF1B904000000E81F000000EBFAE816000000E9EBF8000058EB090F25E8F2FFFFFF0FB94975F1EB05EBF9EBF0D6E807000000C78383C013EB0B58EB02CD2083C002EB01E950C3"
	strings:
		$1 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F 32 30 30 35 5F 33 5F 31 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 }
	condition:
		$1 at pe.entry_point
}

rule vcasm_protector_13x_01 {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.3x"
		pattern = "0000000000????????0000000000000000????????????????0000000000000000000000000000000000000000????????????????????????000000006B65726E656C33322E646C6C0000000047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C6962726172794100608BB424240000008BBC2428000000FCC6C28033DBA4C6C302E8A90000000F83F1FFFFFF33C9E89C0000000F832D00000033C0E88F0000000F8337000000C6C30241C6C010E87D00000010C00F83F3FFFFFF"
	strings:
		$1 = { 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 60 8B B4 24 24 00 00 00 8B BC 24 28 00 00 00 FC C6 C2 80 33 DB A4 C6 C3 02 E8 A9 00 00 00 0F 83 F1 FF FF FF 33 C9 E8 9C 00 00 00 0F 83 2D 00 00 00 33 C0 E8 8F 00 00 00 0F 83 37 00 00 00 C6 C3 02 41 C6 C0 10 E8 7D 00 00 00 10 C0 0F 83 F3 FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule vcasm_protector_13x_02 {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.3x"
		pattern = "E9B9160000558BEC81EC74040000576800000000680000C21468FFFF000068????????9C81????????????????????9D54FF14246800000000680000C21068????????9C81????????????????????9D54FF1424680000000068????????9C81????????????????????9D54FF1424680000000068FFFFC21068????????9C81????????????????????9D54FF1424680000000068????????9C81????????????????????9D54FF14246800000000680000C21468FFFF000068????????9C81????????????????????9D54FF1424680000000068????????9C81????????????????????9D54FF14246800000000"
	strings:
		$1 = { E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 FF FF C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule vcasm_protector_1x {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.x"
		pattern = "EB??5B5650726F746563745D"
	strings:
		$1 = { EB ?? 5B 56 50 72 6F 74 65 63 74 5D }
	condition:
		$1 at pe.entry_point
}

rule vfp_exenc_500 {
	meta:
		tool = "P"
		name = "vfp&exeNc"
		version = "5.00"
		pattern = "60E8000000005D????????????????????????5064FF350000000064892500000000CC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }
	condition:
		$1 at pe.entry_point
}

rule vfp_exenc_600 {
	meta:
		tool = "P"
		name = "vfp&exeNc"
		version = "6.00"
		pattern = "60E8010000006358E8010000007A582D0D1040008D90C110400052508D80491040005D508D85651040005064FF350000000064892500000000CC"
	strings:
		$1 = { 60 E8 01 00 00 00 63 58 E8 01 00 00 00 7A 58 2D 0D 10 40 00 8D 90 C1 10 40 00 52 50 8D 80 49 10 40 00 5D 50 8D 85 65 10 40 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }
	condition:
		$1 at pe.entry_point
}

rule virogen_crypt_075 {
	meta:
		tool = "P"
		name = "Virogen Crypt"
		version = "0.75"
		pattern = "9C55E8EC00000087D55D6087D580BD1527400001"
	strings:
		$1 = { 9C 55 E8 EC 00 00 00 87 D5 5D 60 87 D5 80 BD 15 27 40 00 01 }
	condition:
		$1 at pe.entry_point
}

rule virogens_pe_shrinker_014 {
	meta:
		tool = "P"
		name = "Virogen's PE Shrinker"
		version = "0.14"
		pattern = "9C55E8????????87D55D6087D58D??????????8D??????????5756AD0BC074"
	strings:
		$1 = { 9C 55 E8 ?? ?? ?? ?? 87 D5 5D 60 87 D5 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 57 56 AD 0B C0 74 }
	condition:
		$1 at pe.entry_point
}

rule viseman_uv {
	meta:
		tool = "P"
		name = "VISEMAN"
		pattern = "45534956"
	strings:
		$1 = { 45 53 49 56 }
	condition:
		$1 at pe.entry_point
}

rule visual_protect_uv {
	meta:
		tool = "P"
		name = "Visual Protect"
		pattern = "558BEC51535657C705??????000000000068??????00FF1500????00A3??????0068??????00A1??????0050FF1504????00A3??????006A00FF15??????00A3??????008B0D??????0051E8????000083C4048945FC837DFC007403FF65FC5F"
	strings:
		$1 = { 55 8B EC 51 53 56 57 C7 05 ?? ?? ?? 00 00 00 00 00 68 ?? ?? ?? 00 FF 15 00 ?? ?? 00 A3 ?? ?? ?? 00 68 ?? ?? ?? 00 A1 ?? ?? ?? 00 50 FF 15 04 ?? ?? 00 A3 ?? ?? ?? 00 6A 00 FF 15 ?? ?? ?? 00 A3 ?? ?? ?? 00 8B 0D ?? ?? ?? 00 51 E8 ?? ?? 00 00 83 C4 04 89 45 FC 83 7D FC 00 74 03 FF 65 FC 5F }
	condition:
		$1 at pe.entry_point
}

rule vmprotect_uv_01 {
	meta:
		tool = "P"
		name = "VMProtect"
		pattern = "68????????E8??????00"
	strings:
		$1 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule vmprotect_uv_02 {
	meta:
		tool = "P"
		name = "VMProtect"
		pattern = "68????????E8??????FF"
	strings:
		$1 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? FF }
	condition:
		$1 at pe.entry_point
}

rule vmprotect_07x_08 {
	meta:
		tool = "P"
		name = "VMProtect"
		version = "0.7x - 0.8"
		pattern = "5B20564D50726F74656374207620302E382028432920506F6C7954656368205D"
	strings:
		$1 = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }
	condition:
		$1 at pe.entry_point
}

rule vmprotect_1x {
	meta:
		tool = "P"
		name = "VMProtect"
		version = "1.x"
		pattern = "9C6068000000008B742428BF????????FC89F3033424AC00D8"
	strings:
		$1 = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
	condition:
		$1 at pe.entry_point
}

rule vob_protectcd_uv {
	meta:
		tool = "P"
		name = "VOB ProtectCD"
		pattern = "5F81EF????????BE????40??8B87????????03C657568CA7????????FF108987????????5E5F"
	strings:
		$1 = { 5F 81 EF ?? ?? ?? ?? BE ?? ?? 40 ?? 8B 87 ?? ?? ?? ?? 03 C6 57 56 8C A7 ?? ?? ?? ?? FF 10 89 87 ?? ?? ?? ?? 5E 5F }
	condition:
		$1 at pe.entry_point
}

rule vpacker_uv_01 {
	meta:
		tool = "P"
		name = "VPacker"
		pattern = "00000000FFFFFFFFFFFFFFFF????????????????0000000000000000000000000000000000000000????????????????????????????????????????????????????????????????000000006B65726E656C33322E646C6C0000004765744D6F64756C6548616E646C65410000004C6F61644C6962726172794100000047657450726F63416464726573730000005669727475616C416C6C6F630000005669727475616C467265650000005669727475616C50726F746563740000004865617043726561746500000048656170416C6C6F6300C38D4000558BEC51E828000000"
	strings:
		$1 = { 00 00 00 00 FF FF FF FF FF FF FF FF ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 48 65 61 70 43 72 65 61 74 65 00 00 00 48 65 61 70 41 6C 6C 6F 63 00 C3 8D 40 00 55 8B EC 51 E8 28 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule vpacker_uv_02 {
	meta:
		tool = "P"
		name = "VPacker"
		pattern = "89C6C745E001000000F7030000FFFF75180FB703508B45D850FF55F889078BC3E8??FEFFFF8BD8EB13538B45D850FF55F889078BC3E8??FEFFFF8BD883C704FF45E04E75C48BF3833E0075888B45E48B40100345DC8B551483C220890268008000006A008B45D450FF55EC8B55DC8B423C0345DC83C0048BD883C3148D45E0506A40680010000052FF55E88D4360"
	strings:
		$1 = { 89 C6 C7 45 E0 01 00 00 00 F7 03 00 00 FF FF 75 18 0F B7 03 50 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 EB 13 53 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 83 C7 04 FF 45 E0 4E 75 C4 8B F3 83 3E 00 75 88 8B 45 E4 8B 40 10 03 45 DC 8B 55 14 83 C2 20 89 02 68 00 80 00 00 6A 00 8B 45 D4 50 FF 55 EC 8B 55 DC 8B 42 3C 03 45 DC 83 C0 04 8B D8 83 C3 14 8D 45 E0 50 6A 40 68 00 10 00 00 52 FF 55 E8 8D 43 60 }
	condition:
		$1 at pe.entry_point
}

rule vprotector_uv_01 {
	meta:
		tool = "P"
		name = "VProtector"
		pattern = "000000004B45524E454C33322E646C6C00005553455233322E646C6C000047444933322E646C6C000000000000000047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C69627261727941000000536C65657000000047657456657273696F6E000000476574436F6D6D616E644C696E654100000047657453746172747570496E666F4100000047657441435000000043726561746554687265616400000044656657696E646F7750726F63410000005265676973746572436C61737345784100000043726561746557696E646F7745784100000047657453797374656D4D65747269637300000053686F7757696E646F77000000476574444300000052656C65617365444300000046696E6457696E646F77410000004765744D6573736167654100000044657374726F7957696E646F77000000536574506978656C00000000"
	strings:
		$1 = { 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 47 44 49 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 53 6C 65 65 70 00 00 00 47 65 74 56 65 72 73 69 6F 6E 00 00 00 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 00 00 47 65 74 53 74 61 72 74 75 70 49 6E 66 6F 41 00 00 00 47 65 74 41 43 50 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 47 65 74 44 43 00 00 00 52 65 6C 65 61 73 65 44 43 00 00 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 00 00 44 65 73 74 72 6F 79 57 69 6E 64 6F 77 00 00 00 53 65 74 50 69 78 65 6C 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule vprotector_uv_02 {
	meta:
		tool = "P"
		name = "VProtector"
		pattern = "000000005573657233322E646C6C000000000000000000000000000000000000000047646933322E646C6C0000000000000000000000000000000000000000004B65726E656C33322E646C6C000000000000000000000000000000000000080044656657696E646F7750726F63410000000000000000000000000000000008005265676973746572436C6173734578410000000000000000000000000000080043726561746557696E646F77457841000000000000000000000000000000080047657453797374656D4D6574726963730000000000000000000000000000080053686F7757696E646F7700000000000000000000000000000000000000000800476574444300000000000000000000000000000000000000000000000000080052656C656173654443000000000000000000000000000000000000000000080046696E6457696E646F77410000000000000000000000000000000000000000004765744D6573736167654100"
	strings:
		$1 = { 00 00 00 00 55 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 64 69 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 47 65 74 44 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 52 65 6C 65 61 73 65 44 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 }
	condition:
		$1 at pe.entry_point
}

rule vprotector_0x_12x {
	meta:
		tool = "P"
		name = "VProtector"
		version = "0.x - 1.2x"
		pattern = "00005669727475616C416C6C6F630000000000766361736D5F70726F746563745F????????????????????0000000000000000000000000000000000000000000000000033F6E8100000008B642408648F050000000058EB13C78364FF350000000064892500000000ADCD20EB010F31F0EB0C33C8EB03EB090F59740575F851EBF1B904000000E81F000000EBFAE816000000E9EBF8000058EB090F25E8F2FFFFFF0FB94975F1EB05EBF9EBF0D6E807000000C78383C013EB0B58EB02CD2083C002EB01E950C3"
	strings:
		$1 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 }
	condition:
		$1 at pe.entry_point
}

rule vterminal_10x {
	meta:
		tool = "P"
		name = "Vterminal"
		version = "1.0x"
		pattern = "E8000000005805????????9C50C20400"
	strings:
		$1 = { E8 00 00 00 00 58 05 ?? ?? ?? ?? 9C 50 C2 04 00 }
	condition:
		$1 at pe.entry_point
}

rule vx_acme {
	meta:
		tool = "P"
		name = "Vx:"
		version = "ACME (Clonewar Mutant)"
		pattern = "FCAD3DFFFF7420E6428AC4E642E4610C03E661ADB9401FE2FE"
	strings:
		$1 = { FC AD 3D FF FF 74 20 E6 42 8A C4 E6 42 E4 61 0C 03 E6 61 AD B9 40 1F E2 FE }
	condition:
		$1 at pe.entry_point
}

rule vx_arcv4 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "ARCV.4"
		pattern = "E800005D81ED060181FC4F50740B8DB68601BF000157A4EB111E06"
	strings:
		$1 = { E8 00 00 5D 81 ED 06 01 81 FC 4F 50 74 0B 8D B6 86 01 BF 00 01 57 A4 EB 11 1E 06 }
	condition:
		$1 at pe.entry_point
}

rule vx_august_16th {
	meta:
		tool = "P"
		name = "Vx:"
		version = "August 16th (Iron Maiden)"
		pattern = "BA790203D7B41ACD21B82435CD215F57899D4E028C855002"
	strings:
		$1 = { BA 79 02 03 D7 B4 1A CD 21 B8 24 35 CD 21 5F 57 89 9D 4E 02 8C 85 50 02 }
	condition:
		$1 at pe.entry_point
}

rule vx_backfont900 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Backfont.900"
		pattern = "E8????B430CD213C03????B8????BA????CD2181FA????????BA????8CC0488EC08ED880??????5A????03??????408ED880??????5A????83"
	strings:
		$1 = { E8 ?? ?? B4 30 CD 21 3C 03 ?? ?? B8 ?? ?? BA ?? ?? CD 21 81 FA ?? ?? ?? ?? BA ?? ?? 8C C0 48 8E C0 8E D8 80 ?? ?? ?? 5A ?? ?? 03 ?? ?? ?? 40 8E D8 80 ?? ?? ?? 5A ?? ?? 83 }
	condition:
		$1 at pe.entry_point
}

rule vx_caz1024 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Caz.1204"
		pattern = "E8????5E83EE031E06B8FFFFCD2F3C10"
	strings:
		$1 = { E8 ?? ?? 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10 }
	condition:
		$1 at pe.entry_point
}

rule vx_cih_v12_ttit {
	meta:
		tool = "P"
		name = "Vx:"
		version = "CIH Version 1.2 TTIT (! WIN95CIH !)"
		pattern = "558D??????33DB648703E8????????5B8D"
	strings:
		$1 = { 55 8D ?? ?? ?? 33 DB 64 87 03 E8 ?? ?? ?? ?? 5B 8D }
	condition:
		$1 at pe.entry_point
}

rule vx_compiler {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Compiler"
		pattern = "8CC383C3102E011E??022E031E??02531E"
	strings:
		$1 = { 8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E }
	condition:
		$1 at pe.entry_point
}

rule vx_danish_tiny {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Danish tiny"
		pattern = "33C9B44ECD217302FF??BA??00B8??3DCD21"
	strings:
		$1 = { 33 C9 B4 4E CD 21 73 02 FF ?? BA ?? 00 B8 ?? 3D CD 21 }
	condition:
		$1 at pe.entry_point
}

rule vx_doom666 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Doom.666"
		pattern = "E8??????5E83EE??B8CF7BCD213DCF7B????0E1F81C6????BF????B9????FCF3A4061F06B8????50CBB448BB2C00CD21"
	strings:
		$1 = { E8 ?? ?? ?? 5E 83 EE ?? B8 CF 7B CD 21 3D CF 7B ?? ?? 0E 1F 81 C6 ?? ?? BF ?? ?? B9 ?? ?? FC F3 A4 06 1F 06 B8 ?? ?? 50 CB B4 48 BB 2C 00 CD 21 }
	condition:
		$1 at pe.entry_point
}

rule vx_eddie1028 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Eddie.1028"
		pattern = "E8????5EFC83????81??????4D5A????FA8BE681C4????FB3B??????????5006561EB8FE4BCD2181FFBB55????07??????07B449CD21BBFFFFB448CD21"
	strings:
		$1 = { E8 ?? ?? 5E FC 83 ?? ?? 81 ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E B8 FE 4B CD 21 81 FF BB 55 ?? ?? 07 ?? ?? ?? 07 B4 49 CD 21 BB FF FF B4 48 CD 21 }
	condition:
		$1 at pe.entry_point
}

rule vx_eddie1530 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Eddie.1530"
		pattern = "E8????5E81EE????FC2E????????4D5A????FA8BE681C4????FB3B??????????2E????????5006561E33C0501FC4??????2E????????2E"
	strings:
		$1 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? 50 06 56 1E 33 C0 50 1F C4 ?? ?? ?? 2E ?? ?? ?? ?? 2E }
	condition:
		$1 at pe.entry_point
}

rule vx_eddie1800 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Eddie.1800"
		pattern = "E8????5E81EE????FC2E????????4D5A????FA8BE681C4????FB3B??????????5006561E8BFE33C0508ED8C4??????2E????????2E"
	strings:
		$1 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E 8B FE 33 C0 50 8E D8 C4 ?? ?? ?? 2E ?? ?? ?? ?? 2E }
	condition:
		$1 at pe.entry_point
}

rule vx_eddie2000 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Eddie.2000"
		pattern = "E8????5E81EE????FC2E????????2E????????4D5A????FA8BE681C4????FB3B??????????5006561E8BFE33C0508ED8C5??????B430CD21"
	strings:
		$1 = { E8 ?? ?? 5E 81 EE ?? ?? FC 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 C4 ?? ?? FB 3B ?? ?? ?? ?? ?? 50 06 56 1E 8B FE 33 C0 50 8E D8 C5 ?? ?? ?? B4 30 CD 21 }
	condition:
		$1 at pe.entry_point
}
rule vx_eddie2100 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Eddie.2100"
		pattern = "E8????4F4F0EE8????47471EFF????CBE8????84C0????505356571E06B451CD218EC3??????????????8BF2B42FCD21AC"
	strings:
		$1 = { E8 ?? ?? 4F 4F 0E E8 ?? ?? 47 47 1E FF ?? ?? CB E8 ?? ?? 84 C0 ?? ?? 50 53 56 57 1E 06 B4 51 CD 21 8E C3 ?? ?? ?? ?? ?? ?? ?? 8B F2 B4 2F CD 21 AC }
	condition:
		$1 at pe.entry_point
}

rule vx_eddiebased1745 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Eddie.based.1745"
		pattern = "E8????5E81EE????FC??2E????????4D5A????FA??8BE681??????FB??3B??????????5006??561E8BFE33C0??508ED8"
	strings:
		$1 = { E8 ?? ?? 5E 81 EE ?? ?? FC ?? 2E ?? ?? ?? ?? 4D 5A ?? ?? FA ?? 8B E6 81 ?? ?? ?? FB ?? 3B ?? ?? ?? ?? ?? 50 06 ?? 56 1E 8B FE 33 C0 ?? 50 8E D8 }
	condition:
		$1 at pe.entry_point
}

rule vx_einstein {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Einstein"
		pattern = "0042CD217231B96E0333D2B440CD2172193BC17515B80042"
	strings:
		$1 = { 00 42 CD 21 72 31 B9 6E 03 33 D2 B4 40 CD 21 72 19 3B C1 75 15 B8 00 42 }
	condition:
		$1 at pe.entry_point
}

rule vx_explosion1000 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Explosion.1000"
		pattern = "E8????5E1E065081??????56FCB82135CD212E????????2E????????26????????????74??8CD8488ED8"
	strings:
		$1 = { E8 ?? ?? 5E 1E 06 50 81 ?? ?? ?? 56 FC B8 21 35 CD 21 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 26 ?? ?? ?? ?? ?? ?? 74 ?? 8C D8 48 8E D8 }
	condition:
		$1 at pe.entry_point
}

rule vx_faxfree_topo {
	meta:
		tool = "P"
		name = "Vx:"
		version = "FaxFree.Topo"
		pattern = "FA0633C08EC0B8????26????????508CC826????????50CC589D5826????????5826????????07FB"
	strings:
		$1 = { FA 06 33 C0 8E C0 B8 ?? ?? 26 ?? ?? ?? ?? 50 8C C8 26 ?? ?? ?? ?? 50 CC 58 9D 58 26 ?? ?? ?? ?? 58 26 ?? ?? ?? ?? 07 FB }
	condition:
		$1 at pe.entry_point
}

rule vx_gotcha879 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Gotcha.879"
		pattern = "E8????5B81EB????9CFC2E??????????????8CD805????2E????????502E????????????8BC305????8BF0BF0001B92000F3A40EB8000150B8DADACD21"
	strings:
		$1 = { E8 ?? ?? 5B 81 EB ?? ?? 9C FC 2E ?? ?? ?? ?? ?? ?? ?? 8C D8 05 ?? ?? 2E ?? ?? ?? ?? 50 2E ?? ?? ?? ?? ?? ?? 8B C3 05 ?? ?? 8B F0 BF 00 01 B9 20 00 F3 A4 0E B8 00 01 50 B8 DA DA CD 21 }
	condition:
		$1 at pe.entry_point
}

rule vx_grazzie883 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Grazie.883"
		pattern = "1E0E1F5006BF7003B41ABA7003CD21B447B200BE3204CD21"
	strings:
		$1 = { 1E 0E 1F 50 06 BF 70 03 B4 1A BA 70 03 CD 21 B4 47 B2 00 BE 32 04 CD 21 }
	condition:
		$1 at pe.entry_point
}

rule vx_grunt1family {
	meta:
		tool = "P"
		name = "Vx:"
		version = "GRUNT.1.Family"
		pattern = "01B9??003117"
	strings:
		$1 = { 01 B9 ?? 00 31 17 }
	condition:
		$1 at pe.entry_point
}

rule vx_grunt2family {
	meta:
		tool = "P"
		name = "Vx:"
		version = "GRUNT.2.Family"
		pattern = "48E2F7C3515352E8DDFF5A5B59C3B90000E2FEC3"
	strings:
		$1 = { 48 E2 F7 C3 51 53 52 E8 DD FF 5A 5B 59 C3 B9 00 00 E2 FE C3 }
	condition:
		$1 at pe.entry_point
}

rule vx_grunt4family {
	meta:
		tool = "P"
		name = "Vx:"
		version = "GRUNT.4.Family"
		pattern = "E81C008D9E4101403E8B961403B9EA0087DBF7D0311783C302E2F7C3"
	strings:
		$1 = { E8 1C 00 8D 9E 41 01 40 3E 8B 96 14 03 B9 EA 00 87 DB F7 D0 31 17 83 C3 02 E2 F7 C3 }
	condition:
		$1 at pe.entry_point
}

rule vx_hafen1641 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Hafen.1641"
		pattern = "E8????01??????CECC25????25????25????4051D4??????CC47CA????468ACC4488CC"
	strings:
		$1 = { E8 ?? ?? 01 ?? ?? ?? CE CC 25 ?? ?? 25 ?? ?? 25 ?? ?? 40 51 D4 ?? ?? ?? CC 47 CA ?? ?? 46 8A CC 44 88 CC }
	condition:
		$1 at pe.entry_point
}

rule vx_hafen809 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Hafen.809"
		pattern = "E8????1C??81EE????501E068CC88ED80633C08EC026??????073D"
	strings:
		$1 = { E8 ?? ?? 1C ?? 81 EE ?? ?? 50 1E 06 8C C8 8E D8 06 33 C0 8E C0 26 ?? ?? ?? 07 3D }
	condition:
		$1 at pe.entry_point
}

rule vx_harynato {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Haryanto"
		pattern = "81EB2A018B0F1E5B03CB0E51B9100151CB"
	strings:
		$1 = { 81 EB 2A 01 8B 0F 1E 5B 03 CB 0E 51 B9 10 01 51 CB }
	condition:
		$1 at pe.entry_point
}

rule vx_helloweem1172 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Heloween.1172"
		pattern = "E8????5E81EE????5650060E1F8CC001????01????80????????8B????A3????8A????A2????B8????CD213D"
	strings:
		$1 = { E8 ?? ?? 5E 81 EE ?? ?? 56 50 06 0E 1F 8C C0 01 ?? ?? 01 ?? ?? 80 ?? ?? ?? ?? 8B ?? ?? A3 ?? ?? 8A ?? ?? A2 ?? ?? B8 ?? ?? CD 21 3D }
	condition:
		$1 at pe.entry_point
}

rule vx_horse1776 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Horse.1776"
		pattern = "E8????5D83????061E26????????BF????1E0E1F8BF701EEB9????FCF3A61F1E07"
	strings:
		$1 = { E8 ?? ?? 5D 83 ?? ?? 06 1E 26 ?? ?? ?? ?? BF ?? ?? 1E 0E 1F 8B F7 01 EE B9 ?? ?? FC F3 A6 1F 1E 07 }
	condition:
		$1 at pe.entry_point
}

rule vx_hymn1865 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Hymn.1865"
		pattern = "E8????5E83EE4CFC2E????????4D5A????FA8BE681??????FB3B??????????2E??????????5006561E0E1FB800C5CD21"
	strings:
		$1 = { E8 ?? ?? 5E 83 EE 4C FC 2E ?? ?? ?? ?? 4D 5A ?? ?? FA 8B E6 81 ?? ?? ?? FB 3B ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? 50 06 56 1E 0E 1F B8 00 C5 CD 21 }
	condition:
		$1 at pe.entry_point
}

rule vx_igor {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Igor"
		pattern = "1EB8CD7BCD2181FBCD7B7503E9870033DB0E1F8C"
	strings:
		$1 = { 1E B8 CD 7B CD 21 81 FB CD 7B 75 03 E9 87 00 33 DB 0E 1F 8C }
	condition:
		$1 at pe.entry_point
}
rule vx_involuntary1349 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Involuntary.1349"
		pattern = "??BA????B9????8CDD??8CC8??8ED88EC033F68BFEFC????AD??33C2AB"
	strings:
		$1 = { ?? BA ?? ?? B9 ?? ?? 8C DD ?? 8C C8 ?? 8E D8 8E C0 33 F6 8B FE FC ?? ?? AD ?? 33 C2 AB }
	condition:
		$1 at pe.entry_point
}

rule vx_kbdflags1024 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "KBDflags.1024"
		pattern = "8BEC2E892E2403BC00048CD52E892E22"
	strings:
		$1 = { 8B EC 2E 89 2E 24 03 BC 00 04 8C D5 2E 89 2E 22 }
	condition:
		$1 at pe.entry_point
}

rule vx_keypress1212 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Keypress.1212"
		pattern = "E8????E8????E8????E8????????E8????????E8????????EA????????1E33DB8EDBBB"
	strings:
		$1 = { E8 ?? ?? E8 ?? ?? E8 ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EA ?? ?? ?? ?? 1E 33 DB 8E DB BB }
	condition:
		$1 at pe.entry_point
}

rule vx_kuku448 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Kuku.448"
		pattern = "AE75EDE2F8893E????BA????0E07BF????EB"
	strings:
		$1 = { AE 75 ED E2 F8 89 3E ?? ?? BA ?? ?? 0E 07 BF ?? ?? EB }
	condition:
		$1 at pe.entry_point
}

rule vx_kuku886 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Kuku.886"
		pattern = "061E508CC88ED8BA7003B82425CD21??????????90B42FCD2153"
	strings:
		$1 = { 06 1E 50 8C C8 8E D8 BA 70 03 B8 24 25 CD 21 ?? ?? ?? ?? ?? 90 B4 2F CD 21 53 }
	condition:
		$1 at pe.entry_point
}

rule vx_hi924_modf {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Modification of Hi.924"
		pattern = "505351521E069CB82135CD2153BB????26????49485B"
	strings:
		$1 = { 50 53 51 52 1E 06 9C B8 21 35 CD 21 53 BB ?? ?? 26 ?? ?? 49 48 5B }
	condition:
		$1 at pe.entry_point
}

rule vx_mte {
	meta:
		tool = "P"
		name = "Vx:"
		version = "MTE (non-encrypted)"
		pattern = "F7D980E1FE7502494997A3????03C124FE750248"
	strings:
		$1 = { F7 D9 80 E1 FE 75 02 49 49 97 A3 ?? ?? 03 C1 24 FE 75 02 48 }
	condition:
		$1 at pe.entry_point
}

rule vx_nculi_1688 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Ncu-Li.1688"
		pattern = "0E1EB855AACD213D494C74??0E0E1F07E8"
	strings:
		$1 = { 0E 1E B8 55 AA CD 21 3D 49 4C 74 ?? 0E 0E 1F 07 E8 }
	condition:
		$1 at pe.entry_point
}

rule vx_necropolis {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Necropolis"
		pattern = "50FCAD33C2AB8BD0E2F8"
	strings:
		$1 = { 50 FC AD 33 C2 AB 8B D0 E2 F8 }
	condition:
		$1 at pe.entry_point
}

rule vx_necropolis1963 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Necropolis.1963"
		pattern = "B430CD213C03????B80012CD2F3CFFB8????????B44ABB4001CD21????FA0E17BC????E8????FBA1????0BC0"
	strings:
		$1 = { B4 30 CD 21 3C 03 ?? ?? B8 00 12 CD 2F 3C FF B8 ?? ?? ?? ?? B4 4A BB 40 01 CD 21 ?? ?? FA 0E 17 BC ?? ?? E8 ?? ?? FB A1 ?? ?? 0B C0 }
	condition:
		$1 at pe.entry_point
}

rule vx_noon1163 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Noon.1163"
		pattern = "E8????5B5056B4CBCD213C07????81??????2E????4D5A????BF000189DEFC"
	strings:
		$1 = { E8 ?? ?? 5B 50 56 B4 CB CD 21 3C 07 ?? ?? 81 ?? ?? ?? 2E ?? ?? 4D 5A ?? ?? BF 00 01 89 DE FC }
	condition:
		$1 at pe.entry_point
}

rule vx_november_17768 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "November 17.768"
		pattern = "E8????5E81EE????5033C08ED8803E??????0E1F????FC"
	strings:
		$1 = { E8 ?? ?? 5E 81 EE ?? ?? 50 33 C0 8E D8 80 3E ?? ?? ?? 0E 1F ?? ?? FC }
	condition:
		$1 at pe.entry_point
}

rule vx_number_one {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Number One"
		pattern = "F9073C536D696C653EE8"
	strings:
		$1 = { F9 07 3C 53 6D 69 6C 65 3E E8 }
	condition:
		$1 at pe.entry_point
}

rule vx_phoenix_927 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Phoenix.927"
		pattern = "E800005E81C6????BF0001B90400F3A4E8"
	strings:
		$1 = { E8 00 00 5E 81 C6 ?? ?? BF 00 01 B9 04 00 F3 A4 E8 }
	condition:
		$1 at pe.entry_point
}

rule vx_predator2448 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Predator.2448"
		pattern = "0E1FBF????B8????B9????49????????2AC14F4F????F9CC"
	strings:
		$1 = { 0E 1F BF ?? ?? B8 ?? ?? B9 ?? ?? 49 ?? ?? ?? ?? 2A C1 4F 4F ?? ?? F9 CC }
	condition:
		$1 at pe.entry_point
}

rule vx_quake518 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Quake.518"
		pattern = "1E068CC88ED8??????????????B82135CD2181"
	strings:
		$1 = { 1E 06 8C C8 8E D8 ?? ?? ?? ?? ?? ?? ?? B8 21 35 CD 21 81 }
	condition:
		$1 at pe.entry_point
}

rule vx_sk {
	meta:
		tool = "P"
		name = "Vx:"
		version = "SK"
		pattern = "CD20B80300CD1051E800005E83EE09"
	strings:
		$1 = { CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09 }
	condition:
		$1 at pe.entry_point
}

rule vx_slowload {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Slowload"
		pattern = "03D6B440CD21B8024233D233C9CD218BD6B97801"
	strings:
		$1 = { 03 D6 B4 40 CD 21 B8 02 42 33 D2 33 C9 CD 21 8B D6 B9 78 01 }
	condition:
		$1 at pe.entry_point
}

rule vx_sonik_youth {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Sonik Youth"
		pattern = "8A1602008A0732C2880743FEC281FB"
	strings:
		$1 = { 8A 16 02 00 8A 07 32 C2 88 07 43 FE C2 81 FB }
	condition:
		$1 at pe.entry_point
}

rule vx_spanz {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Spanz"
		pattern = "E800005E81EE????8D94????B41ACD21C784"
	strings:
		$1 = { E8 00 00 5E 81 EE ?? ?? 8D 94 ?? ?? B4 1A CD 21 C7 84 }
	condition:
		$1 at pe.entry_point
}

rule vx_syp {
	meta:
		tool = "P"
		name = "Vx:"
		version = "SYP"
		pattern = "478BC2051E00528BD0B8023DCD218BD85A"
	strings:
		$1 = { 47 8B C2 05 1E 00 52 8B D0 B8 02 3D CD 21 8B D8 5A }
	condition:
		$1 at pe.entry_point
}

rule vx_tibs_zhelatin {
	meta:
		tool = "P"
		name = "VX:"
		version = "Tibs/Zhelatin (StormWorm) variant"
		pattern = "FF74241C588D80????7704506862343504E8"
	strings:
		$1 = { FF 74 24 1C 58 8D 80 ?? ?? 77 04 50 68 62 34 35 04 E8 }
	condition:
		$1 at pe.entry_point
}

rule vx_travjack883 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "TravJack.883"
		pattern = "EB??9C9E26????5104??7D??00??2E????????8CC88EC08ED880????????74??8A??????BB????8A??32C288??FEC24381"
	strings:
		$1 = { EB ?? 9C 9E 26 ?? ?? 51 04 ?? 7D ?? 00 ?? 2E ?? ?? ?? ?? 8C C8 8E C0 8E D8 80 ?? ?? ?? ?? 74 ?? 8A ?? ?? ?? BB ?? ?? 8A ?? 32 C2 88 ?? FE C2 43 81 }
	condition:
		$1 at pe.entry_point
}

rule vx_trivial25 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Trivial.25"
		pattern = "B44EFEC6CD21B8??3DBA??00CD2193B440CD"
	strings:
		$1 = { B4 4E FE C6 CD 21 B8 ?? 3D BA ?? 00 CD 21 93 B4 40 CD }
	condition:
		$1 at pe.entry_point
}

rule vx_trivial46 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Trivial.46"
		pattern = "B44EB120BA????CD21BA????B8??3DCD21"
	strings:
		$1 = { B4 4E B1 20 BA ?? ?? CD 21 BA ?? ?? B8 ?? 3D CD 21 }
	condition:
		$1 at pe.entry_point
}

rule vx_trojanteflon {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Trojan.Telefoon"
		pattern = "601EE83B01BFCC012E033ECA012EC705"
	strings:
		$1 = { 60 1E E8 3B 01 BF CC 01 2E 03 3E CA 01 2E C7 05 }
	condition:
		$1 at pe.entry_point
}

rule vx_uddy2617 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Uddy.2617"
		pattern = "2E??????????2E??????????2E??????8CC88ED88C??????2B??????03??????A3????A1????A3????A1????A3????8CC82B??????03??????A3????B8AB9CCD2F3D7698"
	strings:
		$1 = { 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? 8C C8 8E D8 8C ?? ?? ?? 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? 8C C8 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? B8 AB 9C CD 2F 3D 76 98 }
	condition:
		$1 at pe.entry_point
}

rule vx_vcl_01 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VCL (encrypted)"
		pattern = "01B9????8134????4646E2F8C3"
	strings:
		$1 = { 01 B9 ?? ?? 81 34 ?? ?? 46 46 E2 F8 C3 }
	condition:
		$1 at pe.entry_point
}

rule vx_vcl_02 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VCL (encrypted)"
		pattern = "01B9????8135????4747E2F8C3"
	strings:
		$1 = { 01 B9 ?? ?? 81 35 ?? ?? 47 47 E2 F8 C3 }
	condition:
		$1 at pe.entry_point
}

rule vx_vcl_03 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VCL"
		pattern = "ACB90080F2AEB90400ACAE75??E2FA89"
	strings:
		$1 = { AC B9 00 80 F2 AE B9 04 00 AC AE 75 ?? E2 FA 89 }
	condition:
		$1 at pe.entry_point
}

rule vx_virusconstructor_01 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VirusConstructor(IVP).based"
		pattern = "E9????E8????5D??????????81ED????????????E8????81FC????????8D??????BF????57A4A5"
	strings:
		$1 = { E9 ?? ?? E8 ?? ?? 5D ?? ?? ?? ?? ?? 81 ED ?? ?? ?? ?? ?? ?? E8 ?? ?? 81 FC ?? ?? ?? ?? 8D ?? ?? ?? BF ?? ?? 57 A4 A5 }
	condition:
		$1 at pe.entry_point
}

rule vx_virusconstructor_02 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VirusConstructor.based"
		pattern = "BB????B9????2E????????4343????8BECCC8B????81??????061EB8????CD213D????????8CD8488ED8"
	strings:
		$1 = { BB ?? ?? B9 ?? ?? 2E ?? ?? ?? ?? 43 43 ?? ?? 8B EC CC 8B ?? ?? 81 ?? ?? ?? 06 1E B8 ?? ?? CD 21 3D ?? ?? ?? ?? 8C D8 48 8E D8 }
	condition:
		$1 at pe.entry_point
}

rule vx_vx_virusconstructor_03 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VirusConstructor.based"
		pattern = "E8????5D81??????061EE8????E8????????2E????????????B44ABBFFFFCD2183????B44ACD21"
	strings:
		$1 = { E8 ?? ?? 5D 81 ?? ?? ?? 06 1E E8 ?? ?? E8 ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B4 4A BB FF FF CD 21 83 ?? ?? B4 4A CD 21 }
	condition:
		$1 at pe.entry_point
}

rule vx_xpeh4768 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "XPEH.4768"
		pattern = "E8????5B81??????5056572E??????????2E????????????B8010050B8????50E8"
	strings:
		$1 = { E8 ?? ?? 5B 81 ?? ?? ?? 50 56 57 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B8 01 00 50 B8 ?? ?? 50 E8 }
	condition:
		$1 at pe.entry_point
}

rule vx_xrcv1015 {
	meta:
		tool = "P"
		name = "Vx:"
		version = "XRCV.1015"
		pattern = "E8????5E83????53511E06B499CD2180FC21??????????33C0508CD8488EC01FA1????8B"
	strings:
		$1 = { E8 ?? ?? 5E 83 ?? ?? 53 51 1E 06 B4 99 CD 21 80 FC 21 ?? ?? ?? ?? ?? 33 C0 50 8C D8 48 8E C0 1F A1 ?? ?? 8B }
	condition:
		$1 at pe.entry_point
}

rule webcops_uv_01 {
	meta:
		tool = "P"
		name = "WebCops"
		pattern = "A8BE58DCD6CCC4634A0FE002BBCEF35C5023FB62E73D2B"
	strings:
		$1 = { A8 BE 58 DC D6 CC C4 63 4A 0F E0 02 BB CE F3 5C 50 23 FB 62 E7 3D 2B }
	condition:
		$1 at pe.entry_point
}

rule webcops_uv_02 {
	meta:
		tool = "P"
		name = "WebCops"
		pattern = "EB0305EB02EBFC55EB03EB0405EBFBEB53E80400000072"
	strings:
		$1 = { EB 03 05 EB 02 EB FC 55 EB 03 EB 04 05 EB FB EB 53 E8 04 00 00 00 72 }
	condition:
		$1 at pe.entry_point
}

rule werus_crypter_10_01 {
	meta:
		tool = "P"
		name = "Werus Crypter"
		version = "1.0"
		pattern = "68981140006A00E850000000C9C3EDB3FEFFFF6A00E80C000000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25A8104000FF25B010400000000000000000000000000000000000000000000000000000000000000000000000BBE8124000803305E97DFFFFFF"
	strings:
		$1 = { 68 98 11 40 00 6A 00 E8 50 00 00 00 C9 C3 ED B3 FE FF FF 6A 00 E8 0C 00 00 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 A8 10 40 00 FF 25 B0 10 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 BB E8 12 40 00 80 33 05 E9 7D FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule werus_crypter_10_02 {
	meta:
		tool = "P"
		name = "Werus Crypter"
		version = "1.0"
		pattern = "BBE8124000803305E97DFFFFFF"
	strings:
		$1 = { BB E8 12 40 00 80 33 05 E9 7D FF FF FF }
	condition:
		$1 at pe.entry_point
}

rule winu_key_410a {
	meta:
		tool = "P"
		name = "WIBU-Key"
		version = "4.10a"
		pattern = "F705????????FF0000007512"
	strings:
		$1 = { F7 05 ?? ?? ?? ?? FF 00 00 00 75 12 }
	condition:
		$1 at pe.entry_point
}

rule wind_of_crypt_10 {
	meta:
		tool = "P"
		name = "Wind of Crypt"
		version = "1.0"
		pattern = "558BEC83C4EC53????????8945ECB864400010E828EAFFFF33C05568CE51001064????????206A0068800000006A036A006A0168000000808D55EC33C0E8F6DBFFFF8B45ECE812E7FFFF50E83CEAFFFF8BD883FBFF0F84A60000006A0053E841EAFFFF8BF081EE005E00006A006A0068005E000053E852EAFFFFB8F49700108BD6E82EE7FFFFB8F89700108BD6E822E7FFFF8BC6E8ABD8FFFF8BF86A0068F097001056A1F49700105053E805EAFFFF53E8CFE9FFFFB8FC970010BAE8510010E874EAFFFFA1F497001085C0740583E8048B0050B9F8970010B8FC9700108B15F4970010E8D8EAFFFFB8FC970010E85AEBFFFF8BCE8B15F89700108BC7E8EBE9FFFF8BC785C07405E8E4EBFFFF33C05A595964891068D55100108D45ECE8BBE5FFFFC3E9A9DFFFFFEBF05F5E5BE8B7E4FFFF000000FFFFFFFF0A000000635A6C5630556C6B704D"
	strings:
		$1 = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 64 40 00 10 E8 28 EA FF FF 33 C0 55 68 CE 51 00 10 64 ?? ?? ?? ?? 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 F6 DB FF FF 8B 45 EC E8 12 E7 FF FF 50 E8 3C EA FF FF 8B D8 83 FB FF 0F 84 A6 00 00 00 6A 00 53 E8 41 EA FF FF 8B F0 81 EE 00 5E 00 00 6A 00 6A 00 68 00 5E 00 00 53 E8 52 EA FF FF B8 F4 97 00 10 8B D6 E8 2E E7 FF FF B8 F8 97 00 10 8B D6 E8 22 E7 FF FF 8B C6 E8 AB D8 FF FF 8B F8 6A 00 68 F0 97 00 10 56 A1 F4 97 00 10 50 53 E8 05 EA FF FF 53 E8 CF E9 FF FF B8 FC 97 00 10 BA E8 51 00 10 E8 74 EA FF FF A1 F4 97 00 10 85 C0 74 05 83 E8 04 8B 00 50 B9 F8 97 00 10 B8 FC 97 00 10 8B 15 F4 97 00 10 E8 D8 EA FF FF B8 FC 97 00 10 E8 5A EB FF FF 8B CE 8B 15 F8 97 00 10 8B C7 E8 EB E9 FF FF 8B C7 85 C0 74 05 E8 E4 EB FF FF 33 C0 5A 59 59 64 89 10 68 D5 51 00 10 8D 45 EC E8 BB E5 FF FF C3 E9 A9 DF FF FF EB F0 5F 5E 5B E8 B7 E4 FF FF 00 00 00 FF FF FF FF 0A 00 00 00 63 5A 6C 56 30 55 6C 6B 70 4D }
	condition:
		$1 at pe.entry_point
}

rule winkript_10 {
	meta:
		tool = "P"
		name = "Winkript"
		version = "1.0"
		pattern = "33C08BB800??????8B9004??????85FF741B33C950EB0C8A0439C0C804341B880439413BCA72F058"
	strings:
		$1 = { 33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 }
	condition:
		$1 at pe.entry_point
}

rule winupack_039f {
	meta:
		tool = "P"
		name = "WinUpack"
		version = "0.39f"
		pattern = "BEB011????AD50FF7634EB7C4801????0B014C6F61644C6962726172794100001810000010000000????????0000????001000000002000004000000000039"
	strings:
		$1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 ?? ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 }
	condition:
		$1 at pe.entry_point
}

rule wwpack32_1x {
	meta:
		tool = "P"
		name = "WWPack32"
		version = "1.x"
		pattern = "53558BE833DBEB60"
	strings:
		$1 = { 53 55 8B E8 33 DB EB 60 }
	condition:
		$1 at pe.entry_point
}

rule xhider_10_01 {
	meta:
		tool = "P"
		name = "X-Hider"
		version = "1.0"
		pattern = "558BEC83C4EC33C08945ECB854204444E8DFF8FFFF33C055680821444464FF306489208D55ECB81C214444E8E0F9FFFF8B55ECB840????44E88BF5FFFF6A006A006A026A006A016800000040A140????44E87EF6FFFF50E84CF9FFFF6A0050E84CF9FFFFA328????44E8CEFEFFFF33C05A5959648910680F2144448D45ECE8F1F4FFFFC3E9BBF2FFFFEBF0E8FCF3FFFFFFFFFFFF0E000000633A5C303030303030312E64617400"
	strings:
		$1 = { 55 8B EC 83 C4 EC 33 C0 89 45 EC B8 54 20 44 44 E8 DF F8 FF FF 33 C0 55 68 08 21 44 44 64 FF 30 64 89 20 8D 55 EC B8 1C 21 44 44 E8 E0 F9 FF FF 8B 55 EC B8 40 ?? ?? 44 E8 8B F5 FF FF 6A 00 6A 00 6A 02 6A 00 6A 01 68 00 00 00 40 A1 40 ?? ?? 44 E8 7E F6 FF FF 50 E8 4C F9 FF FF 6A 00 50 E8 4C F9 FF FF A3 28 ?? ?? 44 E8 CE FE FF FF 33 C0 5A 59 59 64 89 10 68 0F 21 44 44 8D 45 EC E8 F1 F4 FF FF C3 E9 BB F2 FF FF EB F0 E8 FC F3 FF FF FF FF FF FF 0E 00 00 00 63 3A 5C 30 30 30 30 30 30 31 2E 64 61 74 00 }
	condition:
		$1 at pe.entry_point
}

rule xhider_10_02 {
	meta:
		tool = "P"
		name = "X-Hider"
		version = "1.0"
		pattern = "85D274238B4AF8417F1A50528B42FCE83000000089C258528B48FCE848FBFFFF5A58EB03FF42F8871085D274138B4AF8497C0DFF4AF875088D42F8E85CFAFFFFC38D400085C07E245083C00A83E0FE50E82FFAFFFF5A66C74402FE000083C0085A8950FCC740F801000000C331C0C390"
	strings:
		$1 = { 85 D2 74 23 8B 4A F8 41 7F 1A 50 52 8B 42 FC E8 30 00 00 00 89 C2 58 52 8B 48 FC E8 48 FB FF FF 5A 58 EB 03 FF 42 F8 87 10 85 D2 74 13 8B 4A F8 49 7C 0D FF 4A F8 75 08 8D 42 F8 E8 5C FA FF FF C3 8D 40 00 85 C0 7E 24 50 83 C0 0A 83 E0 FE 50 E8 2F FA FF FF 5A 66 C7 44 02 FE 00 00 83 C0 08 5A 89 50 FC C7 40 F8 01 00 00 00 C3 31 C0 C3 90 }
	condition:
		$1 at pe.entry_point
}

rule xpack_142 {
	meta:
		tool = "P"
		name = "X-Pack"
		version = "1.4.2"
		pattern = "72??C38BDE83????C1????8CD803C38ED88BDF83????C1????8CC003C38EC0C3"
	strings:
		$1 = { 72 ?? C3 8B DE 83 ?? ?? C1 ?? ?? 8C D8 03 C3 8E D8 8B DF 83 ?? ?? C1 ?? ?? 8C C0 03 C3 8E C0 C3 }
	condition:
		$1 at pe.entry_point
}

rule xpack_152_164 {
	meta:
		tool = "P"
		name = "X-Pack"
		version = "1.52 - 1.64"
		pattern = "8BECFA33C08ED0BC????2E????????2E????????EB"
	strings:
		$1 = { 8B EC FA 33 C0 8E D0 BC ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? EB }
	condition:
		$1 at pe.entry_point
}

rule xpack_167 {
	meta:
		tool = "P"
		name = "X-Pack"
		version = "1.67"
		pattern = "B88CD3153375813EE80F009AE8F9FF9A9CEB019A5980CD01519DEB"
	strings:
		$1 = { B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB }
	condition:
		$1 at pe.entry_point
}

rule xpeor_099b_01 {
	meta:
		tool = "P"
		name = "X-PEOR"
		version = "0.99b"
		pattern = "E8????????5D8BCD81ED7A2940??89AD0F6D40"
	strings:
		$1 = { E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40 }
	condition:
		$1 at pe.entry_point
}

rule xpeor_099b_02 {
	meta:
		tool = "P"
		name = "X-PEOR"
		version = "0.99b"
		pattern = "E8000000005D8BCD81ED7A29400089AD0F6D4000"
	strings:
		$1 = { E8 00 00 00 00 5D 8B CD 81 ED 7A 29 40 00 89 AD 0F 6D 40 00 }
	condition:
		$1 at pe.entry_point
}

rule xcomp_xpack_097_098_01 {
	meta:
		tool = "P"
		name = "XComp/XPack"
		version = "0.97 - 0.98"
		pattern = "68????????9C60E8????????????????0000000000000000????????????????0000000000000000000000000000000000000000????????????????????????????????????????000000004B45524E454C33322E444C4C00000047657450726F63416464726573730000004C6F61644C696272617279410000005669727475616C416C6C6F630000005669727475616C467265650000005669727475616C50726F7465637400"
	strings:
		$1 = { 68 ?? ?? ?? ?? 9C 60 E8 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 }
	condition:
		$1 at pe.entry_point
}

rule xcomp_xpack_097_098_02 {
	meta:
		tool = "P"
		name = "XComp/XPack"
		version = "0.97 - 0.98"
		pattern = "68????????9C60E8????????????????0000000000000000????????????????0000000000000000000000000000000000000000????????????????????????000000004B45524E454C33322E444C4C00000047657450726F63416464726573730000004C6F61644C696272617279410000005669727475616C50726F7465637400"
	strings:
		$1 = { 68 ?? ?? ?? ?? 9C 60 E8 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 }
	condition:
		$1 at pe.entry_point
}

rule xcomp_xpack_09x {
	meta:
		tool = "P"
		name = "XComp/XPack"
		version = "0.9x"
		pattern = "AC84C07403AAEBF8E80B000000206E6F7420666F756E64005EACAA84C075FA6A0057526A00E8060000004572726F72005EACAA84C075FAE80B0000005553455233322E444C4C00FF552CE80C0000004D657373616765426F78410050FF5528FFD083C47C48C3"
	strings:
		$1 = { AC 84 C0 74 03 AA EB F8 E8 0B 00 00 00 20 6E 6F 74 20 66 6F 75 6E 64 00 5E AC AA 84 C0 75 FA 6A 00 57 52 6A 00 E8 06 00 00 00 45 72 72 6F 72 00 5E AC AA 84 C0 75 FA E8 0B 00 00 00 55 53 45 52 33 32 2E 44 4C 4C 00 FF 55 2C E8 0C 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 50 FF 55 28 FF D0 83 C4 7C 48 C3 }
	condition:
		$1 at pe.entry_point
}

rule xcr_012 {
	meta:
		tool = "P"
		name = "XCR"
		version = "0.12"
		pattern = "609CE8????????8BDD5D81ED????????899D"
	strings:
		$1 = { 60 9C E8 ?? ?? ?? ?? 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D }
	condition:
		$1 at pe.entry_point
}

rule xcr_013 {
	meta:
		tool = "P"
		name = "XCR"
		version = "0.13"
		pattern = "937108????????????????8BD878E2????????9C33C3????????6079CE????????E801????????83C404E8ABFFFFFF????????2BE8????????03C5FF30????????C6??EB"
	strings:
		$1 = { 93 71 08 ?? ?? ?? ?? ?? ?? ?? ?? 8B D8 78 E2 ?? ?? ?? ?? 9C 33 C3 ?? ?? ?? ?? 60 79 CE ?? ?? ?? ?? E8 01 ?? ?? ?? ?? 83 C4 04 E8 AB FF FF FF ?? ?? ?? ?? 2B E8 ?? ?? ?? ?? 03 C5 FF 30 ?? ?? ?? ?? C6 ?? EB }
	condition:
		$1 at pe.entry_point
}

rule xenocode_811353 {
	meta:
		tool = "P"
		name = "Xenocode"
		version = "8.1.1353"
		pattern = "558BEC83E4F881EC1C090000535657E887FBFFFF8B350C?0????FFD683E0113D110100000F8426040000FFD68B5C2428A30C50????E853FCFFFF8BC82B0D0C50????6A0333D28BC15EF7F6F7C10080FFFF0F858602000033C033FF89BC24240900006689"
	strings:
		$1 = { 55 8B EC 83 E4 F8 81 EC 1C 09 00 00 53 56 57 E8 87 FB FF FF 8B 35 0C ?0 ?? ?? FF D6 83 E0 11 3D 11 01 00 00 0F 84 26 04 00 00 FF D6 8B 5C 24 28 A3 0C 50 ?? ?? E8 53 FC FF FF 8B C8 2B 0D 0C 50 ?? ?? 6A 03 33 D2 8B C1 5E F7 F6 F7 C1 00 80 FF FF 0F 85 86 02 00 00 33 C0 33 FF 89 BC 24 24 09 00 00 66 89 }
	condition:
		$1 at pe.entry_point
}

rule xj_xpal_uv {
	meta:
		tool = "P"
		name = "XJ or XPAL"
		pattern = "558BEC6AFF68????400068????400064A100000000506489250000000083EC44535657669C"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 44 53 56 57 66 9C }
	condition:
		$1 at pe.entry_point
}

rule xpep_03x {
	meta:
		tool = "P"
		name = "xPEP"
		version = "0.3x"
		pattern = "555356515257E816000000"
	strings:
		$1 = { 55 53 56 51 52 57 E8 16 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule extreme_protector_105 {
	meta:
		tool = "P"
		name = "Xtreme-Protector"
		version = "1.05"
		pattern = "E9????0000000000000000"
	strings:
		$1 = { E9 ?? ?? 00 00 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule extreme_protector_106 {
	meta:
		tool = "P"
		name = "Xtreme-Protector"
		version = "1.06"
		pattern = "B8??????00B975????005051E805000000E94A010000608B7424248B7C2428FCB2808A0646880747BB0200000002D275058A164612D273EA02D275058A164612D2734F33C002D275058A164612D20F83DF00000002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C07406572BF88A075F880747BB02000000EB9BB80100000002D275058A164612D213C002D275058A"
	strings:
		$1 = { B8 ?? ?? ?? 00 B9 75 ?? ?? 00 50 51 E8 05 00 00 00 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 74 06 57 2B F8 8A 07 5F 88 07 47 BB 02 00 00 00 EB 9B B8 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A }
	condition:
		$1 at pe.entry_point
}

rule xtremlok_uv {
	meta:
		tool = "P"
		name = "XTREMLOK"
		pattern = "909090EB29????????000000000000000000000000000000000000000053544154494300??????????????????00525351565755E8????????5D81ED36000000"
	strings:
		$1 = { 90 90 90 EB 29 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 53 54 41 54 49 43 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 52 53 51 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 36 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule xxpack_01 {
	meta:
		tool = "P"
		name = "XXPack"
		version = "0.1"
		pattern = "E8040000008360EB0C5DEB054555EB04B8EBF900C3E8000000005DEB010081ED5E1F4000EB0283098DB5EF1F4000EB028309BAA3110000EB006800??????C3"
	strings:
		$1 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 00 68 00 ?? ?? ?? C3 }
	condition:
		$1 at pe.entry_point
}

rule yodas_crypter_10 {
	meta:
		tool = "P"
		name = "yoda's Crypter"
		version = "1.0"
		pattern = "60E8000000005D81EDE71A4000E8A1000000E8D1000000E885010000F785"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED E7 1A 40 00 E8 A1 00 00 00 E8 D1 00 00 00 E8 85 01 00 00 F7 85 }
	condition:
		$1 at pe.entry_point
}

rule yodas_crypter_11 {
	meta:
		tool = "P"
		name = "yoda's Crypter"
		version = "1.1"
		pattern = "60E8000000005D81ED8A1C4000B99E0000008DBD4C2340008BF733"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 8A 1C 40 00 B9 9E 00 00 00 8D BD 4C 23 40 00 8B F7 33 }
	condition:
		$1 at pe.entry_point
}

rule yodas_crypter_12 {
	meta:
		tool = "P"
		name = "yoda's Crypter"
		version = "1.2"
		pattern = "60E8000000005D81EDF31D4000B97B0900008DBD3B1E40008BF7AC????????????????????????????????????????????????????????????????????????????????????????????????AAE2CC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }
	condition:
		$1 at pe.entry_point
}

rule yodas_crypter_13_01 {
	meta:
		tool = "P"
		name = "yoda's Crypter"
		version = "1.3"
		pattern = "558BEC53565760E8000000005D81ED6C284000B95D34400081E9C62840008BD581C2C62840008D3A8BF733C0EB0490EB01C2AC"
	strings:
		$1 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }
	condition:
		$1 at pe.entry_point
}

rule yodas_crypter_13_02 {
	meta:
		tool = "P"
		name = "yoda's Crypter"
		version = "1.3"
		pattern = "558BEC53565760E8000000005D81ED8C214000B9512D400081E9E62140008BD581C2E62140008D3A8BF733C0EB0490EB01C2AC"
	strings:
		$1 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 8C 21 40 00 B9 51 2D 40 00 81 E9 E6 21 40 00 8B D5 81 C2 E6 21 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }
	condition:
		$1 at pe.entry_point
}

rule yodas_crypter_13_03 {
	meta:
		tool = "P"
		name = "yoda's Crypter"
		version = "1.3"
		pattern = "558BEC81ECC00000005356578DBD40FFFFFFB930000000B8CCCCCCCCF3AB60E8000000005D81ED84524100B9755E410081E9DE5241008BD581C2DE5241008D3A8BF733C0EB0490EB01C2AC????????????????????????????????????????????????????????????????????????????????????????????????AAE2CC"
	strings:
		$1 = { 55 8B EC 81 EC C0 00 00 00 53 56 57 8D BD 40 FF FF FF B9 30 00 00 00 B8 CC CC CC CC F3 AB 60 E8 00 00 00 00 5D 81 ED 84 52 41 00 B9 75 5E 41 00 81 E9 DE 52 41 00 8B D5 81 C2 DE 52 41 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }
	condition:
		$1 at pe.entry_point
}

rule yodas_crypter_1x_modf {
	meta:
		tool = "P"
		name = "yoda's Crypter"
		version = "1.x modified"
		pattern = "60E8000000005D81ED????????B9????00008DBD????????8BF7AC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7 AC }
	condition:
		$1 at pe.entry_point
}

rule yodas_protector_uv_01 {
	meta:
		tool = "P"
		name = "yoda's Protector"
		pattern = "E8000000005D81ED????42008BD581C2????420052E801000000C3C3E803000000EB01??E80E000000E8D1FFFFFFC3E803000000EB01??33C064FF30648920CC"
		start = 96
	strings:
		$1 = { E8 00 00 00 00 5D 81 ED ?? ?? 42 00 8B D5 81 C2 ?? ?? 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC }
	condition:
		$1 at pe.entry_point + 96
}

rule yodas_protector_uv_02 {
	meta:
		tool = "P"
		name = "yoda's Protector"
		pattern = "E8??????00EB01E???????0000E8??????00EB01??????????00E8??????00EB01??????????00E8??????00EB01????????0000E8??????00EB01"
	strings:
		$1 = { E8 ?? ?? ?? 00 EB 01 E? ?? ?? ?? 00 00 E8 ?? ?? ?? 00 EB 01 ?? ?? ?? ?? ?? 00 E8 ?? ?? ?? 00 EB 01 ?? ?? ?? ?? ?? 00 E8 ?? ?? ?? 00 EB 01 ?? ?? ?? ?? 00 00 E8 ?? ?? ?? 00 EB 01 }
	condition:
		$1 in (pe.entry_point .. pe.entry_point + 12)
}

rule yodas_protector_10b {
	meta:
		tool = "P"
		name = "yoda's Protector"
		version = "1.0b"
		pattern = "558BEC53565760E8000000005D81ED4C324000E803000000EB01??B9EA47400081E9E93240008BD581C2E93240008D3A8BF733C0E80400000090EB01??E803000000EB01"
	strings:
		$1 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 00 00 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule yodas_protector_101 {
	meta:
		tool = "P"
		name = "yoda's Protector"
		version = "1.01"
		pattern = "558BEC535657E803000000EB01??E886000000E803000000EB01??E879000000E803000000EB01??E8A4000000E803000000EB01??E897000000E803000000EB01??E82D000000E803000000EB01??60E8000000005D81ED"
	strings:
		$1 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED }
	condition:
		$1 at pe.entry_point
}

rule yodas_protector_102 {
	meta:
		tool = "P"
		name = "yoda's Protector"
		version = "1.02"
		pattern = "E803000000EB01??BB55000000E803000000EB01??E88F000000E803000000EB01??E882000000E803000000EB01??E8B8000000E803000000EB01??E8AB000000E803000000EB01??83FB55E803000000EB01??752EE803000000EB01??C360E8000000005D81ED233F42008BD581C2723F420052E801000000C3C3E803000000EB01??E80E000000E8D1FFFFFFC3E803000000EB01??33C064FF30648920CCC3E803000000EB01??33C064FF306489204BCCC3E803000000EB01??33DBB93A66420081E91D4042008BD581C21D4042008D3A8BF733C0E803000000EB01??E817000000909090E9C31F000033C064FF3064892043CCC3"
	strings:
		$1 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 23 3F 42 00 8B D5 81 C2 72 3F 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3A 66 42 00 81 E9 1D 40 42 00 8B D5 81 C2 1D 40 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 C3 1F 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }
	condition:
		$1 at pe.entry_point
}

rule yodas_protector_102_dll_ocx {
	meta:
		tool = "P"
		name = "yoda's Protector"
		version = "1.02 DLL or OCX"
		pattern = "??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????60E8000000005D81ED233F42008BD581C2723F420052E801000000C3C3E803000000EB01??E80E000000E8D1FFFFFFC3E803000000EB01??33C064FF30648920CCC3E803000000EB"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 E8 00 00 00 00 5D 81 ED 23 3F 42 00 8B D5 81 C2 72 3F 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB }
	condition:
		$1 at pe.entry_point
}

rule yodas_protector_1033 {
	meta:
		tool = "P"
		name = "yoda's Protector"
		version = "1.03.3"
		pattern = "E803000000EB01??BB55000000E803000000EB01??E88E000000E803000000EB01??E881000000E803000000EB01??E8B7000000E803000000EB01??E8AA000000E803000000EB01??83FB55E803000000EB01??752DE803000000EB01??60E8000000005D81ED07E240008BD581C256E2400052E801000000C3C3E803000000EB01??E80E000000E8D1FFFFFFC3E803000000EB01??33C064FF30648920CCC3E803000000EB01??33C064FF306489204BCCC3"
	strings:
		$1 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2D E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 }
	condition:
		$1 at pe.entry_point
}

rule yodas_protector_1032_dll_ocx_01 {
	meta:
		tool = "P"
		name = "yoda's Protector"
		version = "1.03.2 DLL or OCX"
		pattern = "??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????60E8000000005D81ED947342008BD581C2E373420052E801000000C3C3E803000000EB01??E80E000000E8D1FFFFFFC3E803000000EB01??33C064FF30648920CCC3E803000000EB"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 E8 00 00 00 00 5D 81 ED 94 73 42 00 8B D5 81 C2 E3 73 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB }
	condition:
		$1 at pe.entry_point
}

rule yodas_protector_1032_dll_ocx_02 {
	meta:
		tool = "P"
		name = "yoda's Protector"
		version = "1.03.3 DLL or OCX"
		pattern = "60????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????E8000000005D81ED07E240008BD581C256E2400052E801000000C3C3E803000000EB01??E80E000000E8D1FFFFFFC3E803000000EB01??33C064FF30648920CCC3E803000000EB01"
	strings:
		$1 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 }
	condition:
		$1 at pe.entry_point
}

rule yzpack_11 {
	meta:
		tool = "P"
		name = "yzpack"
		version = "1.1"
		pattern = "6033C08D480750E2FD8BEC648B4030780C8B400C8B701CAD8B4008EB098B40348D407C8B403C894504E8F3070000608B5D048B733C8B74337803F3568B762003F333C9499241AD03C35233FF0FB61038F2"
	strings:
		$1 = { 60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 8D 40 7C 8B 40 3C 89 45 04 E8 F3 07 00 00 60 8B 5D 04 8B 73 3C 8B 74 33 78 03 F3 56 8B 76 20 03 F3 33 C9 49 92 41 AD 03 C3 52 33 FF 0F B6 10 38 F2 }
	condition:
		$1 at pe.entry_point
}

rule yzpack_112 {
	meta:
		tool = "P"
		name = "yzpack"
		version = "1.12"
		pattern = "5A52456083EC188BEC8BFC33C0648B4030780C8B400C8B701CAD8B4008EB098B403483C07C8B403CABE9????????B409BA00001FCD21B8014CCD2140000000504500004C010200????????0000000000000000E000????0B01????????0000"
	strings:
		$1 = { 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 ?? ?? ?? ?? B4 09 BA 00 00 1F CD 21 B8 01 4C CD 21 40 00 00 00 50 45 00 00 4C 01 02 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 E0 00 ?? ?? 0B 01 ?? ?? ?? ?? 00 00 }
	condition:
		$1 at pe.entry_point
}

rule yzpack_12 {
	meta:
		tool = "P"
		name = "yzpack"
		version = "1.2"
		pattern = "4D5A52456083EC188BEC8BFC33C0648B4030780C8B400C8B701CAD8B4008EB098B403483C07C8B403CABE9"
	strings:
		$1 = { 4D 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 }
	condition:
		$1 at pe.entry_point
}

rule yzpack_20 {
	meta:
		tool = "P"
		name = "yzpack"
		version = "2.0"
		pattern = "25????????6187CC5545455581EDCA00000055A4B302FF142473F833C9FF1424731833C0FF1424731FB30241B010FF142412C073F9753CAAEBDCFF5424042BCB750FFF542408EB27ACD1E8743013C9EB1B9148C1E008ACFF5424083D007D0000730A80FC05730683F87F77024141958BC5B301568BF72BF0F3A45EEB99BD????????FF6528"
	strings:
		$1 = { 25 ?? ?? ?? ?? 61 87 CC 55 45 45 55 81 ED CA 00 00 00 55 A4 B3 02 FF 14 24 73 F8 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 1F B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3C AA EB DC FF 54 24 04 2B CB 75 0F FF 54 24 08 EB 27 AC D1 E8 74 30 13 C9 EB 1B 91 48 C1 E0 08 AC FF 54 24 08 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 99 BD ?? ?? ?? ?? FF 65 28 }
	condition:
		$1 at pe.entry_point
}

rule zcode_101 {
	meta:
		tool = "P"
		name = "ZCode"
		version = "1.01"
		pattern = "E912000000????????????????????????E9FBFFFFFFC368????????64FF35"
	strings:
		$1 = { E9 12 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E9 FB FF FF FF C3 68 ?? ?? ?? ?? 64 FF 35 }
	condition:
		$1 at pe.entry_point
}

rule zealpack_10 {
	meta:
		tool = "P"
		name = "ZealPack"
		version = "1.0"
		pattern = "C745F400004000C745F0????????8B45F405????????8945F4C745FC00000000EB098B4DFC83C101894DFC8B55FC3B55F07D228B45F40345FC8A08884DF80FBE55F883F20F8855F88B45F40345FC8A4DF88808EBCDFF65F4"
	strings:
		$1 = { C7 45 F4 00 00 40 00 C7 45 F0 ?? ?? ?? ?? 8B 45 F4 05 ?? ?? ?? ?? 89 45 F4 C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 89 4D FC 8B 55 FC 3B 55 F0 7D 22 8B 45 F4 03 45 FC 8A 08 88 4D F8 0F BE 55 F8 83 F2 0F 88 55 F8 8B 45 F4 03 45 FC 8A 4D F8 88 08 EB CD FF 65 F4 }
	condition:
		$1 at pe.entry_point
}

rule zipworxsecureexe_25 {
	meta:
		tool = "P"
		name = "ZipWorxSecureEXE"
		version = "2.5"
		pattern = "E9B8000000????????????????????????0000000000????????????????????005365637572654558452045786563757461626C652046696C652050726F746563746F720D0A436F7079726967687428632920323030342D32303037205A6970574F525820546563686E6F6C6F676965732C204C4C430D0A506F7274696F6E7320436F707972696768742028632920313939372D32303031204C65652048617369756B0D0A416C"
	strings:
		$1 = { E9 B8 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 53 65 63 75 72 65 45 58 45 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 28 63 29 20 32 30 30 34 2D 32 30 30 37 20 5A 69 70 57 4F 52 58 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 2C 20 4C 4C 43 0D 0A 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 37 2D 32 30 30 31 20 4C 65 65 20 48 61 73 69 75 6B 0D 0A 41 6C }
	condition:
		$1 at pe.entry_point
}

rule zprotect_120_130 {
	meta:
		tool = "P"
		name = "Zprotect"
		version = "1.2.0 - 1.3.0"
		pattern = "00000000000000002E74657874627373????????001000000000000000000000000000000000000000000000200000E02E74657874000000????????????????????????????????000000000000000000000000200000E02E64617461000000????????????????????????????????000000000000000000000000400000402E69646174610000????????????????????????????????000000000000000000000000400000C0????????????????????????????????????????????????000000000000000000000000??0000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 2E 74 65 78 74 62 73 73 ?? ?? ?? ?? 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 2E 74 65 78 74 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 2E 64 61 74 61 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2E 69 64 61 74 61 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? 00 00 }
	condition:
		$1 at pe.entry_point
}

rule the_best_cryptor_uv {
	meta:
		tool = "P"
		name = "The Best Cryptor"
		pattern = "EB065652554C5A009090909090909090"
	strings:
		$1 = { EB 06 56 52 55 4C 5A 00 90 90 90 90 90 90 90 90 }
	condition:
		$1 at pe.entry_point
}

rule the_guard_library_uv {
	meta:
		tool = "P"
		name = "The Guard Library"
		pattern = "50E8????????5825??F0FFFF8BC883C1605183C04083EA0652FF209DC3"
	strings:
		$1 = { 50 E8 ?? ?? ?? ?? 58 25 ?? F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D C3 }
	condition:
		$1 at pe.entry_point
}

rule thehypers_protector_uv {
	meta:
		tool = "P"
		name = "TheHyper's protector"
		pattern = "558BEC83EC148BFCE814000000????0101????0101??????00????0101????02015EE80D0000006B65726E656C33322E646C6C008B4604FF108BD8E80D0000005669727475616C416C6C6F6300538B06FF108907E80C0000005669727475616C4672656500538B06FF10894704E80F00000047657450726F636573734865617000538B06FF10894708E80A00000048656170416C6C6F6300538B06FF1089470CE8090000004865"
	strings:
		$1 = { 55 8B EC 83 EC 14 8B FC E8 14 00 00 00 ?? ?? 01 01 ?? ?? 01 01 ?? ?? ?? 00 ?? ?? 01 01 ?? ?? 02 01 5E E8 0D 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8B 46 04 FF 10 8B D8 E8 0D 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 07 E8 0C 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 53 8B 06 FF 10 89 47 04 E8 0F 00 00 00 47 65 74 50 72 6F 63 65 73 73 48 65 61 70 00 53 8B 06 FF 10 89 47 08 E8 0A 00 00 00 48 65 61 70 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 47 0C E8 09 00 00 00 48 65 }
	condition:
		$1 at pe.entry_point
}

// Some unnamed tools. Still can be used for detection of packed binaries.

rule unknown_packer_01 {
	meta:
		tool = "P"
		name = "unknown packer"
		pattern = "EB????BE????BF????2E"
	strings:
		$1 = { EB ?? ?? BE ?? ?? BF ?? ?? 2E }
	condition:
		$1 at pe.entry_point
}

rule unknown_packer_02 {
	meta:
		tool = "P"
		name = "unknown packer"
		pattern = "061E575650535152BD????0E1F8C"
	strings:
		$1 = { 06 1E 57 56 50 53 51 52 BD ?? ?? 0E 1F 8C }
	condition:
		$1 at pe.entry_point
}

rule unknown_packer_03 {
	meta:
		tool = "P"
		name = "unknown packer"
		pattern = "545968617A79"
	strings:
		$1 = { 54 59 68 61 7A 79 }
	condition:
		$1 at pe.entry_point
}

rule unknown_packer_04 {
	meta:
		tool = "P"
		name = "unknown packer"
		pattern = "BC????C32EFF2E????CF"
	strings:
		$1 = { BC ?? ?? C3 2E FF 2E ?? ?? CF }
	condition:
		$1 at pe.entry_point
}

rule unknown_packer_05 {
	meta:
		tool = "P"
		name = "unknown packer"
		pattern = "FABB????B9????87E5872703E3918ACB80E1??D3C49133E38727"
	strings:
		$1 = { FA BB ?? ?? B9 ?? ?? 87 E5 87 27 03 E3 91 8A CB 80 E1 ?? D3 C4 91 33 E3 87 27 }
	condition:
		$1 at pe.entry_point
}

rule unknown_packer_06 {
	meta:
		tool = "P"
		name = "unknown packer"
		pattern = "FAB8????BE????33F00E172E??????BA????87E65B33DC"
	strings:
		$1 = { FA B8 ?? ?? BE ?? ?? 33 F0 0E 17 2E ?? ?? ?? BA ?? ?? 87 E6 5B 33 DC }
	condition:
		$1 at pe.entry_point
}

rule unknown_packer_07 {
	meta:
		tool = "P"
		name = "unknown packer"
		pattern = "8CC805????50B8????50B0??068CD20683"
	strings:
		$1 = { 8C C8 05 ?? ?? 50 B8 ?? ?? 50 B0 ?? 06 8C D2 06 83 }
	condition:
		$1 at pe.entry_point
}

rule unknown_packer_08 {
	meta:
		tool = "P"
		name = "unknown packer"
		pattern = "8BC42D????24008BF857B9????BE????F3A5FDC3974F4F"
	strings:
		$1 = { 8B C4 2D ?? ?? 24 00 8B F8 57 B9 ?? ?? BE ?? ?? F3 A5 FD C3 97 4F 4F }
	condition:
		$1 at pe.entry_point
}

rule unknown_packer_09 {
	meta:
		tool = "P"
		name = "unknown packer"
		pattern = "60BE????????8DBE????????83????57EB"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 83 ?? ?? 57 EB }
	condition:
		$1 at pe.entry_point
}

rule unknown_packer_10 {
	meta:
		tool = "P"
		name = "unknown packer"
		pattern = "EB??2E90????8CDB8CCA8EDAFA8BECBE????BC????BF"
	strings:
		$1 = { EB ?? 2E 90 ?? ?? 8C DB 8C CA 8E DA FA 8B EC BE ?? ?? BC ?? ?? BF }
	condition:
		$1 at pe.entry_point
}

rule unknown_packer_11 {
	meta:
		tool = "P"
		name = "unknown packer"
		pattern = "06B452CD2107E8????B462CD21E8"
	strings:
		$1 = { 06 B4 52 CD 21 07 E8 ?? ?? B4 62 CD 21 E8 }
	condition:
		$1 at pe.entry_point
}

rule unknown_joiner {
	meta:
		tool = "P"
		name = "unknown joiner"
		pattern = "44904C90B9DE000000BA0010400083C20344904CB90700000044904C33C9C705083040000000000090680001000068213040006A00E8C5020000906A006880"
	strings:
		$1 = { 44 90 4C 90 B9 DE 00 00 00 BA 00 10 40 00 83 C2 03 44 90 4C B9 07 00 00 00 44 90 4C 33 C9 C7 05 08 30 40 00 00 00 00 00 90 68 00 01 00 00 68 21 30 40 00 6A 00 E8 C5 02 00 00 90 6A 00 68 80 }
	condition:
		$1 at pe.entry_point
}
