/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_01.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_01 =
R"x86_pe_packer(
rule rule_1__EP__ExE_Pack {
	meta:
		tool = "P"
		name = "!EP"
		version = "1.0"
		extra = "ExePack"
		pattern = "6068????????B8????????FF1068????????50B8????????FF1068????????6A40FFD08905????????89C7BE????????60FCB28031DBA4B302E86D00000073F631C9E864000000731C31C0E85B0000007323B30241B010E84F00000010C073F7753FAAEBD4E84D00000029D97510E842000000EB28ACD1E8744D11C9EB1C9148C1E008ACE82C0000003D007D0000730A80FC05730683F87F770241419589E8B3015689FE29C6F3A45EEB8E00D275058A164610D2C3"
	strings:
		$1 = { 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 6A 40 FF D0 89 05 ?? ?? ?? ?? 89 C7 BE ?? ?? ?? ?? 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_2__EP__ExE_Pack {
	meta:
		tool = "P"
		name = "!EP"
		version = "1.4 lite final"
		extra = "ExePack"
		pattern = "33C08BC068????????68????????E8"
	strings:
		$1 = { 33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_3__EP__ExE_Pack {
	meta:
		tool = "P"
		name = "!EP"
		version = "1.4 lite b2"
		extra = "ExePack"
		pattern = "0000000000000000????????????????????????0000000000000000????????????????0000000000000000000000000000000000000000????????00000000????????????????????????000000004B45524E454C33322E444C4C005553455233322E444C4C00000047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C696272617279410000004D657373616765426F78410000000000EB4C476C6F62616C416C6C6F6300476C6F62616C46726565000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 55 53 45 52 33 32 2E 44 4C 4C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 00 00 00 00 EB 4C 47 6C 6F 62 61 6C 41 6C 6C 6F 63 00 47 6C 6F 62 61 6C 46 72 65 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_4__EP__ExE_Pack {
	meta:
		tool = "P"
		name = "!EP"
		version = "1.4 lite final"
		extra = "ExePack"
		pattern = "9090909061B8????????FFE0558BEC60558B75088B7D0CE802000000EB048B1C24C381C30002000053578B07890383C70483C3044E75F35F5EFCB2808A064688074702D275058A164612D273EF02D275058A164612D2734A33C002D275058A164612D20F83D600000002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C07406572BF88A075F880747EBA0B80100000002D275058A164612D213C002D275058A164612D272EA83E8027528B90100000002D275058A164612D213C902D275058A164612D272EA568BF72BF5F3A45EE958FFFFFF48C1E0088A06468BE8B90100000002D275058A164612D213C902D275058A164612D272EA3D007D0000731A3D00050000720E41568BF72BF0F3A45EE918FFFFFF83F87F770383C102568BF72BF0F3A45EE903FFFFFF8A064633C9C0E801741283D1028BE8568BF72BF0F3A45EE9E7FEFFFF5D2B7D0C897DFC615DC3"
	strings:
		$1 = { 90 90 90 90 61 B8 ?? ?? ?? ?? FF E0 55 8B EC 60 55 8B 75 08 8B 7D 0C E8 02 00 00 00 EB 04 8B 1C 24 C3 81 C3 00 02 00 00 53 57 8B 07 89 03 83 C7 04 83 C3 04 4E 75 F3 5F 5E FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 46 12 D2 73 EF 02 D2 75 05 8A 16 46 12 D2 73 4A 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 D6 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 74 06 57 2B F8 8A 07 5F 88 07 47 EB A0 B8 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 72 EA 83 E8 02 75 28 B9 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C9 02 D2 75 05 8A 16 46 12 D2 72 EA 56 8B F7 2B F5 F3 A4 5E E9 58 FF FF FF 48 C1 E0 08 8A 06 46 8B E8 B9 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C9 02 D2 75 05 8A 16 46 12 D2 72 EA 3D 00 7D 00 00 73 1A 3D 00 05 00 00 72 0E 41 56 8B F7 2B F0 F3 A4 5E E9 18 FF FF FF 83 F8 7F 77 03 83 C1 02 56 8B F7 2B F0 F3 A4 5E E9 03 FF FF FF 8A 06 46 33 C9 C0 E8 01 74 12 83 D1 02 8B E8 56 8B F7 2B F0 F3 A4 5E E9 E7 FE FF FF 5D 2B 7D 0C 89 7D FC 61 5D C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_5__EP__ExE_Pack {
	meta:
		tool = "P"
		name = "!EP"
		version = "3.60 - 4.06"
		extra = "ExePack"
		pattern = "8CC005????0E1FA3????03??????8EC08B??????8B??4F8BF7FDF3A4"
	strings:
		$1 = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 ?? ?? ?? 8E C0 8B ?? ?? ?? 8B ?? 4F 8B F7 FD F3 A4 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_6__pirit {
	meta:
		tool = "P"
		name = "$pirit"
		version = "1.5"
		pattern = "??????5B24555044FB322E315D"
	strings:
		$1 = { ?? ?? ?? 5B 24 55 50 44 FB 32 2E 31 5D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_7__pirit {
	meta:
		tool = "P"
		name = "$pirit"
		version = "1.5"
		pattern = "B44DCD21E8????FDE8????B451CD21"
	strings:
		$1 = { B4 4D CD 21 E8 ?? ?? FD E8 ?? ?? B4 51 CD 21 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_8____MSLRH {
	meta:
		tool = "P"
		name = "[MSLRH]"
		version = "0.31a"
		pattern = "60D1CB0FCAC1CAE0D1CA0FC8EB01F10FC0C9D2D10FC1C0D3DAC0D6A8EB01DED0EC0FC1CBD0CF0FC1D1D2DB0FC8EB01BCC0E9C6C1D0910FCBEB01730FCA87D987D2D0CF87D90FC8EB01C1EB01A286CAD0E10FC0CB0F"
	strings:
		$1 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_9___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [32Lite 0.03]"
		pattern = "6006FC1E07BE909090906A04689010909068"
	strings:
		$1 = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_10___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [Armadillo 3.00]"
		pattern = "60E82A0000005D5051EB0FB9EB0FB8EB07B9EB0F90EB08FDEB0BF2EBF5EBF6F2EB08FDEBE9F3EBE4FCE959585051EB85"
	strings:
		$1 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_11___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [CD-Cops II]"
		pattern = "5360BD909090908D45908D5D90E8000000008D01"
	strings:
		$1 = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_12___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [CodeSafe 2.0]"
		pattern = "90909090909090909090909090909090909090909090EB0B83EC10535657E8C4010085"
	strings:
		$1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_13___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [Crunch/PE Heuristic]"
		pattern = "55E80E0000005D83ED068BC5556089AD????????2B8500000000"
	strings:
		$1 = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_14___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [DxPack 1.0]"
		pattern = "60E8000000005D8BFD81ED909090902BB90000000081EF9090909083BD90909090900F8400000000"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_15___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [FSG 1.31]"
		pattern = "BE90909000BF90909000BB9090900053BB90909000B280"
	strings:
		$1 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_16___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [Gleam 1.00]"
		pattern = "90909090909090909090909090909090909090909090EB0B83EC0C535657E8240200FF"
	strings:
		$1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_17___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [JDPack 1.x / JDProtect 0.9]"
		pattern = "60E8220000005D8BD581ED909090902B959090909081EA0690909089959090909083BD4500010001"
	strings:
		$1 = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_18___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [LCC Win32 1.x]"
		pattern = "64A1010000005589E56AFF68????????689A10409050"
	strings:
		$1 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_19___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [Lockless Intro Pack]"
		pattern = "2CE8EB1A90905D8BC581EDF67390902B859090909083E8068985FF01ECAD"
	strings:
		$1 = { 2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_20___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [MEW 11 SE 1.0]"
		pattern = "E909000000000000020000000C90"
	strings:
		$1 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_21___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [MSVC 7.0 DLL]"
		pattern = "558D6C010081EC000000008B459083F801560F840000000085C00F84"
	strings:
		$1 = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_22___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [MinGW GCC 2.x]"
		pattern = "5589E5E802000000C9C39090455845"
	strings:
		$1 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_23___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [PE Pack 0.99]"
		pattern = "60E8110000005D83ED0680BDE0049090010F84F2FFCC0A"
	strings:
		$1 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_24___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [PE-Protect 0.9]"
		pattern = "525155576467A1300085C0780DE8070000005883C007C690C3"
	strings:
		$1 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_25___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [PE-SHiELD 0.25]"
		pattern = "60E82B0000009090909090909090909090909090909090909090909090909090909090909090909090909090909090CCCC"
	strings:
		$1 = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_26___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [REALBasic]"
		pattern = "5589E5909090909090909090905090909090900001"
	strings:
		$1 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_27___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [VBOX 4.3 MTE / Ste@lth PE 1.01]"
		pattern = "0BC00BC00BC00BC00BC00BC00BC00BC0"
	strings:
		$1 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_28___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 - 0.2 [VOB ProtectCD 5]"
		pattern = "363E268AC060E800000000"
	strings:
		$1 = { 36 3E 26 8A C0 60 E8 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_29___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [ACProtect 1.09]"
		pattern = "6090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090EB02000090909004909090909090909090909090909090909090909090"
	strings:
		$1 = { 60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_30___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Borland Delphi 3.0]"
		pattern = "558BEC83C49090909068????????9090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090"
	strings:
		$1 = { 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_31___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Borland Delphi 5.0 KOL/MCK]"
		pattern = "558BEC9090909068????????9090909090909090909090909090909090909090909090909090909000FF90909090909090900001909090909090909090EB0400000001909090909090900001909090909090909090"
	strings:
		$1 = { 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_32___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [DEF 1.0]"
		pattern = "BE000140006A0559807E070074118B46909090909090909090909090909090909083C101E9"
	strings:
		$1 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_33___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [ExeSmasher]"
		pattern = "9CFE039060BE909041908DBE9010FFFF5783CDFFEB1090909090909090909090909090909090FE0BE9"
	strings:
		$1 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
