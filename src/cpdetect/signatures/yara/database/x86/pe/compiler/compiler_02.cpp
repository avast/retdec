/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/compiler/compiler_02.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PeCompiler_02 =
R"x86_pe_compiler(rule rule_41_Borland_Delphi {
	meta:
		tool = "C"
		name = "Borland Delphi"
		version = "6.0"
		pattern = "538BD833C0A3????????6A00E8??????FFA3????????A1????????A3????????33C0A3????????33C0A3????????E8"
	strings:
		$1 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_42_Borland_Delphi {
	meta:
		tool = "C"
		name = "Borland Delphi"
		version = "6.0"
		pattern = "558BEC83C4F0B8????4500E8??????FFA1????45008B00E8????FFFF8B0D"
	strings:
		$1 = { 55 8B EC 83 C4 F0 B8 ?? ?? 45 00 E8 ?? ?? ?? FF A1 ?? ?? 45 00 8B 00 E8 ?? ?? FF FF 8B 0D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_43_Borland_Delphi {
	meta:
		tool = "C"
		name = "Borland Delphi"
		pattern = "C3E9??????FF8D40"
	strings:
		$1 = { C3 E9 ?? ?? ?? FF 8D 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_44_Borland_Pascal {
	meta:
		tool = "C"
		name = "Borland Pascal"
		version = "7.0 for Windows"
		pattern = "9AFFFF00009AFFFF00005589E531C09AFFFF0000"
	strings:
		$1 = { 9A FF FF 00 00 9A FF FF 00 00 55 89 E5 31 C0 9A FF FF 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_45_Borland_Pascal {
	meta:
		tool = "C"
		name = "Borland Pascal"
		version = "7.0 protected mode"
		pattern = "B8????BB????8ED08BE38CD88EC00E1FA1????25????A3????E8????833E??????75"
	strings:
		$1 = { B8 ?? ?? BB ?? ?? 8E D0 8B E3 8C D8 8E C0 0E 1F A1 ?? ?? 25 ?? ?? A3 ?? ?? E8 ?? ?? 83 3E ?? ?? ?? 75 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_46_Borland_Pascal {
	meta:
		tool = "C"
		name = "Borland Pascal"
		version = "7.0"
		pattern = "B8????8ED88C??????8CD38CC02BD88BC405????C1????03D8B4??CD210E"
	strings:
		$1 = { B8 ?? ?? 8E D8 8C ?? ?? ?? 8C D3 8C C0 2B D8 8B C4 05 ?? ?? C1 ?? ?? 03 D8 B4 ?? CD 21 0E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_47_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "0FBF44240853"
	strings:
		$1 = { 0F BF 44 24 08 53 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_48_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "0FBF44240856"
	strings:
		$1 = { 0F BF 44 24 08 56 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_49_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "33C040C20800"
	strings:
		$1 = { 33 C0 40 C2 08 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_50_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "33C040C20C00"
	strings:
		$1 = { 33 C0 40 C2 0C 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_51_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "33C040C3"
	strings:
		$1 = { 33 C0 40 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_52_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "33C0C20800"
	strings:
		$1 = { 33 C0 C2 08 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_53_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "33C0C20C00"
	strings:
		$1 = { 33 C0 C2 0C 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_54_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "33C0C21000"
	strings:
		$1 = { 33 C0 C2 10 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_55_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "33C0C3"
	strings:
		$1 = { 33 C0 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_56_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "538B5C240C83FB0C568B7424147207C74608"
	strings:
		$1 = { 53 8B 5C 24 0C 83 FB 0C 56 8B 74 24 14 72 07 C7 46 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_57_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "5533C08BEC"
	strings:
		$1 = { 55 33 C0 8B EC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_58_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "5589E58B45085DA3?????????801000000C20C00"
	strings:
		$1 = { 55 89 E5 8B 45 08 5D A3 ?? ?? ?? ?? ?8 01 00 00 00 C2 0C 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_59_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "558BEC2BC040C9C20C00"
	strings:
		$1 = { 55 8B EC 2B C0 40 C9 C2 0C 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_60_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "558BEC33C040C9C20C00"
	strings:
		$1 = { 55 8B EC 33 C0 40 C9 C2 0C 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_61_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "558BEC33C05DC20800"
	strings:
		$1 = { 55 8B EC 33 C0 5D C2 08 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_62_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "558BEC518B450C8945FC837DFC"
	strings:
		$1 = { 55 8B EC 51 8B 45 0C 89 45 FC 83 7D FC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_63_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "558BEC535657837D"
	strings:
		$1 = { 55 8B EC 53 56 57 83 7D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_64_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "558BEC53568B750C576A015F3BF7"
	strings:
		$1 = { 55 8B EC 53 56 8B 75 0C 57 6A 01 5F 3B F7 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_65_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "558BEC8B4508"
	strings:
		$1 = { 55 8B EC 8B 45 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_66_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "558BEC8B450C"
	strings:
		$1 = { 55 8B EC 8B 45 0C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_67_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "558BEC8B4510"
	strings:
		$1 = { 55 8B EC 8B 45 10 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_68_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "55B8010000008BEC81"
	strings:
		$1 = { 55 B8 01 00 00 00 8B EC 81 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_69_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "55B8010000008BEC83"
	strings:
		$1 = { 55 B8 01 00 00 00 8B EC 83 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_70_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "55B8010000008BEC8B"
	strings:
		$1 = { 55 B8 01 00 00 00 8B EC 8B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_71_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "56573EA120F0DFFF837C240C008BF80F85??0100008B742410568B466025FF"
	strings:
		$1 = { 56 57 3E A1 20 F0 DF FF 83 7C 24 0C 00 8B F8 0F 85 ?? 01 00 00 8B 74 24 10 56 8B 46 60 25 FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_72_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "5657BE010000008B442410"
	strings:
		$1 = { 56 57 BE 01 00 00 00 8B 44 24 10 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_73_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "5657BF010000008B742410"
	strings:
		$1 = { 56 57 BF 01 00 00 00 8B 74 24 10 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_74_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "568B74240C83FE0C578B7C24147207C74708"
	strings:
		$1 = { 56 8B 74 24 0C 83 FE 0C 57 8B 7C 24 14 72 07 C7 47 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_75_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "568B74240C85F6740F83FE01724883FE0276??83FE03753EE8"
	strings:
		$1 = { 56 8B 74 24 0C 85 F6 74 0F 83 FE 01 72 48 83 FE 02 76 ?? 83 FE 03 75 3E E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_76_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "68????????68????????FF742410FF742410E8????????C20800"
	strings:
		$1 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 74 24 10 FF 74 24 10 E8 ?? ?? ?? ?? C2 08 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_77_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "68????????FF74240CFF74240CE8????????33C0C20800"
	strings:
		$1 = { 68 ?? ?? ?? ?? FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? 33 C0 C2 08 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_78_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "68????????FF74240CFF74240CE8????????C20800"
	strings:
		$1 = { 68 ?? ?? ?? ?? FF 74 24 0C FF 74 24 0C E8 ?? ?? ?? ?? C2 08 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_79_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "68????????FF74240CFF74240CFF15????????C20800"
	strings:
		$1 = { 68 ?? ?? ?? ?? FF 74 24 0C FF 74 24 0C FF 15 ?? ?? ?? ?? C2 08 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_80_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "6A??5839442408750A8B4C2404890D????????C20C00"
	strings:
		$1 = { 6A ?? 58 39 44 24 08 75 0A 8B 4C 24 04 89 0D ?? ?? ?? ?? C2 0C 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_81_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "6A0158C20C00"
	strings:
		$1 = { 6A 01 58 C2 0C 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_82_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "81EC000100005355565733DB5333C068"
	strings:
		$1 = { 81 EC 00 01 00 00 53 55 56 57 33 DB 53 33 C0 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_83_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "81EC840100006A008D442404508D4C24"
	strings:
		$1 = { 81 EC 84 01 00 00 6A 00 8D 44 24 04 50 8D 4C 24 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_84_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "83EC6056576A008D4424??508D4C24??518D5424??52C74424"
	strings:
		$1 = { 83 EC 60 56 57 6A 00 8D 44 24 ?? 50 8D 4C 24 ?? 51 8D 54 24 ?? 52 C7 44 24 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_85_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "83EC606A008D4424??508D4C24??518D5424??52C74424"
	strings:
		$1 = { 83 EC 60 6A 00 8D 44 24 ?? 50 8D 4C 24 ?? 51 8D 54 24 ?? 52 C7 44 24 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_86_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "83EC608B4424688B4C2464"
	strings:
		$1 = { 83 EC 60 8B 44 24 68 8B 4C 24 64 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_87_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "9C60E8????????619D558BEC538B5D08568B750C85F6578B7D107509833D"
	strings:
		$1 = { 9C 60 E8 ?? ?? ?? ?? 61 9D 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_88_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "9C60E8????????619D6A??68????????E8????????33C0408945E4"
	strings:
		$1 = { 9C 60 E8 ?? ?? ?? ?? 61 9D 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_89_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "9C60E8????????619D6A??68????????E8????????33DB538B3D"
	strings:
		$1 = { 9C 60 E8 ?? ?? ?? ?? 61 9D 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 DB 53 8B 3D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_90_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "9C60E8????????619D6A??68????????E8????????33DB895DFC8D458050FF15"
	strings:
		$1 = { 9C 60 E8 ?? ?? ?? ?? 61 9D 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 DB 89 5D FC 8D 45 80 50 FF 15 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_91_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "9C60E8????????619D6A??68????????E8????????66813D000000014D5A"
	strings:
		$1 = { 9C 60 E8 ?? ?? ?? ?? 61 9D 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 81 3D 00 00 00 01 4D 5A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_92_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "9C60E8????????619D8BFF558BEC538B5D08568B750C85F6578B7D107509833D"
	strings:
		$1 = { 9C 60 E8 ?? ?? ?? ?? 61 9D 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_93_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "A1????????0FBF0853????????????????33????6A06890D????????FFD684C0"
	strings:
		$1 = { A1 ?? ?? ?? ?? 0F BF 08 53 ?? ?? ?? ?? ?? ?? ?? ?? 33 ?? ?? 6A 06 89 0D ?? ?? ?? ?? FF D6 84 C0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_94_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "A1????????568B742408578B3D????????6A008986????????A1"
	strings:
		$1 = { A1 ?? ?? ?? ?? 56 8B 74 24 08 57 8B 3D ?? ?? ?? ?? 6A 00 89 86 ?? ?? ?? ?? A1 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_95_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "A1????????568B7424088986A4000000A1????????898690000000"
	strings:
		$1 = { A1 ?? ?? ?? ?? 56 8B 74 24 08 89 86 A4 00 00 00 A1 ?? ?? ?? ?? 89 86 90 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_96_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "A1????????83EC208B0D????????53568B74242C578B56188986900000008D44240CC786A4000000"
	strings:
		$1 = { A1 ?? ?? ?? ?? 83 EC 20 8B 0D ?? ?? ?? ?? 53 56 8B 74 24 2C 57 8B 56 18 89 86 90 00 00 00 8D 44 24 0C C7 86 A4 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_97_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "A1????????83EC30833800760BB8010000C083C430C20800"
	strings:
		$1 = { A1 ?? ?? ?? ?? 83 EC 30 83 38 00 76 0B B8 01 00 00 C0 83 C4 30 C2 08 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_98_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "A1????????85C0740B3D4EE640BB7548EB02F3908B0D2403FE7F8B152003FE7F"
	strings:
		$1 = { A1 ?? ?? ?? ?? 85 C0 74 0B 3D 4E E6 40 BB 75 48 EB 02 F3 90 8B 0D 24 03 FE 7F 8B 15 20 03 FE 7F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_99_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "A1????????85C0B94EE640BB74??3BC1"
	strings:
		$1 = { A1 ?? ?? ?? ?? 85 C0 B9 4E E6 40 BB 74 ?? 3B C1 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_100_CODE_DLL {
	meta:
		tool = "C"
		name = "CODE-DLL"
		pattern = "A1????????8B0035????????A3????????E9"
	strings:
		$1 = { A1 ?? ?? ?? ?? 8B 00 35 ?? ?? ?? ?? A3 ?? ?? ?? ?? E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
})x86_pe_compiler";
