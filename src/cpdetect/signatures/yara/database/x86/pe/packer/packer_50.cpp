/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_50.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_50 =
R"x86_pe_packer(
rule rule_1353_Splice {
	meta:
		tool = "P"
		name = "Splice"
		version = "1.1"
		pattern = "68001A4000E8EEFFFFFF000000000000300000004000000000000000????????????????????????????????00000000000001000000????????????50726F6A6563743100??????????????0000000006000000AC29400007000000BC2840000700000074284000070000002C2840000700000008234000010000003821400000000000FFFFFFFFFFFFFFFF000000008C21400008??400001000000AC194000000000000000000000000000AC1940004F00430050000000E7AF582F9A4C174DB7A9CA3E576FF776"
	strings:
		$1 = { 68 00 1A 40 00 E8 EE FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 01 00 00 00 ?? ?? ?? ?? ?? ?? 50 72 6F 6A 65 63 74 31 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 06 00 00 00 AC 29 40 00 07 00 00 00 BC 28 40 00 07 00 00 00 74 28 40 00 07 00 00 00 2C 28 40 00 07 00 00 00 08 23 40 00 01 00 00 00 38 21 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 8C 21 40 00 08 ?? 40 00 01 00 00 00 AC 19 40 00 00 00 00 00 00 00 00 00 00 00 00 00 AC 19 40 00 4F 00 43 00 50 00 00 00 E7 AF 58 2F 9A 4C 17 4D B7 A9 CA 3E 57 6F F7 76 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1354_ST_Protector {
	meta:
		tool = "P"
		name = "ST Protector"
		version = "1.5"
		pattern = "000000004B65526E456C33322E644C6C000047657450726F634164647265737300004C6F61644C696272617279410000"
	strings:
		$1 = { 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1355_STABSTR {
	meta:
		tool = "P"
		name = "STABSTR"
		pattern = "5589E583EC14538B4D088B450C8B5510BB0100000083F801740E724483F802746F83F8037472EB7E890D????????C705????????010000008915????????83C4F8"
	strings:
		$1 = { 55 89 E5 83 EC 14 53 8B 4D 08 8B 45 0C 8B 55 10 BB 01 00 00 00 83 F8 01 74 0E 72 44 83 F8 02 74 6F 83 F8 03 74 72 EB 7E 89 0D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 89 15 ?? ?? ?? ?? 83 C4 F8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1356_StarForce {
	meta:
		tool = "P"
		name = "StarForce"
		version = "1.x - 5.x"
		pattern = "68????????FF25????????0000000000"
	strings:
		$1 = { 68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1357_StarForce {
	meta:
		tool = "P"
		name = "StarForce"
		version = "3.0"
		pattern = "68????????FF25????63"
	strings:
		$1 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 63 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1358_StarForce {
	meta:
		tool = "P"
		name = "StarForce"
		version = "3.x"
		pattern = "E8????????000000000000"
	strings:
		$1 = { E8 ?? ?? ?? ?? 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1359_StarForce {
	meta:
		tool = "P"
		name = "StarForce"
		version = "1.1"
		extra = "ProActive"
		pattern = "68????????FF25????57"
	strings:
		$1 = { 68 ?? ?? ?? ?? FF 25 ?? ?? 57 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1360_StarForce {
	meta:
		tool = "P"
		name = "StarForce"
		extra = "Protection Driver"
		pattern = "5768??0D01006800????00E850??FFFF68??????0068??????0068??????0068??????0068??????00"
	strings:
		$1 = { 57 68 ?? 0D 01 00 68 00 ?? ?? 00 E8 50 ?? FF FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1361_Ste_lth {
	meta:
		tool = "P"
		name = "Ste@lth"
		pattern = "??????????B8??????0050C3"
	strings:
		$1 = { ?? ?? ?? ?? ?? B8 ?? ?? ?? 00 50 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1362_Ste_lth {
	meta:
		tool = "P"
		name = "Ste@lth"
		pattern = "??????????B9??????0051C3"
	strings:
		$1 = { ?? ?? ?? ?? ?? B9 ?? ?? ?? 00 51 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1363_Ste_lth {
	meta:
		tool = "P"
		name = "Ste@lth"
		pattern = "??????????BB??????0053C3"
	strings:
		$1 = { ?? ?? ?? ?? ?? BB ?? ?? ?? 00 53 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1364_Ste_lth {
	meta:
		tool = "P"
		name = "Ste@lth"
		version = "1.01"
		pattern = "??????????BA??????00"
	strings:
		$1 = { ?? ?? ?? ?? ?? BA ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1365_Stealth_PE {
	meta:
		tool = "P"
		name = "Stealth PE"
		version = "1.1"
		pattern = "BA??????00FFE2BA??????00B8????????890283C203B8????????890283C2FDFFE2"
	strings:
		$1 = { BA ?? ?? ?? 00 FF E2 BA ?? ?? ?? 00 B8 ?? ?? ?? ?? 89 02 83 C2 03 B8 ?? ?? ?? ?? 89 02 83 C2 FD FF E2 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1366_Stone_s_PE_Encryptor {
	meta:
		tool = "P"
		name = "Stone's PE Encryptor"
		version = "1.0 - 1.13"
		pattern = "555756525153E8????????5D8BD581"
	strings:
		$1 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1367_Stone_s_PE_Encryptor {
	meta:
		tool = "P"
		name = "Stone's PE Encryptor"
		version = "2.0"
		pattern = "535152565755E8????????5D81ED423040??FF95323540??B8373040??03C52B851B3440??8985273440??83"
	strings:
		$1 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1368_STUD_RC4 {
	meta:
		tool = "P"
		name = "STUD RC4"
		version = "1.0 Jamie Edition"
		pattern = "682C114000E8F0FFFFFF00000000000030000000380000000000000037BB71ECA4E1984C9BFE8F0FFA6A07F6000000000000010000002020466F7220737475640020546F0000000006000000CC1A400007000000D4184000070000007C184000070000002C18400007000000E017400056423521F01F2A000000000000000000000000007E000000000000000000000000000A000904000000000000E8134000F413400000F0300000FFFFFF080000000100000000000000E90000000411400004114000C8104000780000007C00000081000000820000000000000000000000000000000000000061616100537475640000737475640000010001003016400000000000FFFFFFFFFFFFFFFF00000000B41640001030400007000000241240000E002000000000001C9E2100EC1140005C104000E41A40002C3440006817400058174000781740008C1740008C1040006210400092104000F81A400024194000981040009E104000770418FF041CFF0500002401000D1400781C400048214000"
	strings:
		$1 = { 68 2C 11 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30 00 00 00 38 00 00 00 00 00 00 00 37 BB 71 EC A4 E1 98 4C 9B FE 8F 0F FA 6A 07 F6 00 00 00 00 00 00 01 00 00 00 20 20 46 6F 72 20 73 74 75 64 00 20 54 6F 00 00 00 00 06 00 00 00 CC 1A 40 00 07 00 00 00 D4 18 40 00 07 00 00 00 7C 18 40 00 07 00 00 00 2C 18 40 00 07 00 00 00 E0 17 40 00 56 42 35 21 F0 1F 2A 00 00 00 00 00 00 00 00 00 00 00 00 00 7E 00 00 00 00 00 00 00 00 00 00 00 00 00 0A 00 09 04 00 00 00 00 00 00 E8 13 40 00 F4 13 40 00 00 F0 30 00 00 FF FF FF 08 00 00 00 01 00 00 00 00 00 00 00 E9 00 00 00 04 11 40 00 04 11 40 00 C8 10 40 00 78 00 00 00 7C 00 00 00 81 00 00 00 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 61 61 61 00 53 74 75 64 00 00 73 74 75 64 00 00 01 00 01 00 30 16 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 B4 16 40 00 10 30 40 00 07 00 00 00 24 12 40 00 0E 00 20 00 00 00 00 00 1C 9E 21 00 EC 11 40 00 5C 10 40 00 E4 1A 40 00 2C 34 40 00 68 17 40 00 58 17 40 00 78 17 40 00 8C 17 40 00 8C 10 40 00 62 10 40 00 92 10 40 00 F8 1A 40 00 24 19 40 00 98 10 40 00 9E 10 40 00 77 04 18 FF 04 1C FF 05 00 00 24 01 00 0D 14 00 78 1C 40 00 48 21 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1369_SuckStop {
	meta:
		tool = "P"
		name = "SuckStop"
		version = "1.11"
		pattern = "EB??????BE????B430CD21EB??9B"
	strings:
		$1 = { EB ?? ?? ?? BE ?? ?? B4 30 CD 21 EB ?? 9B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1370_SuperDAT {
	meta:
		tool = "P"
		name = "SuperDAT"
		pattern = "558BEC6AFF6840F3420068A4BF420064A100000000506489250000000083EC585356578965E8FF1508F2420033D28AD48915604243008BC881E1FF000000890D"
	strings:
		$1 = { 55 8B EC 6A FF 68 40 F3 42 00 68 A4 BF 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 08 F2 42 00 33 D2 8A D4 89 15 60 42 43 00 8B C8 81 E1 FF 00 00 00 89 0D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1371_SVK_Protector {
	meta:
		tool = "P"
		name = "SVK-Protector"
		version = "1.051"
		pattern = "60EB03C784E8EB03C7849AE8000000005D81ED10000000EB03C784E964A023000000EB"
	strings:
		$1 = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1372_SVK_Protector {
	meta:
		tool = "P"
		name = "SVK-Protector"
		version = "1.11"
		pattern = "60E8????????5D81ED06??????64A023"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1373_SVK_Protector {
	meta:
		tool = "P"
		name = "SVK-Protector"
		version = "1.3x"
		pattern = "60E8000000005D81ED06000000EB05B8????420064A023"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? 42 00 64 A0 23 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1374_SVK_Protector {
	meta:
		tool = "P"
		name = "SVK-Protector"
		version = "1.43"
		pattern = "784E884C0EB03C784E97567B9490000008DB5C502000056?"
	strings:
		$1 = { 78 4E 88 4C 0E B0 3C 78 4E 97 56 7B 94 90 00 00 08 DB 5C 50 20 00 05 6? }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1375_SVKP {
	meta:
		tool = "P"
		name = "SVK-Protector"
		pattern = "60E8????????5D81ED06000000EB05B8????????64A023000000EB03C784E8????????C784E9"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? ?? ?? 64 A0 23 00 00 00 EB 03 C7 84 E8 ?? ?? ?? ?? C7 84 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1376_SYMANTEC_FILE {
	meta:
		tool = "P"
		name = "SYMANTEC FILE"
		pattern = "EB08????????00000000??0B??????????05E8??00000052FF7424??FF7424??FF7424CCFF7424??E806000000??0890??05??C21000"
	strings:
		$1 = { EB 08 ?? ?? ?? ?? 00 00 00 00 ?? 0B ?? ?? ?? ?? ?? 05 E8 ?? 00 00 00 52 FF 74 24 ?? FF 74 24 ?? FF 74 24 CC FF 74 24 ?? E8 06 00 00 00 ?? 08 90 ?? 05 ?? C2 10 00 }
	condition:
		for any of them : ( $ in (pe.entry_point .. pe.entry_point + 4) )
}
rule rule_1377_SYMANTEC_FILE {
	meta:
		tool = "P"
		name = "SYMANTEC FILE"
		pattern = "EB08????????000000006A17E80D0000006A30E8060000007A08907B0569C204004152780B51525A597905E80200000053FF7424F4FF742438FF74246C"
	strings:
		$1 = { EB 08 ?? ?? ?? ?? 00 00 00 00 6A 17 E8 0D 00 00 00 6A 30 E8 06 00 00 00 7A 08 90 7B 05 69 C2 04 00 41 52 78 0B 51 52 5A 59 79 05 E8 02 00 00 00 53 FF 74 24 F4 FF 74 24 38 FF 74 24 6C }
	condition:
		for any of them : ( $ in (pe.entry_point .. pe.entry_point + 4) )
}
rule rule_1378_T_PACK {
	meta:
		tool = "P"
		name = "T-PACK"
		version = "0.5c -m1"
		pattern = "68????FD60BE????BF????B9????F3A48BF7BF????FC46E98EFE"
	strings:
		$1 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 8E FE }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1379_T_PACK {
	meta:
		tool = "P"
		name = "T-PACK"
		version = "0.5c -m2"
		pattern = "68????FD60BE????BF????B9????F3A48BF7BF????FC46E9CEFD"
	strings:
		$1 = { 68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 CE FD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1380_TaiShanXiangYu_LockSoft {
	meta:
		tool = "P"
		name = "TaiShanXiangYu LockSoft"
		version = "1.0"
		pattern = "E803000000EB01??BB55000000E803000000EB01??E88F000000E803000000EB01??E882000000E803000000EB01??E8B8000000E803000000EB01??E8AB000000E803000000EB01??83FB55E803000000EB01??752EE803000000EB01??C360E8000000005D81EDE30042008BD581C23201420052E801000000C3C3E803000000EB01??E80E000000E8D1FFFFFFC3E803000000EB01??33C064FF30648920CCC3E803000000EB01??33C064FF306489204BCCC3E803000000EB01??33DBB9????????81??????????8BD581??????????8D3A8BF733C0E803000000EB01??E817000000??????E9????????33C064FF3064892043CCC3"
	strings:
		$1 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED E3 00 42 00 8B D5 81 C2 32 01 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 8B D5 81 ?? ?? ?? ?? ?? 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 64 FF 30 64 89 20 43 CC C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1381_TaiShanXiangYu_LockSoft {
	meta:
		tool = "P"
		name = "TaiShanXiangYu LockSoft"
		version = "1.0 DLL"
		pattern = "60E8000000005D81EDE30042008BD581C23201420052E801000000C3C3E803000000EB01??E80E000000E8D1FFFFFFC3E803000000EB01??33C064FF30648920CCC3E803000000EB01??33C064FF306489204BCCC3E803000000EB01??33DBB9AF28420081E9DD0142008BD581C2DD0142008D3A8BF733C0E803000000EB01??E817000000909090E97820000033C064FF3064892043CCC390EB01??AC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED E3 00 42 00 8B D5 81 C2 32 01 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 AF 28 42 00 81 E9 DD 01 42 00 8B D5 81 C2 DD 01 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 78 20 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 90 EB 01 ?? AC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1382_TARMA {
	meta:
		tool = "P"
		name = "TARMA"
		pattern = "54495A31"
	strings:
		$1 = { 54 49 5A 31 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1383_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.41x"
		pattern = "668BC08D2424EB01EB60EB01EB9CE8000000005E83C6508BFE687801????59EB01EBAC54E803??????5CEB08"
	strings:
		$1 = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 50 8B FE 68 78 01 ?? ?? 59 EB 01 EB AC 54 E8 03 ?? ?? ?? 5C EB 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1384_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.42"
		pattern = "C1EE00668BC9EB01EB60EB01EB9CE8000000005E83C6528BFE68790159EB01EBAC54E8035CEB08"
	strings:
		$1 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 52 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1385_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.51"
		pattern = "C1EE00668BC9EB01EB60EB01EB9CE8000000005E83C65E8BFE687901000059EB01EBAC54E8030000005CEB088D642404FF6424FC6A05D02C247201E80124245CF7DCEB02CD208D6424FEF7DCEB02CD20FEC8E80000000032C1EB02820DAAEB03820D58EB021D7A49EB05E8010000007FAE147EA077767574"
	strings:
		$1 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 00 00 59 EB 01 EB AC 54 E8 03 00 00 00 5C EB 08 8D 64 24 04 FF 64 24 FC 6A 05 D0 2C 24 72 01 E8 01 24 24 5C F7 DC EB 02 CD 20 8D 64 24 FE F7 DC EB 02 CD 20 FE C8 E8 00 00 00 00 32 C1 EB 02 82 0D AA EB 03 82 0D 58 EB 02 1D 7A 49 EB 05 E8 01 00 00 00 7F AE 14 7E A0 77 76 75 74 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1386_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.51"
		pattern = "C1EE00668BC9EB01EB60EB01EB9CE8000000005E83C65E8BFE68790159EB01EBAC54E8035CEB08"
	strings:
		$1 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1387_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.60"
		pattern = "E90000000060E8000000005883C008"
	strings:
		$1 = { E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
