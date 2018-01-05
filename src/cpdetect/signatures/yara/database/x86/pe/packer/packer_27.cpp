/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_27.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_27 =
R"x86_pe_packer(
rule rule_749_kkrunchy {
	meta:
		tool = "P"
		name = "kkrunchy"
		version = "0.17"
		pattern = "FCFF4D0831D28D7D30BE"
	strings:
		$1 = { FC FF 4D 08 31 D2 8D 7D 30 BE }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_750_kkrunchy {
	meta:
		tool = "P"
		name = "kkrunchy"
		version = "0.23a2"
		pattern = "BD????????C74500??????00B8??????0089450489455450C74510??????00FF4D0CFF4514FF4558C6451C08B8000800008D7D30ABABABABBB0000D800BF"
	strings:
		$1 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_751_Krypton {
	meta:
		tool = "P"
		name = "Krypton"
		version = "0.2"
		pattern = "8B0C24E90A7C01??AD4240BDBE9D7A04"
	strings:
		$1 = { 8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_752_Krypton {
	meta:
		tool = "P"
		name = "Krypton"
		version = "0.3"
		pattern = "8B0C24E9C08D01??C13A6ECA5D7E796DB3645A71EA"
	strings:
		$1 = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_753_Krypton {
	meta:
		tool = "P"
		name = "Krypton"
		version = "0.4"
		pattern = "54E8????????5D8BC581ED6134????2B856037????83E806"
	strings:
		$1 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 61 34 ?? ?? 2B 85 60 37 ?? ?? 83 E8 06 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_754_Krypton {
	meta:
		tool = "P"
		name = "Krypton"
		version = "0.5"
		pattern = "54E8????????5D8BC581ED7144????2B856460????EB43DF"
	strings:
		$1 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_755_kryptor {
	meta:
		tool = "P"
		name = "kryptor"
		pattern = "EB6687DB"
	strings:
		$1 = { EB 66 87 DB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_756_kryptor {
	meta:
		tool = "P"
		name = "kryptor"
		pattern = "EB6A87DB"
	strings:
		$1 = { EB 6A 87 DB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_757_kryptor {
	meta:
		tool = "P"
		name = "kryptor"
		version = "5"
		pattern = "E803??????E9EB6C5840FFE0"
	strings:
		$1 = { E8 03 ?? ?? ?? E9 EB 6C 58 40 FF E0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_758_kryptor {
	meta:
		tool = "P"
		name = "kryptor"
		version = "6"
		pattern = "E803??????E9EB685833D27402E9E940427502"
	strings:
		$1 = { E8 03 ?? ?? ?? E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_759_kryptor {
	meta:
		tool = "P"
		name = "kryptor"
		version = "9"
		pattern = "60E8????????5EB9????????2BC002040ED3C04979F8418D7E2C3346??66B9"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_760_LameCrypt {
	meta:
		tool = "P"
		name = "LameCrypt"
		version = "1.0"
		pattern = "60669CBB????????80B300104000904B83FBFF75F3669D61"
	strings:
		$1 = { 60 66 9C BB ?? ?? ?? ?? 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_761_LamerStop {
	meta:
		tool = "P"
		name = "LamerStop"
		version = "1.0c"
		source = "(c) Stefan Esser"
		pattern = "E8????05????CD2133C08EC026??????2E??????26??????2E??????BA????FA"
	strings:
		$1 = { E8 ?? ?? 05 ?? ?? CD 21 33 C0 8E C0 26 ?? ?? ?? 2E ?? ?? ?? 26 ?? ?? ?? 2E ?? ?? ?? BA ?? ?? FA }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_762_LARP {
	meta:
		tool = "P"
		name = "LARP"
		version = "2.0"
		pattern = "E80100000081E8020000008184E8EF0100008184E80100000064E802000000E881E881000000C38184E80400000001310000506823314000E8A10100008168D71740003BD10F87320400000F8652280000818468F117400085C90F85842800000F844204000081E8D4180000685B50E8760100008184681418400068B32C400085C00F84272800000F85FA0300008184588304240183C4040BE47404FF6424FC81E84B01000081E80100000084E8060000008184740081840BE474????????????000BE47402FFE081E80000000068????????E80200000075BAF872027302??????????????????????00E8FA00000081840BE47427E8EF0000008184E80100000050E80200000081840BE4E8D900000081847408????????????FFE2"
	strings:
		$1 = { E8 01 00 00 00 81 E8 02 00 00 00 81 84 E8 EF 01 00 00 81 84 E8 01 00 00 00 64 E8 02 00 00 00 E8 81 E8 81 00 00 00 C3 81 84 E8 04 00 00 00 01 31 00 00 50 68 23 31 40 00 E8 A1 01 00 00 81 68 D7 17 40 00 3B D1 0F 87 32 04 00 00 0F 86 52 28 00 00 81 84 68 F1 17 40 00 85 C9 0F 85 84 28 00 00 0F 84 42 04 00 00 81 E8 D4 18 00 00 68 5B 50 E8 76 01 00 00 81 84 68 14 18 40 00 68 B3 2C 40 00 85 C0 0F 84 27 28 00 00 0F 85 FA 03 00 00 81 84 58 83 04 24 01 83 C4 04 0B E4 74 04 FF 64 24 FC 81 E8 4B 01 00 00 81 E8 01 00 00 00 84 E8 06 00 00 00 81 84 74 00 81 84 0B E4 74 ?? ?? ?? ?? ?? ?? 00 0B E4 74 02 FF E0 81 E8 00 00 00 00 68 ?? ?? ?? ?? E8 02 00 00 00 75 BA F8 72 02 73 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 E8 FA 00 00 00 81 84 0B E4 74 27 E8 EF 00 00 00 81 84 E8 01 00 00 00 50 E8 02 00 00 00 81 84 0B E4 E8 D9 00 00 00 81 84 74 08 ?? ?? ?? ?? ?? ?? FF E2 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_763_Lattice_C {
	meta:
		tool = "P"
		name = "Lattice C"
		version = "1.01"
		pattern = "FAB8????05????B1??D3E88CCB03C38ED88ED026????????2BD8F7??????75??B1??D3E3EB"
	strings:
		$1 = { FA B8 ?? ?? 05 ?? ?? B1 ?? D3 E8 8C CB 03 C3 8E D8 8E D0 26 ?? ?? ?? ?? 2B D8 F7 ?? ?? ?? 75 ?? B1 ?? D3 E3 EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_764_Lattice_C {
	meta:
		tool = "P"
		name = "Lattice C"
		version = "3.0"
		pattern = "FAB8????8ED8B8????8E"
	strings:
		$1 = { FA B8 ?? ?? 8E D8 B8 ?? ?? 8E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_765_LaunchAnywhere {
	meta:
		tool = "P"
		name = "LaunchAnywhere"
		version = "4.0.0.1"
		pattern = "55589E55383EC4855B8FFFFFFFF505068E03E420064FF35000000006489250000000068C0694400E8E480FFFF59E84E290000E8C90D000085C075086AFFE86E2B000059E8A82C0000E8232E0000FF154CC2440089C3EB193C22751489C08D4000438A0384C074043C2275F53C227501438A0384C0740B3C2074073C0975D9EB01438A0384C074043C207EF58D45B850FF15E4C144008B45E4250100000074060FB745E8EB05B80A?"
	strings:
		$1 = { 55 58 9E 55 38 3E C4 85 5B 8F FF FF FF F5 05 06 8E 03 E4 20 06 4F F3 50 00 00 00 06 48 92 50 00 00 00 06 8C 06 94 40 0E 8E 48 0F FF F5 9E 84 E2 90 00 0E 8C 90 D0 00 08 5C 07 50 86 AF FE 86 E2 B0 00 05 9E 8A 82 C0 00 0E 82 32 E0 00 0F F1 54 CC 24 40 08 9C 3E B1 93 C2 27 51 48 9C 08 D4 00 04 38 A0 38 4C 07 40 43 C2 27 5F 53 C2 27 50 14 38 A0 38 4C 07 40 B3 C2 07 40 73 C0 97 5D 9E B0 14 38 A0 38 4C 07 40 43 C2 07 EF 58 D4 5B 85 0F F1 5E 4C 14 40 08 B4 5E 42 50 10 00 00 07 40 60 FB 74 5E 8E B0 5B 80 A? }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_766_Launcher_Generator {
	meta:
		tool = "P"
		name = "Launcher Generator"
		version = "1.03"
		pattern = "680020400068102040006A006A006A206A006A006A0068F02240006A00E89300000085C00F847E000000B8000000003B056820400074136A??686023400068202340006A00E883000000A1582040003B056C2040007451C1E002A35C204000BB7021400003C38B18686020400053B8F021400003055C2040008BD88B03057020400050B87022400003055C204000FF30FF3500204000E826000000A15820400040A358204000EB"
	strings:
		$1 = { 68 00 20 40 00 68 10 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 68 F0 22 40 00 6A 00 E8 93 00 00 00 85 C0 0F 84 7E 00 00 00 B8 00 00 00 00 3B 05 68 20 40 00 74 13 6A ?? 68 60 23 40 00 68 20 23 40 00 6A 00 E8 83 00 00 00 A1 58 20 40 00 3B 05 6C 20 40 00 74 51 C1 E0 02 A3 5C 20 40 00 BB 70 21 40 00 03 C3 8B 18 68 60 20 40 00 53 B8 F0 21 40 00 03 05 5C 20 40 00 8B D8 8B 03 05 70 20 40 00 50 B8 70 22 40 00 03 05 5C 20 40 00 FF 30 FF 35 00 20 40 00 E8 26 00 00 00 A1 58 20 40 00 40 A3 58 20 40 00 EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_767_LGLZ {
	meta:
		tool = "P"
		name = "LGLZ"
		version = "1.04 COM"
		pattern = "BF????3BFC7219B409BA1201CD21B44CCD21"
	strings:
		$1 = { BF ?? ?? 3B FC 72 19 B4 09 BA 12 01 CD 21 B4 4C CD 21 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_768_LGLZ {
	meta:
		tool = "P"
		name = "LGLZ"
		version = "1.04b"
		pattern = "FC1E060E8CC8????????BA????03C28BD805????8EDB8EC033F633FFB9????F3A54B484A79"
	strings:
		$1 = { FC 1E 06 0E 8C C8 ?? ?? ?? ?? BA ?? ?? 03 C2 8B D8 05 ?? ?? 8E DB 8E C0 33 F6 33 FF B9 ?? ?? F3 A5 4B 48 4A 79 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_769_LOCK98 {
	meta:
		tool = "P"
		name = "LOCK98"
		version = "1.00.28"
		pattern = "55E8000000005D81??????????EB05E9????????EB08"
	strings:
		$1 = { 55 E8 00 00 00 00 5D 81 ?? ?? ?? ?? ?? EB 05 E9 ?? ?? ?? ?? EB 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_770_LOCKED {
	meta:
		tool = "P"
		name = "LOCKED?"
		pattern = "2923BE84E16CD6AE529049F1F1BBE9EBB3A6DB3C870C3E99245E0D1C06B747DEB3124DC843BB8BA61F035A7D0938251F"
	strings:
		$1 = { 29 23 BE 84 E1 6C D6 AE 52 90 49 F1 F1 BB E9 EB B3 A6 DB 3C 87 0C 3E 99 24 5E 0D 1C 06 B7 47 DE B3 12 4D C8 43 BB 8B A6 1F 03 5A 7D 09 38 25 1F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_771_Lockless_Intro_Pack {
	meta:
		tool = "P"
		name = "Lockless Intro Pack"
		pattern = "2CE8????????5D8BC581EDF673????2B85????????83E8068985"
	strings:
		$1 = { 2C E8 ?? ?? ?? ?? 5D 8B C5 81 ED F6 73 ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 06 89 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_772_LTC {
	meta:
		tool = "P"
		name = "LTC"
		version = "1.3"
		pattern = "54E8000000005D8BC581EDF67340002B858775400083E806"
	strings:
		$1 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_773_LY_WGKX {
	meta:
		tool = "P"
		name = "LY_WGKX"
		pattern = "4D7946756E006273"
	strings:
		$1 = { 4D 79 46 75 6E 00 62 73 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_774_LY_WGKX {
	meta:
		tool = "P"
		name = "LY_WGKX"
		version = "2.x"
		pattern = "00000000????????0000000000000000????????????????00000000000000000000000000000000000000004C59????????????????????00000000????????000000000000000000000000????????00000000000000000000000001004D7946756E0062730000"
	strings:
		$1 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C 59 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 01 00 4D 79 46 75 6E 00 62 73 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_775_Macromedia_Windows_Flash_Projector_Player {
	meta:
		tool = "P"
		name = "Macromedia Windows Flash Projector"
		version = "4.0"
		pattern = "83EC4456FF15244143008BF08A063C22751C8A4601463C22740C84C074088A4601463C2275F4803E22750F46EB0C"
	strings:
		$1 = { 83 EC 44 56 FF 15 24 41 43 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_776_Macromedia_Windows_Flash_Projector_Player {
	meta:
		tool = "P"
		name = "Macromedia Windows Flash Projector"
		version = "5.0"
		pattern = "83EC4456FF15706144008BF08A063C22751C8A4601463C22740C84C074088A4601463C2275F4803E22750F46EB0C3C207E088A4601463C207FF88A0684C0740C3C207F088A46014684C075F48D442404C74424300000000050FF1580614400F644243001740B8B44243425FFFF0000EB05B80A00000050566A006A00FF157461440050E81800000050FF15786144005E83C444C3909090909090"
	strings:
		$1 = { 83 EC 44 56 FF 15 70 61 44 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74 0C 3C 20 7F 08 8A 46 01 46 84 C0 75 F4 8D 44 24 04 C7 44 24 30 00 00 00 00 50 FF 15 80 61 44 00 F6 44 24 30 01 74 0B 8B 44 24 34 25 FF FF 00 00 EB 05 B8 0A 00 00 00 50 56 6A 00 6A 00 FF 15 74 61 44 00 50 E8 18 00 00 00 50 FF 15 78 61 44 00 5E 83 C4 44 C3 90 90 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_777_Macromedia_Windows {
	meta:
		tool = "P"
		name = "Macromedia Windows"
		version = "6.0"
		pattern = "83EC4456FF15248149008BF08A063C22751C8A4601463C22740C84C074088A4601463C2275F4803E22750F46EB0C"
	strings:
		$1 = { 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_778_MarjinZ_EXE_Scrambler_SE {
	meta:
		tool = "P"
		name = "MarjinZ EXE-Scrambler SE"
		pattern = "E8A3020000E935FDFFFFFF25C82000106A1468C0210010E8E4010000FF357C3300108B358C200010FFD6598945E483F8FF750CFF7508FF158820001059EB616A08E802030000598365FC00FF357C330010FFD68945E4FF3578330010FFD68945E08D45E0508D45E450FF7508E8D10200008945DCFF75E48B3574200010FFD6A37C330010FF75E0FFD683C41CA378330010C745FCFEFFFFFFE8090000008B45DCE8A0010000C3"
	strings:
		$1 = { E8 A3 02 00 00 E9 35 FD FF FF FF 25 C8 20 00 10 6A 14 68 C0 21 00 10 E8 E4 01 00 00 FF 35 7C 33 00 10 8B 35 8C 20 00 10 FF D6 59 89 45 E4 83 F8 FF 75 0C FF 75 08 FF 15 88 20 00 10 59 EB 61 6A 08 E8 02 03 00 00 59 83 65 FC 00 FF 35 7C 33 00 10 FF D6 89 45 E4 FF 35 78 33 00 10 FF D6 89 45 E0 8D 45 E0 50 8D 45 E4 50 FF 75 08 E8 D1 02 00 00 89 45 DC FF 75 E4 8B 35 74 20 00 10 FF D6 A3 7C 33 00 10 FF 75 E0 FF D6 83 C4 1C A3 78 33 00 10 C7 45 FC FE FF FF FF E8 09 00 00 00 8B 45 DC E8 A0 01 00 00 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_779_MaskPE {
	meta:
		tool = "P"
		name = "MaskPE"
		version = "1.6"
		pattern = "36812C24??????00C360"
	strings:
		$1 = { 36 81 2C 24 ?? ?? ?? 00 C3 60 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_780_MaskPE {
	meta:
		tool = "P"
		name = "MaskPE"
		version = "2.0"
		pattern = "B818000000648B1883C330C3403E0FB600C1E0??83C0??36010424C3"
	strings:
		$1 = { B8 18 00 00 00 64 8B 18 83 C3 30 C3 40 3E 0F B6 00 C1 E0 ?? 83 C0 ?? 36 01 04 24 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_781_Matrix_Dongle {
	meta:
		tool = "P"
		name = "Matrix Dongle"
		pattern = "000000000000000000000000????????????????0000000000000000000000000000000000000000????????????????0000000000004C6F61644C6962726172794100000047657450726F6341646472657373004B45524E454C33322E444C4C00E8B6000000000000000000????????????E8000000005B2BD98BF88B4C242C33C02BCFF2AA8B3C248B0A2BCF895C24208037A2474975F98D642404FF6424FC60C74208????????E8C5FFFFFFC3C2F7294E295A29E6868A89635CA265E2A3A2"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 E8 B6 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? E8 00 00 00 00 5B 2B D9 8B F8 8B 4C 24 2C 33 C0 2B CF F2 AA 8B 3C 24 8B 0A 2B CF 89 5C 24 20 80 37 A2 47 49 75 F9 8D 64 24 04 FF 64 24 FC 60 C7 42 08 ?? ?? ?? ?? E8 C5 FF FF FF C3 C2 F7 29 4E 29 5A 29 E6 86 8A 89 63 5C A2 65 E2 A3 A2 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_782_Matrix_Dongle {
	meta:
		tool = "P"
		name = "Matrix Dongle"
		pattern = "E800000000E800000000595A2BCA2BD1E81AFFFFFF"
	strings:
		$1 = { E8 00 00 00 00 E8 00 00 00 00 59 5A 2B CA 2B D1 E8 1A FF FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_783_May_be_PKLite_Header {
	meta:
		tool = "P"
		name = "May be PKLite Header"
		version = "6.xx"
		pattern = "????506B"
	strings:
		$1 = { ?? ?? 50 6B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_784_MEGALITE {
	meta:
		tool = "P"
		name = "MEGALITE"
		version = "1.20a"
		pattern = "B8????BA????05????3B2D73??72??B409BA????CD21CD90"
	strings:
		$1 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 2D 73 ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_785_MESS {
	meta:
		tool = "P"
		name = "MESS"
		version = "1.20"
		pattern = "????????FAB9????F3????E3??EB??EB??B6"
	strings:
		$1 = { ?? ?? ?? ?? FA B9 ?? ?? F3 ?? ?? E3 ?? EB ?? EB ?? B6 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
