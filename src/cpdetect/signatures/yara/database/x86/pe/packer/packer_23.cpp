/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_23.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_23 =
R"x86_pe_packer(
rule rule_635_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "D1E903C06880????00EB02CD205E40BBF400000033CA2BC70FB616EB013E"
	strings:
		$1 = { D1 E9 03 C0 68 80 ?? ?? 00 EB 02 CD 20 5E 40 BB F4 00 00 00 33 CA 2B C7 0F B6 16 EB 01 3E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_636_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "E8010000000E59E8010000005858BE80????00EB0261E968F4000000C1C8"
	strings:
		$1 = { E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE 80 ?? ?? 00 EB 02 61 E9 68 F4 00 00 00 C1 C8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_637_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0 / 7.0 / ASM"
		pattern = "E8010000005A5EE802000000BADD5E03F2EB0164BB80????008BFAEB01A8"
	strings:
		$1 = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_638_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 7.0"
		pattern = "EB01????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????EB"
	strings:
		$1 = { EB 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_639_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "WinRAR-SFX"
		pattern = "EB0102EB02CD20B880??4200EB0155BEF400000013DF13D80FB638D1F3F7"
	strings:
		$1 = { EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_640_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland Delphi / Borland C++"
		pattern = "EB012EEB02A555BB80????0087FE8D05AACEE063EB0175BA5ECEE063EB02"
	strings:
		$1 = { EB 01 2E EB 02 A5 55 BB 80 ?? ?? 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_641_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "EB014D83F64C6880????00EB02CD205BEB012368481C2B3AE80200000038"
	strings:
		$1 = { EB 01 4D 83 F6 4C 68 80 ?? ?? 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_642_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland Delphi 2.0"
		pattern = "EB0156E802000000B2D9596880??4100E8020000006532595EEB02CD20BB"
	strings:
		$1 = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_643_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MASM32"
		pattern = "EB01DBE80200000086435E8D1DD075CF83C1EE1D6850??8F83EB023D0F5A"
	strings:
		$1 = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_644_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		pattern = "EB02????EB02"
	strings:
		$1 = { EB 02 ?? ?? EB 02 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_645_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Microsoft Visual Basic / MASM32"
		pattern = "EB0209940FB7FF6880????0081F68E0000005BEB0211C28D05F400000047"
	strings:
		$1 = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_646_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "EB02AB35EB02B5C68D0580????00C1C211BEF4000000F7DBF7DB0FBE38E8"
	strings:
		$1 = { EB 02 AB 35 EB 02 B5 C6 8D 05 80 ?? ?? 00 C1 C2 11 BE F4 00 00 00 F7 DB F7 DB 0F BE 38 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_647_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "EB02CD20??CF????80????00????????????????00"
	strings:
		$1 = { EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_648_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Watcom C/C++ EXE"
		pattern = "EB02CD2003??8D??80????00??????????????????EB02"
	strings:
		$1 = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_649_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland C++ 1999"
		pattern = "EB02CD202BC86880????00EB021EBB5EEB02CD2068B12B6E37405B0FB6C9"
	strings:
		$1 = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_650_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland Delphi / MSVC / ASM"
		pattern = "EB02CD20EB02CD20EB02CD20C1E618BB80????00EB0282B8EB01108D05F4"
	strings:
		$1 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_651_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0 / ASM"
		pattern = "F7D0EB02CD20BEBB741CFBEB02CD20BF3B????FBC1C10333F7EB02CD2068"
	strings:
		$1 = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_652_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MASM32 / TASM32 / Microsoft Visual Basic"
		pattern = "F7D80FBEC2BE80????000FBEC9BF083B6507EB02D829BBECC59AF8EB0194"
	strings:
		$1 = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_653_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0 / 7.0"
		pattern = "F7D84049EB02E00A8D3580??????0FB6C2EB019C8D1DF4000000EB013C80"
	strings:
		$1 = { F7 D8 40 49 EB 02 E0 0A 8D 35 80 ?? ?? ?? 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_654_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0 / 7.0"
		pattern = "F7DB80EABFB92F4067BAEB010168AF????BA80EA9D58C1C2092BC18BD768"
	strings:
		$1 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? ?? BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_655_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "Borland Delphi / Microsoft Visual C++"
		pattern = "0FB6D0E8010000000C5AB880????00EB0200DE8D35F4000000F7D2EB020EEA8B38EB01A0C1F31181EF8488F44CEB02CD2083F72287D333FEC1C31983F726E802000000BCDE5A81EFF7EF6F18EB02CD2083EF7FEB01F72BFEEB017F81EFDF30901EEB02CD2087FA881080EA0340EB01204EEB013D83FE0075A2EB02CD20EB01C3787342F7356C2D3FED3397??????5DF0452955575571630272E91F2D67B1C091FD1058A390716C"
	strings:
		$1 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 F7 2B FE EB 01 7F 81 EF DF 30 90 1E EB 02 CD 20 87 FA 88 10 80 EA 03 40 EB 01 20 4E EB 01 3D 83 FE 00 75 A2 EB 02 CD 20 EB 01 C3 78 73 42 F7 35 6C 2D 3F ED 33 97 ?? ?? ?? 5D F0 45 29 55 57 55 71 63 02 72 E9 1F 2D 67 B1 C0 91 FD 10 58 A3 90 71 6C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_656_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "Borland Delphi / Borland C++"
		pattern = "0FBEC1EB010E8D35C3BEB622F7D16843????22EB02B5155FC1F11533F780E9F9BBF4000000EB028FD0EB0208AD8A162BC71BC780C27A4180EA10EB013C81EACFAEF1AAEB01EC81EABBC6ABEE2CE332D30BCB81EAABEE90142C772AD3EB01872AD3E80100000092598816EB02520846EB02CD204B80F1C285DB75AEC1E004EB00DAB2825C9BC789984F8AF7??????B14DDFB8ADACABD40727D450CF9AD51CECF2277718404EA4A8"
	strings:
		$1 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB EE 90 14 2C 77 2A D3 EB 01 87 2A D3 E8 01 00 00 00 92 59 88 16 EB 02 52 08 46 EB 02 CD 20 4B 80 F1 C2 85 DB 75 AE C1 E0 04 EB 00 DA B2 82 5C 9B C7 89 98 4F 8A F7 ?? ?? ?? B1 4D DF B8 AD AC AB D4 07 27 D4 50 CF 9A D5 1C EC F2 27 77 18 40 4E A4 A8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_657_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "MASM32 / TASM32"
		pattern = "33C22CFB8D3D7E45B480E8020000008A45586802??8C7FEB02CD205E80C91603F7EB0240B068F400000080F12C5BC1E9050FB6C98A160FB6C90FBFC72AD3E802000000994C5880EA53C1C9162AD3E8020000009DCE5880EA33C1E11232D34880C226EB02CD208816F7D846EB01C04B408D0D000000003BD975B7EB0114EB010ACFC5935390DA9667548DCC????518E18745382838047B4D241FB64316AAF7D89BC0A91D7833739"
	strings:
		$1 = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE 58 80 EA 33 C1 E1 12 32 D3 48 80 C2 26 EB 02 CD 20 88 16 F7 D8 46 EB 01 C0 4B 40 8D 0D 00 00 00 00 3B D9 75 B7 EB 01 14 EB 01 0A CF C5 93 53 90 DA 96 67 54 8D CC ?? ?? 51 8E 18 74 53 82 83 80 47 B4 D2 41 FB 64 31 6A AF 7D 89 BC 0A 91 D7 83 37 39 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_658_FSG {
	meta:
		tool = "P"
		name = "FSG"
		extra = "1.20"
		pattern = "4B45524E454C33322E646C6C00004C6F61644C69627261727941000047657450726F634164647265737300??0000000000"
	strings:
		$1 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_659_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "MSVC 6.0"
		pattern = "C1E006EB02CD20EB0127EB0124BE80??420049EB01998D1DF4000000EB015CF7D81BCAEB01318A1680E941EB01C2C1E00AEB01A181EAA88C18A13446E801000000625932D3C1C902EB016880F21A0FBEC9F7D12AD3"
	strings:
		$1 = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_660_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "Borland C++"
		pattern = "C1F007EB02CD20BE80????001BC68D1DF40000000FB606EB02CD208A160FB6C3E801000000DC5980EA37EB02CD202AD3EB02CD2080EA731BCF32D3C1C80E80EA230FB6C902D3EB01B502D3EB02DB5B81C2F6567BF6EB02567B2AD3E801000000ED58881613C346EB02CD204BEB02CD202BC93BD975A1E802000000D76B58EB009E966A2867AB6954033E7F??????310D634435383718879F108C37C641804C5E8BDB604C3A2808"
	strings:
		$1 = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 EB 02 56 7B 2A D3 E8 01 00 00 00 ED 58 88 16 13 C3 46 EB 02 CD 20 4B EB 02 CD 20 2B C9 3B D9 75 A1 E8 02 00 00 00 D7 6B 58 EB 00 9E 96 6A 28 67 AB 69 54 03 3E 7F ?? ?? ?? 31 0D 63 44 35 38 37 18 87 9F 10 8C 37 C6 41 80 4C 5E 8B DB 60 4C 3A 28 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_661_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.20"
		extra = "MSVC 6.0 / 7.0"
		pattern = "EB02CD20EB01918D3580????0033C26883937E7D0CA45B23C36877937E7DEB01FA5FE802000000F7FB5833DFEB013FE8020000001188580FB616EB02CD20EB02862F2AD3EB02CD2080EA2FEB015232D380E9CD80EA738BCF81C29644EB04EB02CD208816E80200000044A25946E801000000AD594B80C11383FB0075B2F7D9968F804D0C4C91501C0C508A??????50E93416504C4C0E7E9B49C632023E7E7B5E8CC56B503F0E0F"
	strings:
		$1 = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA 73 8B CF 81 C2 96 44 EB 04 EB 02 CD 20 88 16 E8 02 00 00 00 44 A2 59 46 E8 01 00 00 00 AD 59 4B 80 C1 13 83 FB 00 75 B2 F7 D9 96 8F 80 4D 0C 4C 91 50 1C 0C 50 8A ?? ?? ?? 50 E9 34 16 50 4C 4C 0E 7E 9B 49 C6 32 02 3E 7E 7B 5E 8C C5 6B 50 3F 0E 0F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_662_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.30"
		pattern = "BBD0014000BF00104000BE????????53E80A00000002D275058A164612D2C3B280A46A025BFF142473F733C9FF1424731833C0FF14247321B30241B010FF142412C073F9753FAAEBDCE8430000002BCB7510E838000000EB28ACD1E8744113C9EB1C9148C1E008ACE8220000003D007D0000730A80FC05730683F87F77024141958BC5B301568BF72BF0F3A45EEB9633C941FF54240413C9FF54240472F4C35F5B0FB73B4F7408"
	strings:
		$1 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 41 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 96 33 C9 41 FF 54 24 04 13 C9 FF 54 24 04 72 F4 C3 5F 5B 0F B7 3B 4F 74 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_663_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.31"
		pattern = "BBD0014000BF00104000BE????????53BB????????B280A4B680FFD373F933C9FFD3731633C0FFD37323B68041B010FFD312C073FA7542AAEBE0E84600000002F683D9017510E838000000EB28ACD1E8744813C9EB1C9148C1E008ACE8220000003D007D0000730A80FC05730683F87F77024141958BC5B600568BF72BF0F3A45EEB9733C941FFD313C9FFD372F8C302D275058A164612D2C35B5B0FB73B4F74084F7413C1E70C"
	strings:
		$1 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB 1C 91 48 C1 E0 08 AC E8 22 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B6 00 56 8B F7 2B F0 F3 A4 5E EB 97 33 C9 41 FF D3 13 C9 FF D3 72 F8 C3 02 D2 75 05 8A 16 46 12 D2 C3 5B 5B 0F B7 3B 4F 74 08 4F 74 13 C1 E7 0C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_664_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.31"
		pattern = "BE??????00BF??????00BB??????0053BB??????00B280"
	strings:
		$1 = { BE ?? ?? ?? 00 BF ?? ?? ?? 00 BB ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_665_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.33"
		pattern = "BEA4014000AD93AD97AD5696B280A4B680FF1373F933C9FF13731633C0FF13731FB68041B010FF1312C073FA753CAAEBE0FF530802F683D901750EFF5304EB26ACD1E8742F13C9EB1A9148C1E008ACFF53043D007D"
	strings:
		$1 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
