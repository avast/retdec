/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_22.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_22 =
R"x86_pe_packer(rule rule_599_FreeJoiner {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "1.5.3 stub engine 1.7.1"
		pattern = "E802FDFFFF6A00E80D000000CCFF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A8104000"
	strings:
		$1 = { E8 02 FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A8 10 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_600_FreeJoiner {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 014 - 021"

		pattern = "E8????FFFF6A00E80D000000CCFF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { E8 ?? ?? FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_601_FreeJoiner {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 023"
		pattern = "E8E1FDFFFF6A00E80C000000FF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { E8 E1 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_602_FreeJoiner {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 029"
		pattern = "5032C48AC358E8DEFDFFFF6A00E80D000000CCFF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { 50 32 C4 8A C3 58 E8 DE FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_603_FreeJoiner {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 031 / 032"
		pattern = "5032??668BC358E8??FDFFFF6A00E80D000000CCFF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { 50 32 ?? 66 8B C3 58 E8 ?? FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_604_FreeJoiner {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 033"
		pattern = "506633C3668BC158E8ACFDFFFF6A00E80D000000CCFF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { 50 66 33 C3 66 8B C1 58 E8 AC FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_605_FreeJoiner {
	meta:
		tool = "P"
		name = "FreeJoiner"
		version = "small build 035"
		pattern = "5133CB86C959E89EFDFFFF6687DB6A00E80C000000FF2578104000FF257C104000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25AC104000"
	strings:
		$1 = { 51 33 CB 86 C9 59 E8 9E FD FF FF 66 87 DB 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_606_Freshbind {
	meta:
		tool = "P"
		name = "Freshbind"
		version = "2.0"
		pattern = "64A1000000005589E56AFF681CA04100"
	strings:
		$1 = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 1C A0 41 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_607_Frusion {
	meta:
		tool = "P"
		name = "Frusion"
		pattern = "83EC0C535556576804010000C7442414"
	strings:
		$1 = { 83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_609_FSG {
	meta:
		tool = "P"
		name = "FSG"
		pattern = "??????????81C2F14F5305525281C2FC04000089D15AE81200000005443467552902C1020883C20439D175EAC3"
	strings:
		$1 = { ?? ?? ?? ?? ?? 81 C2 F1 4F 53 05 52 52 81 C2 FC 04 00 00 89 D1 5A E8 12 00 00 00 05 44 34 67 55 29 02 C1 02 08 83 C2 04 39 D1 75 EA C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_610_FSG {
	meta:
		tool = "P"
		name = "FSG"
		pattern = "8D????????0000BA????????81C2????????525281C21C05000089D15A6A??6A??6A??E8??00000005????????3102C102"
	strings:
		$1 = { 8D ?? ?? ?? ?? 00 00 BA ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 52 52 81 C2 1C 05 00 00 89 D1 5A 6A ?? 6A ?? 6A ?? E8 ?? 00 00 00 05 ?? ?? ?? ?? 31 02 C1 02 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_619_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.00"
		pattern = "BBD0014000BF00104000BE????????53E80A00000002D275058A164612D2C3FCB280A46A025BFF142473F733C9FF1424731833C0FF14247321B30241B010FF142412C073F9753FAAEBDCE8430000002BCB7510E838"
	strings:
		$1 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_620_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "03DEEB01F8B880??4200EB02CD206817A0B3ABEB01E8590FB6DB680BA1B3ABEB02CD205E80CBAA2BF1EB02CD20430FBE3813D680C3472BFEEB01F403FEEB024F4E81EF93537C3C80C32981F78A8F678B80C3C72BFE"
	strings:
		$1 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_621_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MASM32 / TASM32"
		pattern = "03F723FE33FBEB02CD20BB80??4000EB0186EB0190B8F400000083EE052BF281F6EE000000EB02CD208A0BE802000000A9545EC1EE07F7D7EB01DE81E9B796A0C4EB016BEB02CD2080E94BC1CF08EB017180E91CEB"
	strings:
		$1 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_622_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0 / 7.0"
		pattern = "0BD08BDAE80200000040A05AEB019DB880????00EB02CD2003D38D35F4000000EB0135EB018880CA7C80F3748B38EB02ACBA03DBE801000000A55BC1C20B81C7DA100A4EEB01082BD183EF14EB02CD2033D383EF27"
	strings:
		$1 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_623_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland Delphi / MSVC"
		pattern = "1BDBE8020000001A0D5B6880????00E801000000EA5A58EB02CD2068F4000000EB02CD205E0FB6D080CA5C8B38EB0135EB02DC9781EFF7651743E80200000097CB5B81C7B28BA10C8BD183EF17EB020C6583EF4313"
	strings:
		$1 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_624_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland C++"
		pattern = "23CAEB025A0DE8020000006A3558C1C910BE80????000FB6C9EB02CD20BBF4000000EB0204FAEB01FAEB015FEB02CD208A16EB02113180E931EB023011C1E91180EA04EB02F0EA33CB81EAABAB190804D503C280EA"
	strings:
		$1 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_625_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland Delphi / C++"
		pattern = "2BC2E802000000954A598D3D52F12AE8C1C81CBE2E????18EB02ABA003F7EB02CD2068F40000000BC75B03CB8A068A16E8020000008D4659EB01A402D3EB02CD2002D3E80200000057AB5881C2AA87ACB90FBEC980"
	strings:
		$1 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_626_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 4.x / LCC Win32 1.x"
		pattern = "2C711BCAEB012AEB01658D3580????0080C98480C968BBF4000000EB01EB"
	strings:
		$1 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_627_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 5.0 / 6.0"
		pattern = "33D20FBED2EB01C7EB01D88D0580??????EB02CD20EB01F8BEF4000000EB"
	strings:
		$1 = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_628_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "WinRAR-SFX"
		pattern = "80E9A1C1C11368E4167546C1C1055EEB019D6864863746EB028CE05FF7D0"
	strings:
		$1 = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_629_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0 / 7.0"
		pattern = "87FEE80200000098CC5FBB80????00EB02CD2068F4000000E801000000E3"
	strings:
		$1 = { 87 FE E8 02 00 00 00 98 CC 5F BB 80 ?? ?? 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_630_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "91EB02CD20BF50BC046F91BED0????6FEB02CD202BF7EB02F0468D1DF400"
	strings:
		$1 = { 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 ?? ?? 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_631_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		pattern = "BBD00140??BF??1040??BE????????FCB2808A064688074702D275058A16"
	strings:
		$1 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_632_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Borland Delphi / MSVC"
		pattern = "C1C810EB010FBF03746677C1E91D6883????77EB02CD205EEB02CD202BF7"
	strings:
		$1 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_633_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "Microsoft Visual Basic 5.0 / 6.0)"
		pattern = "C1CB10EB010FB90374F6EE0FB6D38D0583????EF80F3F62BC1EB01DE6877"
	strings:
		$1 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_634_FSG {
	meta:
		tool = "P"
		name = "FSG"
		version = "1.10"
		extra = "MSVC 6.0"
		pattern = "C1CE10C1F60F6800????002BFA5B23F98D1580????00E801000000B65E0B"
	strings:
		$1 = { C1 CE 10 C1 F6 0F 68 00 ?? ?? 00 2B FA 5B 23 F9 8D 15 80 ?? ?? 00 E8 01 00 00 00 B6 5E 0B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
