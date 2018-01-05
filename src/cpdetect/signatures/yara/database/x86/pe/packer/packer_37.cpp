/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_37.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_37 =
R"x86_pe_packer(
rule rule_1009_PE_SHiELD {
	meta:
		tool = "P"
		name = "PE-SHiELD"
		version = "0.1b MTE"
		pattern = "E8????????????????????????????????????????????????????B91B01????D1"
	strings:
		$1 = { E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B9 1B 01 ?? ?? D1 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1010_PE_SHiELD {
	meta:
		tool = "P"
		name = "PE-SHiELD"
		version = "0.2 / 0.2b / 0.2b2"
		pattern = "60E8????????414E414B494E5D83ED06EB02EA04"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1011_PE_SHiELD {
	meta:
		tool = "P"
		name = "PE-SHiELD"
		version = "0.25"
		pattern = "60E82B000000"
	strings:
		$1 = { 60 E8 2B 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1012_PE_SHiELD {
	meta:
		tool = "P"
		name = "PE-SHiELD"
		version = "0.251"
		pattern = "5D83ED06EB02EA048D"
	strings:
		$1 = { 5D 83 ED 06 EB 02 EA 04 8D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1013_Pe123 {
	meta:
		tool = "P"
		name = "Pe123"
		version = "2006.4.12"
		pattern = "8BC0609CE801000000C353E87200000050E81C0300008BD8FFD35BC38BC0E8000000005883C005C38BC0558BEC608B4D108B7D0C8B7508F3A4615DC20C00E8000000005883E805C38BC0E8000000005883C005C38BC0E80000000058C1E80CC1E00C6681384D5A740C2D001000006681384D5A75F4C3E8000000005883E805C38BC0558BEC81C44CFEFFFF536A408D8544FFFFFF50E8BCFFFFFF50E88AFFFFFF68F80000008D85"
	strings:
		$1 = { 8B C0 60 9C E8 01 00 00 00 C3 53 E8 72 00 00 00 50 E8 1C 03 00 00 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 E8 00 00 00 00 58 C1 E8 0C C1 E0 0C 66 81 38 4D 5A 74 0C 2D 00 10 00 00 66 81 38 4D 5A 75 F4 C3 E8 00 00 00 00 58 83 E8 05 C3 8B C0 55 8B EC 81 C4 4C FE FF FF 53 6A 40 8D 85 44 FF FF FF 50 E8 BC FF FF FF 50 E8 8A FF FF FF 68 F8 00 00 00 8D 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1014_Pe123 {
	meta:
		tool = "P"
		name = "Pe123"
		version = "2006.4.4"
		pattern = "8BC0EB013460EB012A9CEB02EAC8E80F000000EB033D2323EB014AEB015BC38D400053EB016CEB017EEB018FE81501000050E867040000EB019A8BD8FFD35BC38BC0E8000000005883C005C38BC0558BEC608B4D108B7D0C8B7508F3A4615DC20C00E8000000005883E805C38BC0E8000000005883C005C38BC0E80000000058C1E80CC1E00C6681384D5A740C2D001000006681384D5A75F4C3E8000000005883E805C38BC055"
	strings:
		$1 = { 8B C0 EB 01 34 60 EB 01 2A 9C EB 02 EA C8 E8 0F 00 00 00 EB 03 3D 23 23 EB 01 4A EB 01 5B C3 8D 40 00 53 EB 01 6C EB 01 7E EB 01 8F E8 15 01 00 00 50 E8 67 04 00 00 EB 01 9A 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 E8 00 00 00 00 58 C1 E8 0C C1 E0 0C 66 81 38 4D 5A 74 0C 2D 00 10 00 00 66 81 38 4D 5A 75 F4 C3 E8 00 00 00 00 58 83 E8 05 C3 8B C0 55 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1015_Pe123 {
	meta:
		tool = "P"
		name = "Pe123"
		version = "2006.4.4 - 20xx.4.12"
		pattern = "8BC0??????????????????????????????????????????????????????????????00??????????????????????????????????????????????????????????????????????????????C0"
	strings:
		$1 = { 8B C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1016_PE_Admin {
	meta:
		tool = "P"
		name = "PE_Admin"
		version = "1.0 EncryptPE 1.2003.5.18"
		pattern = "609C64FF3500000000E879010000900000000000000000000000????????????????0000000000000000000000000000000000000000????????????????????????????????????????????????????????????????????????000000006B65726E656C33322E646C6C00000047657453797374656D4469726563746F72794100000043726561746546696C654100000043726561746546696C654D617070696E67410000004D6170566965774F6646696C65000000556E6D6170566965774F6646696C65000000436C6F736548616E646C650000004C6F61644C6962726172794100000047657450726F63416464726573730000004578697450726F63657373"
	strings:
		$1 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 90 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1017_PEBundle {
	meta:
		tool = "P"
		name = "PEBundle"
		pattern = "9C60E8????????33C08BC483C004938BE38B5BFC81EB07??400087DD????????400001"
	strings:
		$1 = { 9C 60 E8 ?? ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 ?? 40 00 87 DD ?? ?? ?? ?? 40 00 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1018_PEBundle {
	meta:
		tool = "P"
		name = "PEBundle"
		version = "0.20 - 2.0x"
		pattern = "9C60E802??????33C08BC483C004938BE38B5BFC81EB????40??87DD6A0468??10????68??02????6A??FF95"
	strings:
		$1 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1019_PEBundle {
	meta:
		tool = "P"
		name = "PEBundle"
		version = "2.00b5 - 2.30"
		pattern = "9C60E802??????33C08BC483C004938BE38B5BFC81EB????40??87DD01AD????????01AD"
	strings:
		$1 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 01 AD ?? ?? ?? ?? 01 AD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1020_PEBundle {
	meta:
		tool = "P"
		name = "PEBundle"
		version = "2.44"
		pattern = "9C60E802??????33C08BC483C004938BE38B5BFC81EB????40??87DD83BD"
	strings:
		$1 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1021_PEBundle {
	meta:
		tool = "P"
		name = "PEBundle"
		version = "3.10"
		pattern = "9C60E80200000033C08BC483C004938BE38B5BFC81EB0720400087DD????????400001"
	strings:
		$1 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD ?? ?? ?? ?? 40 00 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1022_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.90"
		pattern = "EB0668????4000C39C60BD????0000B902000000B0908DBD7A424000F3AA01ADD9434000FFB5"
	strings:
		$1 = { EB 06 68 ?? ?? 40 00 C3 9C 60 BD ?? ?? 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1023_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.92"
		pattern = "EB0668????????C39C60BD????????B902??????B0908DBDA54F40??F3AA01AD045140??FFB5"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD A5 4F 40 ?? F3 AA 01 AD 04 51 40 ?? FF B5 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1024_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.94"
		pattern = "EB0668????????C39C60E8????????5D555881ED????????2B85????????0185????????50B902"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1025_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.971 - 0.976"
		pattern = "EB0668C39C60E85D555B81ED8B85018566C785"
	strings:
		$1 = { EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1026_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.977"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EBA08640??87DD8B852A87"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 ?? 87 DD 8B 85 2A 87 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1027_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.978"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB248840??87DD8B85A988"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 ?? 87 DD 8B 85 A9 88 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1028_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.978.1"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB498740??87DD8B85CE87"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 49 87 40 ?? 87 DD 8B 85 CE 87 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1029_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.978.2"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EBD18440??87DD8B855685"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 ?? 87 DD 8B 85 56 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1030_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.98"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EBD78440??87DD8B855C85"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D7 84 40 ?? 87 DD 8B 85 5C 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1031_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "0.99"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB2F8540??87DD8B85B485"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 ?? 87 DD 8B 85 B4 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1032_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.00"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EBC48440??87DD8B854985"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB C4 84 40 ?? 87 DD 8B 85 49 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1033_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b1"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB286340??87DD8B85AD63"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 ?? 87 DD 8B 85 AD 63 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1034_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b2"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F6040??87DD8B859460"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 94 60 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1035_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b3"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F6040??87DD8B85956040??0185036040??66C785??6040??9090BB95"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 95 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1036_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b4"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F6040??87DD8B85956040??0185036040??66C785??6040??9090BB44"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 44 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1037_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b5"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F6040??87DD8B85956040??0185036040??66C785??6040??9090BB49"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 49 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1038_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b6"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F60??0087DD8B859A6040??0185036040??66C785??6040??90900185926040??BBB7"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 ?? 00 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB B7 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1039_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.10b7"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F6040??87DD8B859A6040??0185036040??66C785??6040??90900185926040??BB14"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB 14 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1040_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.20 - 1.20.1"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B859A7040"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 9A 70 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1041_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.22"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B85A67040??0185037040??66C785??7040??909001859E7040??BBF308"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB F3 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1042_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.23b3 - 1.24.1"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B85A67040??0185037040??66C785704090??9001859E7040BB??D208"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
