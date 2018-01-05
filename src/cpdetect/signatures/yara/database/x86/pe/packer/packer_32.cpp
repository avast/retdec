/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_32.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_32 =
R"x86_pe_packer(
rule rule_887_NTPacker {
	meta:
		tool = "P"
		name = "NTPacker"
		version = "1.0"
		pattern = "558BEC83C4E05333C08945E08945E48945E88945ECB8????4000E8????FFFF33C05568????400064FF306489208D4DECBA????4000A1????4000E8??FCFFFF8B55ECB8????4000E8????FFFF8D4DE8BA????4000A1????4000E8??FEFFFF8B55E8B8????4000E8????FFFFB8????4000E8??FBFFFF8BD8A1????4000BA????4000E8????FFFF75268BD3A1????4000E8????FFFF84C0752A8D55E433C0E8????FFFF8B45E48BD3E8????FFFFEB148D55E033C0E8????FFFF8B45E08BD3E8????FFFF6A00E8????FFFF33C05A595964891068????40008D45E0BA04000000E8????FFFFC3E9????FFFFEBEB5BE8????FFFF000000FFFFFFFF0100000025000000FFFFFFFF010000005C000000FFFFFFFF060000005345525645520000FFFFFFFF0100000031"
	strings:
		$1 = { 55 8B EC 83 C4 E0 53 33 C0 89 45 E0 89 45 E4 89 45 E8 89 45 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 33 C0 55 68 ?? ?? 40 00 64 FF 30 64 89 20 8D 4D EC BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FC FF FF 8B 55 EC B8 ?? ?? 40 00 E8 ?? ?? FF FF 8D 4D E8 BA ?? ?? 40 00 A1 ?? ?? 40 00 E8 ?? FE FF FF 8B 55 E8 B8 ?? ?? 40 00 E8 ?? ?? FF FF B8 ?? ?? 40 00 E8 ?? FB FF FF 8B D8 A1 ?? ?? 40 00 BA ?? ?? 40 00 E8 ?? ?? FF FF 75 26 8B D3 A1 ?? ?? 40 00 E8 ?? ?? FF FF 84 C0 75 2A 8D 55 E4 33 C0 E8 ?? ?? FF FF 8B 45 E4 8B D3 E8 ?? ?? FF FF EB 14 8D 55 E0 33 C0 E8 ?? ?? FF FF 8B 45 E0 8B D3 E8 ?? ?? FF FF 6A 00 E8 ?? ?? FF FF 33 C0 5A 59 59 64 89 10 68 ?? ?? 40 00 8D 45 E0 BA 04 00 00 00 E8 ?? ?? FF FF C3 E9 ?? ?? FF FF EB EB 5B E8 ?? ?? FF FF 00 00 00 FF FF FF FF 01 00 00 00 25 00 00 00 FF FF FF FF 01 00 00 00 5C 00 00 00 FF FF FF FF 06 00 00 00 53 45 52 56 45 52 00 00 FF FF FF FF 01 00 00 00 31 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_888_NTPacker {
	meta:
		tool = "P"
		name = "NTPacker"
		version = "2.x"
		pattern = "4B57696E646F7773001055547970657300003F756E744D61696E46756E6374696F6E73000047756E744279706173730000B761504C696275000000"
	strings:
		$1 = { 4B 57 69 6E 64 6F 77 73 00 10 55 54 79 70 65 73 00 00 3F 75 6E 74 4D 61 69 6E 46 75 6E 63 74 69 6F 6E 73 00 00 47 75 6E 74 42 79 70 61 73 73 00 00 B7 61 50 4C 69 62 75 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_890_Nullsoft_Install_System {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "1.3x PIMP"
		pattern = "558BEC81EC????000056576A??BE????????598DBD"
	strings:
		$1 = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_892_Nullsoft_Install_System {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "1.xx PiMP"
		pattern = "83EC5C53555657FF15??????00"
	strings:
		$1 = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_893_Nullsoft_Install_System {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "1.xx"
		pattern = "83EC0C535657FF152071400005E8030000BE60FD410089442410B320FF15287040006800040000FF15287140005056FF1508714000803D60FD410022750880C302BE61FD41008A068B3DF071400084C0740F3AC3740B56FFD78BF08A0684C075F1803E00740556FFD78BF089742414803E20750756FFD78BF0EBF4803E2F75"
	strings:
		$1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 80 3E 20 75 07 56 FF D7 8B F0 EB F4 80 3E 2F 75 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_894_Nullsoft_Install_System {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.0rc2"
		pattern = "83EC1053555657C74424147092400033EDC644241320FF152C70400055FF1584724000BE00544300BF000400005657A3A8EC4200FF15C4704000E88DFFFFFF8B1D9070400085C0752168FB03000056FF155C714000686892400056FFD3E86AFFFFFF85C00F8459010000BE20E4420056FF1568704000685C92400056E8B928000057FF15BC704000BE004043005056FF15B87040006A00FF1544714000803D0040430022A320EC"
	strings:
		$1 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 68 68 92 40 00 56 FF D3 E8 6A FF FF FF 85 C0 0F 84 59 01 00 00 BE 20 E4 42 00 56 FF 15 68 70 40 00 68 5C 92 40 00 56 E8 B9 28 00 00 57 FF 15 BC 70 40 00 BE 00 40 43 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 40 43 00 22 A3 20 EC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_895_Nullsoft_Install_System {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.0"
		pattern = "83EC0C53555657C7442410????????33DBC644241420FF15????????53FF15????????BE????????BF????????5657A3????????FF15????????E88DFFFFFF8B2D????????85C0"
	strings:
		$1 = { 83 EC 0C 53 55 56 57 C7 44 24 10 ?? ?? ?? ?? 33 DB C6 44 24 14 20 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? 56 57 A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? E8 8D FF FF FF 8B 2D ?? ?? ?? ?? 85 C0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_896_Nullsoft_Install_System {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.0"
		pattern = "83EC0C53555657C74424107092400033DBC644241420FF152C70400053FF1584724000BE00544300BF000400005657A3A8EC4200FF15C4704000E88DFFFFFF8B2D9070400085C0752168FB03000056FF155C714000"
	strings:
		$1 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_897_Nullsoft_Install_System {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.0b2, 2.0b3"
		pattern = "83EC0C53555657FF15??7040008B35??92400005E803000089442414B320FF152C704000BF0004000068??????0057FF15????400057FF15"
	strings:
		$1 = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 ?? ?? ?? 00 57 FF 15 ?? ?? 40 00 57 FF 15 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_898_Nullsoft_Install_System {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.0b4"
		pattern = "83EC1053555657C7442414F091400033EDC644241320FF152C70400055FF1588724000BE00D44200BF000400005657A3606F4200FF15C4704000E89FFFFFFF8B1D9070400085C0752168FB03000056FF1560714000"
	strings:
		$1 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_899_Nullsoft_Install_System {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.0b4"
		pattern = "83EC14836424040053555657C644241320FF1530704000BE00207A00BD000400005655FF15C470400056E87D2B00008B1D8C7040006A0056FFD3BF809279005657E81526000085C0753868F89140005556FF156071400003C650E87829000056E8472B00006A0056FFD35657E8EA25000085C0750DC744241458914000E97202000057FF152471400068EC91400057E843"
	strings:
		$1 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 40 00 03 C6 50 E8 78 29 00 00 56 E8 47 2B 00 00 6A 00 56 FF D3 56 57 E8 EA 25 00 00 85 C0 75 0D C7 44 24 14 58 91 40 00 E9 72 02 00 00 57 FF 15 24 71 40 00 68 EC 91 40 00 57 E8 43 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_901_NX_PE_Packer {
	meta:
		tool = "P"
		name = "NX PE Packer"
		version = "1.0"
		pattern = "FF60FFCAFF00BADC0DE040005000600070008000"
	strings:
		$1 = { FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_902_Muckis_protector {
	meta:
		tool = "P"
		name = "Muckis protector"
		pattern = "BE????????B9????????8A06F6D0880646E2F7E9"
	strings:
		$1 = { BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 8A 06 F6 D0 88 06 46 E2 F7 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_903_Muckis_protector {
	meta:
		tool = "P"
		name = "Muckis protector"
		pattern = "E8240000008B4C240CC70117000100C781B80000000000000031C0894114894118806A00"
	strings:
		$1 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 6A 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_904_Obsidium {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.0.0.59 final"
		pattern = "E8AB1C"
	strings:
		$1 = { E8 AB 1C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_905_Obsidium {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.0.0.61"
		pattern = "E8AF1C0000"
	strings:
		$1 = { E8 AF 1C 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_906_Obsidium {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.1.1.1"
		pattern = "EB02????E8E71C0000"
	strings:
		$1 = { EB 02 ?? ?? E8 E7 1C 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_907_Obsidium {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.2.0.0"
		pattern = "EB02????E83F1E0000"
	strings:
		$1 = { EB 02 ?? ?? E8 3F 1E 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_908_Obsidium {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.2.0.0"
		pattern = "EB02????E8771E0000"
	strings:
		$1 = { EB 02 ?? ?? E8 77 1E 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_909_Obsidium {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.2.5.0"
		pattern = "E80E0000008B54240C8382B80000000D33C0C36467FF3600006467892600005033C08B00C3E9FA000000E8D5FFFFFF5864678F06000083C404E82B130000"
	strings:
		$1 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_910_Obsidium {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.2.5.8"
		pattern = "EB01??E829000000EB02????EB01??8B54240CEB04????????8382B800000024EB04????????33C0EB02????C3EB02????EB03??????6467FF360000EB01??646789260000EB03??????EB01??50EB03??????33C0EB04????????8B00EB03??????C3EB01??E9FA000000EB02????E8D5FFFFFFEB04????????EB03??????EB01??58EB01??EB02????64678F060000EB04????????83C404EB01??E87B210000"
	strings:
		$1 = { EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 24 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 04 ?? ?? ?? ?? 8B 00 EB 03 ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 02 ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 01 ?? 58 EB 01 ?? EB 02 ?? ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 01 ?? E8 7B 21 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_911_Obsidium {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.2.x.x"
		pattern = "E80E00000033C08B54240C8382B80000000DC36467FF3600006467892600005033C08B00C3E9FA000000E8D5FFFFFF5864678F06000083C404E82B130000"
	strings:
		$1 = { E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_912_Obsidium {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.0.0"
		pattern = "EB04????????E829000000EB02????EB01??8B54240CEB02????8382B800000022EB02????33C0EB04????????C3EB04????????EB04????????6467FF360000EB04????????646789260000EB04????????EB01??50EB03??????33C0EB02????8B00EB01??C3EB04????????E9FA000000EB01??E8D5FFFFFFEB02????EB03??????58EB04????????EB01??64678F060000EB02????83C404EB02????E847260000"
	strings:
		$1 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 02 ?? ?? 83 82 B8 00 00 00 22 EB 02 ?? ?? 33 C0 EB 04 ?? ?? ?? ?? C3 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 04 ?? ?? ?? ?? 64 67 89 26 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 50 EB 03 ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 01 ?? C3 EB 04 ?? ?? ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 02 ?? ?? EB 03 ?? ?? ?? 58 EB 04 ?? ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 02 ?? ?? 83 C4 04 EB 02 ?? ?? E8 47 26 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_913_Obsidium {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.0.13"
		pattern = "EB01??E826000000EB02????EB02????8B54240CEB01??8382B800000021EB04????????33C0EB02????C3EB01??EB04????????6467FF360000EB02????646789260000EB01??EB03??????50EB01??33C0EB03??????8B00EB02????C3EB02????E9FA000000EB01??E8D5FFFFFFEB03??????EB02????58EB03??????EB04????????64678F060000EB03??????83C404EB03??????E813260000"
	strings:
		$1 = { EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 02 ?? ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 01 ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 02 ?? ?? C3 EB 02 ?? ?? E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 03 ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 64 67 8F 06 00 00 EB 03 ?? ?? ?? 83 C4 04 EB 03 ?? ?? ?? E8 13 26 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_914_Obsidium {
	meta:
		tool = "P"
		name = "Obsidium"
		version = "1.3.0.17"
		pattern = "EB02????E828000000EB04????????EB01??8B54240CEB01??8382B800000025EB02????33C0EB03??????C3EB03??????EB02????6467FF360000EB01??646789260000EB03??????EB04????????50EB04????????33C0EB02????8B00EB04????????C3EB01??E9FA000000EB03??????E8D5FFFFFFEB04????????EB02????58EB03??????EB01??64678F060000EB04????????83C404EB02????E84F260000"
	strings:
		$1 = { EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 ?? ?? 33 C0 EB 03 ?? ?? ?? C3 EB 03 ?? ?? ?? EB 02 ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? 33 C0 EB 02 ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 01 ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 02 ?? ?? 58 EB 03 ?? ?? ?? EB 01 ?? 64 67 8F 06 00 00 EB 04 ?? ?? ?? ?? 83 C4 04 EB 02 ?? ?? E8 4F 26 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
