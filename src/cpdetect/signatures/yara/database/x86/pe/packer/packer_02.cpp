/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_02.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_02 =
R"x86_pe_packer(
rule rule_34___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [LCC Win32 DLL]"
		pattern = "5589E5535657837D0C017505E817909090FF7510FF750CFF7508A1????????E9"
	strings:
		$1 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 ?? ?? ?? ?? E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_35___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [LTC 1.3]"
		pattern = "54E8000000005D8BC581EDF67340002B858775400083E806E9"
	strings:
		$1 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_36___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Microsoft Visual Basic 5.0 - 6.0]"
		pattern = "68????????E80A00000000000000000030000000E9"
	strings:
		$1 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_37___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [MSVC 5.0+ (MFC)]"

		pattern = "558BEC6AFF68????????68????????64A10000000050E9"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_38___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [MSVC 6.0 (Debug)]"
		pattern = "558BEC5190909001019090909068????????90909090909090909090909000019090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909000019090909090"
	strings:
		$1 = { 55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_39___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Morphine 1.2]"
		pattern = "90909090909090909090909090909090EB06009090909090909090EB08E890000000669090909090909090909090909090909090909090909090909090909090516690909059909090909090909090909090909090"
	strings:
		$1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_40___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Neolite 2.0]"
		pattern = "E9A60000009090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090"
	strings:
		$1 = { E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_41___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [NorthStar PE Shrinker 1.3]"
		pattern = "9C60E8000000005DB8B38540002DAC8540002BE88DB500000000E9"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_42___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Pack Master 1.0 (PeX Clone)]"
		pattern = "60E801010000E883C404E801909090E95D81EDD3224090E804029090E8EB08EB02CD20FF24249A66BE4746909090909090909090909090909090909090909090909090909090909090909090909090909090909090"
	strings:
		$1 = { 60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_43___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [PE Intro 1.0]"
		pattern = "8B04249C60E8140000005D81ED0A45409080BD67444090900F8548FFED0AE9"
	strings:
		$1 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_44___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [PE Ninja 1.31]"
		pattern = "909090909090909090909090909090909090909090909090909090909090909090909090E9"
	strings:
		$1 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_45___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [PENightMare 2 Beta]"
		pattern = "60E910000000EF4003A7078F071C375D43A704B92C3AE9"
	strings:
		$1 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_46___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [PEX 0.99]"
		pattern = "60E8010000005583C404E801000000905D81FFFFFF0001E9"
	strings:
		$1 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_47___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [Video-Lan-Client]"
		pattern = "5589E583EC08909090909090909090909090909001FFFF0101010001909090909090909090909090909000010001000190900001E9"
	strings:
		$1 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_48___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1 [yoda's Protector 1.02]"
		pattern = "E803000000EB019090E9"
	strings:
		$1 = { E8 03 00 00 00 EB 01 90 90 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_49___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1"
		pattern = "9090909068????????6764FF360000676489260000F190909090"
	strings:
		$1 = { 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_50___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1-0.2 [ASProtect]"
		pattern = "609090909090905D909090909090909090909003DD"
	strings:
		$1 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_51___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1-0.2 [UPX 0.6]"
		pattern = "60E8000000005883E83D508DB8000000FF578DB0E8000000"
	strings:
		$1 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_52___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1-0.2 [WATCOM C/C++ EXE]"
		pattern = "E900000000909090905741"
	strings:
		$1 = { E9 00 00 00 00 90 90 90 90 57 41 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_53___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.1-0.2 [XCR 0.11]"
		pattern = "608BF033DB83C30183C001E9"
	strings:
		$1 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_54___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [.BJFNT 1.1b]"
		pattern = "EB01EA9CEB01EA53EB01EA51EB01EA52EB01EA5690"
	strings:
		$1 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_55___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [.BJFNT 1.2]"
		pattern = "EB0269B183EC04EB03CD20EBEB01EB9CEB01EBEB00"
	strings:
		$1 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_56___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Borland C++]"
		pattern = "EB1066623A432B2B484F4F4B90E990909090"
	strings:
		$1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_57___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Borland Delphi DLL]"
		pattern = "558BEC83C4B4B890909090E800000000E8000000008D4000"
	strings:
		$1 = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_58___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Borland Delphi Setup Module]"
		pattern = "558BEC83C49053565733C08945F08945D48945D0E800000000"
	strings:
		$1 = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_59___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Code-Lock]"
		pattern = "434F44452D4C4F434B2E4F435800012801504B47054C3FB4044D4C474B"
	strings:
		$1 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_60___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [DEF 1.0]"
		pattern = "BE000140006A0559807E070074118B46909090909090909090909090909090909083C101"
	strings:
		$1 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_61___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [ExeSmasher]"
		pattern = "9CFE039060BE909041908DBE9010FFFF5783CDFFEB1090909090909090909090909090909090FE0B"
	strings:
		$1 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_62___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [LCC Win32 DLL]"
		pattern = "5589E5535657837D0C017505E817909090FF7510FF750CFF7508A1"
	strings:
		$1 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_63___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Microsoft Visual Basic 5.0 - 6.0]"
		pattern = "68????????E80A00000000000000000030000000"
	strings:
		$1 = { 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_64___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [NorthStar PE Shrinker 1.3]"
		pattern = "9C60E8000000005DB8B38540002DAC8540002BE88DB500000000"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_65___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [PE Intro 1.0]"
		pattern = "8B04249C60E8140000005D81ED0A45409080BD67444090900F8548FFED0A"
	strings:
		$1 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_66___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [PENightMare 2 Beta]"
		pattern = "60E910000000EF4003A7078F071C375D43A704B92C3A"
	strings:
		$1 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_67___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [PEX 0.99]"
		pattern = "60E8010000005583C404E801000000905D81FFFFFF0001"
	strings:
		$1 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_68___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Video-Lan-Client]"
		pattern = "5589E583EC08909090909090909090909090909001FFFF0101010001909090909090909090909090909000010001000190900001"
	strings:
		$1 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_69___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [Watcom C/C++ DLL]"
		pattern = "535657558B7424148B7C24188B6C241C83FF030F8701000000F1"
	strings:
		$1 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_70___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [yoda's Protector 1.02]"
		pattern = "E803000000EB019090"
	strings:
		$1 = { E8 03 00 00 00 EB 01 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_71___PseudoSigner {
	meta:
		tool = "P"
		name = "* PseudoSigner"
		version = "0.2 [ZCode 1.01]"
		pattern = "E912000000000000000000000000000000E9FBFFFFFFC3680000000064FF3500000000"
	strings:
		$1 = { E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_72_____Protector {
	meta:
		tool = "P"
		name = "*** Protector"
		version = "1.1.11 (DDeM->PE Engine v0.9, DDeM->CI v0.9.2)"
		pattern = "535156E8000000005B81EB081000008DB334100000B9F3030000BA63172AEE311683C604"
	strings:
		$1 = { 53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_73__BJFnt {
	meta:
		tool = "P"
		name = ".BJFnt"
		version = "1.1b"
		pattern = "EB01EA9CEB01EA53EB01EA51EB01EA52EB01EA56"
	strings:
		$1 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_74__BJFnt {
	meta:
		tool = "P"
		name = ".BJFnt"
		version = "1.2 RC"
		pattern = "EB0269B183EC04EB03CD20EBEB01EB9CEB01EBEB"
	strings:
		$1 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_75__BJFnt {
	meta:
		tool = "P"
		name = ".BJFnt"
		version = "1.3"
		pattern = "EB??3A????1EEB??CD209CEB??CD20EB??CD2060EB"
	strings:
		$1 = { EB ?? 3A ?? ?? 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_76_32Lite {
	meta:
		tool = "P"
		name = "32Lite"
		version = "0.03a"
		pattern = "6006FC1E07BE????????6A0468??10????68"
	strings:
		$1 = { 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? 10 ?? ?? 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_77_Anticrack_Software_Protector {
	meta:
		tool = "P"
		name = "Anticrack Software Protector"
		version = "1.09"
		pattern = "60??????????????????E801000000????????????????????????????????????????????0000??????04"
	strings:
		$1 = { 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 04 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
