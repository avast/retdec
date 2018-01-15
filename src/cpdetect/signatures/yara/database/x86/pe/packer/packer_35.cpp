/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_35.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_35 =
R"x86_pe_packer(
rule rule_951_PackItBitch {
	meta:
		tool = "P"
		name = "PackItBitch"
		version = "1.0"
		pattern = "000000000000000000000000????????????????00000000000000000000000000000000000000004B45524E454C33322E444C4C00????????????????0000000000004C6F61644C6962726172794100000047657450726F63416464726573730000??000000000000????????????????0000000000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_952_PackItBitch {
	meta:
		tool = "P"
		name = "PackItBitch"
		version = "1.0"
		pattern = "00000000000000000000000028??????35??????00000000000000000000000000000000000000004B45524E454C33322E444C4C0041??????50??????0000000000004C6F61644C6962726172794100000047657450726F63416464726573730000??????????????79??????7D??????0000000000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 28 ?? ?? ?? 35 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 41 ?? ?? ?? 50 ?? ?? ?? 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? ?? ?? ?? ?? ?? ?? 79 ?? ?? ?? 7D ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_953_Packman {
	meta:
		tool = "P"
		name = "Packman"
		version = "0.0.0.1"
		pattern = "0F85??FFFFFF8DB3????????EB3D8B460C03C350FF5500568B360BF675028BF703F303FBEB1BD1C1D1E973050FB7C9EB0503CB8D4902505150FF5504AB5883C6048B0E85C975DF5E83C6148B7E1085FF75BC8D8B0000????B800????000BC0743403C3EB2A8D700803400433ED33D2668B2E660FA4EA0480FA03750D81E5FF0F000003EF03EB014D0046463BF075DC8B3885FF75D061E9??FEFFFF02D275058A164612D2C3"
	strings:
		$1 = { 0F 85 ?? FF FF FF 8D B3 ?? ?? ?? ?? EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36 0B F6 75 02 8B F7 03 F3 03 FB EB 1B D1 C1 D1 E9 73 05 0F B7 C9 EB 05 03 CB 8D 49 02 50 51 50 FF 55 04 AB 58 83 C6 04 8B 0E 85 C9 75 DF 5E 83 C6 14 8B 7E 10 85 FF 75 BC 8D 8B 00 00 ?? ?? B8 00 ?? ?? 00 0B C0 74 34 03 C3 EB 2A 8D 70 08 03 40 04 33 ED 33 D2 66 8B 2E 66 0F A4 EA 04 80 FA 03 75 0D 81 E5 FF 0F 00 00 03 EF 03 EB 01 4D 00 46 46 3B F0 75 DC 8B 38 85 FF 75 D0 61 E9 ?? FE FF FF 02 D2 75 05 8A 16 46 12 D2 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_954_Packman {
	meta:
		tool = "P"
		name = "Packman"
		version = "0.0.0.1"
		pattern = "60E800000000588D??????????8D??????????8D"
	strings:
		$1 = { 60 E8 00 00 00 00 58 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_955_Packman {
	meta:
		tool = "P"
		name = "Packman"
		version = "1.0.0.0"
		pattern = "60E8000000005B8D5BC6011B8B138D73146A08590116AD4975FA"
	strings:
		$1 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_956_PACKWIN {
	meta:
		tool = "P"
		name = "PACKWIN"
		version = "1.01p"
		pattern = "8CC0FA8ED0BC????FB060E1F2E????????8BF14E8BFE8CDB2E????????8EC3FDF3A453B8????50CB"
	strings:
		$1 = { 8C C0 FA 8E D0 BC ?? ?? FB 06 0E 1F 2E ?? ?? ?? ?? 8B F1 4E 8B FE 8C DB 2E ?? ?? ?? ?? 8E C3 FD F3 A4 53 B8 ?? ?? 50 CB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_957_PAK_SFX_Archive {
	meta:
		tool = "P"
		name = "PAK-SFX Archive"
		pattern = "558BEC83????A1????2E??????2E??????????8CD78EC78D????BE????FCAC3C0D"
	strings:
		$1 = { 55 8B EC 83 ?? ?? A1 ?? ?? 2E ?? ?? ?? 2E ?? ?? ?? ?? ?? 8C D7 8E C7 8D ?? ?? BE ?? ?? FC AC 3C 0D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_958_PassEXE {
	meta:
		tool = "P"
		name = "PassEXE"
		version = "2.0"
		pattern = "061E0E0E071FBE????B9????871481??????EB??C7??????840087??????FB1F584A"
	strings:
		$1 = { 06 1E 0E 0E 07 1F BE ?? ?? B9 ?? ?? 87 14 81 ?? ?? ?? EB ?? C7 ?? ?? ?? 84 00 87 ?? ?? ?? FB 1F 58 4A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_959_PassLock_2000 {
	meta:
		tool = "P"
		name = "PassLock 2000"
		version = "1.0"
		pattern = "558BEC535657BB00504000662EF7053420400004000F8598000000E81F010000C74360010000008D83E401000050FF15F061400083EC44C7042444000000C744242C0000000054FF15E8614000B80A000000F744242C0100000074050FB744243083C444894356FF15D0614000E89E00000089434CFF15D46140008943486A00FF15E461400089435CE8F9000000E8AA000000B8FF000000720D53E8960000005BFF4B10FF4B18"
	strings:
		$1 = { 55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 00 00 C7 43 60 01 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 83 EC 44 C7 04 24 44 00 00 00 C7 44 24 2C 00 00 00 00 54 FF 15 E8 61 40 00 B8 0A 00 00 00 F7 44 24 2C 01 00 00 00 74 05 0F B7 44 24 30 83 C4 44 89 43 56 FF 15 D0 61 40 00 E8 9E 00 00 00 89 43 4C FF 15 D4 61 40 00 89 43 48 6A 00 FF 15 E4 61 40 00 89 43 5C E8 F9 00 00 00 E8 AA 00 00 00 B8 FF 00 00 00 72 0D 53 E8 96 00 00 00 5B FF 4B 10 FF 4B 18 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_960_Password_Protector {
	meta:
		tool = "P"
		name = "Password Protector"
		pattern = "060E0E071FE800005B83EB08BA270103D3E83C02BAEA"
	strings:
		$1 = { 06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_961_Password_Protector {
	meta:
		tool = "P"
		name = "Password Protector"
		pattern = "E8????????5D8BFD81??????????81??????????83????89??????????8D??????????8D??????????4680????74"
	strings:
		$1 = { E8 ?? ?? ?? ?? 5D 8B FD 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 46 80 ?? ?? 74 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_962_Patch_Creation_Wizard {
	meta:
		tool = "P"
		name = "Patch Creation Wizard"
		version = "1.2 Byte Patch"
		pattern = "E87F0300006A00E824030000A3B83340006A0068291040006A006A0150E82C0300006A00E8EF020000558BEC5651578B450C983D100100000F85C10000006A01FF35B8334000E81B030000506A016880000000FF7508E81D030000685F3040006A65FF7508E81403000068B03040006A67FF7508E80503000068013140006A66FF7508E8F60200006A00FF7508E8C8020000A3B4334000C705BC3340002C000000C705C0334000"
	strings:
		$1 = { E8 7F 03 00 00 6A 00 E8 24 03 00 00 A3 B8 33 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 2C 03 00 00 6A 00 E8 EF 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 B8 33 40 00 E8 1B 03 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 1D 03 00 00 68 5F 30 40 00 6A 65 FF 75 08 E8 14 03 00 00 68 B0 30 40 00 6A 67 FF 75 08 E8 05 03 00 00 68 01 31 40 00 6A 66 FF 75 08 E8 F6 02 00 00 6A 00 FF 75 08 E8 C8 02 00 00 A3 B4 33 40 00 C7 05 BC 33 40 00 2C 00 00 00 C7 05 C0 33 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_963_Patch_Creation_Wizard {
	meta:
		tool = "P"
		name = "Patch Creation Wizard"
		version = "1.2 Memory Patch"
		pattern = "6A00E89B020000A37A3340006A00688E1040006A006A0150E8B5020000685A31400068123140006A006A006A046A016A006A0068A23040006A00E85102000085C07431FF35623140006A006A30E862020000E80B010000FF355A314000E822020000FF355E314000E8530200006A00E8220200006A1068F730400068FE3040006A00E8630200006A00E808020000558BEC5651578B450C983D10010000756B6A01FF357A334000"
	strings:
		$1 = { 6A 00 E8 9B 02 00 00 A3 7A 33 40 00 6A 00 68 8E 10 40 00 6A 00 6A 01 50 E8 B5 02 00 00 68 5A 31 40 00 68 12 31 40 00 6A 00 6A 00 6A 04 6A 01 6A 00 6A 00 68 A2 30 40 00 6A 00 E8 51 02 00 00 85 C0 74 31 FF 35 62 31 40 00 6A 00 6A 30 E8 62 02 00 00 E8 0B 01 00 00 FF 35 5A 31 40 00 E8 22 02 00 00 FF 35 5E 31 40 00 E8 53 02 00 00 6A 00 E8 22 02 00 00 6A 10 68 F7 30 40 00 68 FE 30 40 00 6A 00 E8 63 02 00 00 6A 00 E8 08 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 75 6B 6A 01 FF 35 7A 33 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_964_Patch_Creation_Wizard {
	meta:
		tool = "P"
		name = "Patch Creation Wizard"
		version = "1.2 Seek and Destroy Patch"
		pattern = "E8C50500006A00E85E050000A3CE3940006A0068291040006A006A0150E8720500006A00E82F050000558BEC5651578B450C983D100100000F85C10000006A01FF35CE394000E861050000506A016880000000FF7508E863050000685F3040006A65FF7508E85A05000068B03040006A67FF7508E84B05000068013140006A66FF7508E83C0500006A00FF7508E80E050000A3CA394000C705D23940002C000000C705D6394000"
	strings:
		$1 = { E8 C5 05 00 00 6A 00 E8 5E 05 00 00 A3 CE 39 40 00 6A 00 68 29 10 40 00 6A 00 6A 01 50 E8 72 05 00 00 6A 00 E8 2F 05 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 0F 85 C1 00 00 00 6A 01 FF 35 CE 39 40 00 E8 61 05 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 63 05 00 00 68 5F 30 40 00 6A 65 FF 75 08 E8 5A 05 00 00 68 B0 30 40 00 6A 67 FF 75 08 E8 4B 05 00 00 68 01 31 40 00 6A 66 FF 75 08 E8 3C 05 00 00 6A 00 FF 75 08 E8 0E 05 00 00 A3 CA 39 40 00 C7 05 D2 39 40 00 2C 00 00 00 C7 05 D6 39 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_965_PAV_Cryptor {
	meta:
		tool = "P"
		name = "Pawning AntiVirus Cryptor"
		pattern = "53565755BB2C????70BE00300070BF20????70807B28007516833F0074118B1789D033D289178BE8FFD5833F0075EF833D04300070007406FF1554300070807B2802750A833E00750533C089430CFF151C300070807B28017605833E0074228B431085C0741BFF15143000708B53108B42103B4204740A85C0740650E88FFAFFFFFF1520300070807B28017503FF5324807B28007405E835FFFFFF833B007517833D10????70007406FF1510????708B0650E8A9FAFFFF8B03568BF08BFBB90B000000F3A55EE973FFFFFF5D5F5E5BC3A300300070E826FFFFFFC3908F0504300070E9E9FFFFFFC3"
	strings:
		$1 = { 53 56 57 55 BB 2C ?? ?? 70 BE 00 30 00 70 BF 20 ?? ?? 70 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 00 70 00 74 06 FF 15 54 30 00 70 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 1C 30 00 70 80 7B 28 01 76 05 83 3E 00 74 22 8B 43 10 85 C0 74 1B FF 15 14 30 00 70 8B 53 10 8B 42 10 3B 42 04 74 0A 85 C0 74 06 50 E8 8F FA FF FF FF 15 20 30 00 70 80 7B 28 01 75 03 FF 53 24 80 7B 28 00 74 05 E8 35 FF FF FF 83 3B 00 75 17 83 3D 10 ?? ?? 70 00 74 06 FF 15 10 ?? ?? 70 8B 06 50 E8 A9 FA FF FF 8B 03 56 8B F0 8B FB B9 0B 00 00 00 F3 A5 5E E9 73 FF FF FF 5D 5F 5E 5B C3 A3 00 30 00 70 E8 26 FF FF FF C3 90 8F 05 04 30 00 70 E9 E9 FF FF FF C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_966_PC_Guard {
	meta:
		tool = "P"
		name = "PC Guard"
		pattern = "FC5550E8000000005DEB01E360E803000000D2EB0B58EB014840EB0135FFE0E761B8????????60E80300000083EB0EEB010C58EB013540EB0136FFE00B612BE8"
	strings:
		$1 = { FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 B8 ?? ?? ?? ?? 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 2B E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_967_PC_Guard {
	meta:
		tool = "P"
		name = "PC Guard"
		version = "3.03d, 3.05d"
		pattern = "5550E8????????5DEB01E360E803??????D2EB0B58EB014840EB01"
	strings:
		$1 = { 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_968_PC_Guard {
	meta:
		tool = "P"
		name = "PC Guard"
		version = "4.05d, 4.10d, 4.15d"
		pattern = "FC5550E8000000005DEB01"
	strings:
		$1 = { FC 55 50 E8 00 00 00 00 5D EB 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_969_PC_Guard {
	meta:
		tool = "P"
		name = "PC Guard"
		version = "5.00"
		pattern = "FC5550E8000000005D60E80300000083EB0EEB010C58EB013540EB0136FFE00B61B8????????EB01E360E803000000D2EB0B58EB014840EB0135FFE0E7612BE8"
	strings:
		$1 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 ?? ?? ?? ?? EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_970_PCPEC {
	meta:
		tool = "P"
		name = "PCPEC"
		version = "alpha"
		pattern = "535152565755E8????????5D8BCD81??????????2B??????????83"
	strings:
		$1 = { 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B CD 81 ?? ?? ?? ?? ?? 2B ?? ?? ?? ?? ?? 83 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_971_PCPEC {
	meta:
		tool = "P"
		name = "PCPEC"
		version = "alpha preview"
		pattern = "535152565755E8000000005D8BCD81ED333040"
	strings:
		$1 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_972_PCrypt {
	meta:
		tool = "P"
		name = "PCrypt"
		version = "3.51"
		pattern = "504352595054FF76332E353100E9"
	strings:
		$1 = { 50 43 52 59 50 54 FF 76 33 2E 35 31 00 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_973_PCShrinker {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.20"
		pattern = "E8E801????6001ADB32740??68"
	strings:
		$1 = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_974_PCShrinker {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.29"
		pattern = "??BD????????01AD553940??8DB5353940"
	strings:
		$1 = { ?? BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_975_PCShrinker {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.40b"
		pattern = "9C60BD????????01??????????FF??????????6A??FF??????????50502D"
	strings:
		$1 = { 9C 60 BD ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 6A ?? FF ?? ?? ?? ?? ?? 50 50 2D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_976_PCShrinker {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.45"
		pattern = "??BD????????01ADE33840??FFB5DF3840"
	strings:
		$1 = { ?? BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_977_PCShrinker {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.71b"
		pattern = "01AD543A4000FFB5503A40006A40FF95883A4000"
	strings:
		$1 = { 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_978_PCShrinker {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.71"
		pattern = "9C60BD????????01AD543A40??FFB5503A40??6A40FF95883A40??50502D????????8985"
	strings:
		$1 = { 9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_979_PCShrinker {
	meta:
		tool = "P"
		name = "PCShrinker"
		version = "0.xx"
		pattern = "9C60BD????????01??????????FF??????????6A??FF??????????50502D"
	strings:
		$1 = { 9C 60 BD ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 6A ?? FF ?? ?? ?? ?? ?? 50 50 2D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
