/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_16.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_16 =
R"x86_pe_packer(
rule rule_444_Enigma_protector {
	meta:
		tool = "P"
		name = "Enigma protector"
		version = "1.02"

		pattern = "60E8000000005D83ED0681ED??????????????????????????????????????????????????????????????????????E8010000009A83C404EB02FF3560E8240000000000FFEB02CD208B44240C8380B80000000331C0C383C008EB02FF1589C461EB2EEAEB2B83042403EB010031C0EB018564FF30EB0183648920EB02CD2089009A648F0500000000EB02C1905861EB013EBE01000000C1E60283EC0487DE891C24"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 FF 15 89 C4 61 EB 2E EA EB 2B 83 04 24 03 EB 01 00 31 C0 EB 01 85 64 FF 30 EB 01 83 64 89 20 EB 02 CD 20 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 90 58 61 EB 01 3E BE 01 00 00 00 C1 E6 02 83 EC 04 87 DE 89 1C 24 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_445_Enigma {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.1x"
		pattern = "60E8000000005D83ED068BF55756505333D88AC333D8EB132AC3057702000081EB9A0900005B585E5FEB0583C317EBE85756505333D88AC333D8EB132AC30577"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 83 ED 06 8B F5 57 56 50 53 33 D8 8A C3 33 D8 EB 13 2A C3 05 77 02 00 00 81 EB 9A 09 00 00 5B 58 5E 5F EB 05 83 C3 17 EB E8 57 56 50 53 33 D8 8A C3 33 D8 EB 13 2A C3 05 77 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_446_Enigma {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.1x - 1.5x"
		pattern = "558BEC83C4F0B800104000E8????????9A83C4108BE55DE9"
	strings:
		$1 = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 ?? ?? ?? ?? 9A 83 C4 10 8B E5 5D E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_447_Enigma {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.0 - 1.2"
		pattern = "60E8000000005D83????81"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 83 ?? ?? 81 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_448_Enigma {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.10 unregistered"
		pattern = "6072807288728C729072947298729C72A072A459A8B05CE839D539E439F131F95C3D58CA5F56B12D207A2E301632722B72361CA533A99CAD9CB19CB59CB99CBD9CC19CC59CC99CCD9CD19CD59CD99CDD9CE19CE589"
	strings:
		$1 = { 60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_449_Enigma {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.x"
		pattern = "456E69676D612070726F746563746F72207631"
	strings:
		$1 = { 45 6E 69 67 6D 61 20 70 72 6F 74 65 63 74 6F 72 20 76 31 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_450_Enigma {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.31 DLL"
		pattern = "60E8000000005D81ED0600000081ED????????E949000000????????????????????????????????????????????????????????????????????????????????0000000000000000000000000000000000000000000000000000000000000000008A84242800000080F8010F8407000000B8????????FFE0E904000000????????B8????????03C581C0????????B9????????BA????????301040490F85F6FFFFFFE904000000"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 81 ED ?? ?? ?? ?? E9 49 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 8A 84 24 28 00 00 00 80 F8 01 0F 84 07 00 00 00 B8 ?? ?? ?? ?? FF E0 E9 04 00 00 00 ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 81 C0 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 30 10 40 49 0F 85 F6 FF FF FF E9 04 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_451_Enigma {
	meta:
		tool = "P"
		name = "Enigma"
		version = "1.x"
		pattern = "0000005669727475616C416C6C6F630000005669727475616C467265650000004765744D6F64756C6548616E646C654100000047657450726F63416464726573730000004578697450726F636573730000004C6F61644C696272617279410000004D657373616765426F7841000000526567436C6F73654B657900000053797346726565537472696E67000000437265617465466F6E74410000005368656C6C45786563757465410000"
	strings:
		$1 = { 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 00 00 52 65 67 43 6C 6F 73 65 4B 65 79 00 00 00 53 79 73 46 72 65 65 53 74 72 69 6E 67 00 00 00 43 72 65 61 74 65 46 6F 6E 74 41 00 00 00 53 68 65 6C 6C 45 78 65 63 75 74 65 41 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_452_EP {
	meta:
		tool = "P"
		name = "EP"
		version = "1.0"
		pattern = "5083C0178BF09733C033C9B124AC86C4ACAA86C4AAE2F600B8400003003C40D2338B661450708B8D3402448B1810487003BA0C????????C033FE8B30AC30D0C1F010C2D030F030C2C1AA104242CAC1E2045FE95EB1C030??68????F300C3AA"
	strings:
		$1 = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 00 B8 40 00 03 00 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C ?? ?? ?? ?? C0 33 FE 8B 30 AC 30 D0 C1 F0 10 C2 D0 30 F0 30 C2 C1 AA 10 42 42 CA C1 E2 04 5F E9 5E B1 C0 30 ?? 68 ?? ?? F3 00 C3 AA }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_453_EP {
	meta:
		tool = "P"
		name = "EP"
		version = "2.0"
		pattern = "6A??60E90101"
	strings:
		$1 = { 6A ?? 60 E9 01 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_454_EPW {
	meta:
		tool = "P"
		name = "EPW"
		version = "1.2"
		pattern = "06571E5655525153502E????????8CC005????2E??????8ED8A1????2E"
	strings:
		$1 = { 06 57 1E 56 55 52 51 53 50 2E ?? ?? ?? ?? 8C C0 05 ?? ?? 2E ?? ?? ?? 8E D8 A1 ?? ?? 2E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_455_EPW {
	meta:
		tool = "P"
		name = "EPW"
		version = "1.3"
		pattern = "06571E5655525153502E8C0608008CC083C0102E"
	strings:
		$1 = { 06 57 1E 56 55 52 51 53 50 2E 8C 06 08 00 8C C0 83 C0 10 2E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_456_Escargot {
	meta:
		tool = "P"
		name = "Escargot"
		version = "0.1 final"
		pattern = "EB0440302E31606861??????64FF350000000064892500000000B892??????8B00FFD050B8CD??????8138DEC03713752D68C9??????6A406800??0000680000????B896??????8B00FFD08B4424F08B4C24F4EB0549C60401400BC975F7BE0010????B900????00EB0549803431400BC975F7580BC0740833C0C700DEC0AD0BBE????????E9AC0000008B460CBB0000????03C35050"
	strings:
		$1 = { EB 04 40 30 2E 31 60 68 61 ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 92 ?? ?? ?? 8B 00 FF D0 50 B8 CD ?? ?? ?? 81 38 DE C0 37 13 75 2D 68 C9 ?? ?? ?? 6A 40 68 00 ?? 00 00 68 00 00 ?? ?? B8 96 ?? ?? ?? 8B 00 FF D0 8B 44 24 F0 8B 4C 24 F4 EB 05 49 C6 04 01 40 0B C9 75 F7 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B 46 0C BB 00 00 ?? ?? 03 C3 50 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_457_Escargot {
	meta:
		tool = "P"
		name = "Escargot"
		version = "0.1"
		pattern = "EB0440302E31606861"
	strings:
		$1 = { EB 04 40 30 2E 31 60 68 61 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_458_Escargot {
	meta:
		tool = "P"
		name = "Escargot"
		version = "0.1"
		pattern = "EB0828657363302E312960682B??????64FF350000000064892500000000B85C??????8B00FFD050BE0010????B900????00EB0549803431400BC975F7580BC0740833C0C700DEC0AD0BBE????????E9AC0000008B460CBB0000????03C35050B854??????8B00FFD05F803F007406C6070047EBF533FF8B160BD275038B561003D303D78B0AC702000000000BC9744BF7C100000080741481E1FFFF0000505150B850"
	strings:
		$1 = { EB 08 28 65 73 63 30 2E 31 29 60 68 2B ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 5C ?? ?? ?? 8B 00 FF D0 50 BE 00 10 ?? ?? B9 00 ?? ?? 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE ?? ?? ?? ?? E9 AC 00 00 00 8B 46 0C BB 00 00 ?? ?? 03 C3 50 50 B8 54 ?? ?? ?? 8B 00 FF D0 5F 80 3F 00 74 06 C6 07 00 47 EB F5 33 FF 8B 16 0B D2 75 03 8B 56 10 03 D3 03 D7 8B 0A C7 02 00 00 00 00 0B C9 74 4B F7 C1 00 00 00 80 74 14 81 E1 FF FF 00 00 50 51 50 B8 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_459_Excalibur {
	meta:
		tool = "P"
		name = "Excalibur"
		version = "1.03"
		pattern = "E90000000060E8140000005D81ED000000006A45E8A30000006800000000E85861EB39"
	strings:
		$1 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_460_Excalibur {
	meta:
		tool = "P"
		name = "Excalibur"
		version = "1.03"
		pattern = "E90000000060E8140000005D81ED00000000"
	strings:
		$1 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_461_Exe_Guarder {
	meta:
		tool = "P"
		name = "Exe Guarder"
		version = "1.8"
		pattern = "558BEC83C4D05356578D75FC8B442430250000FFFF81384D5A900074072D00100000EBF18945FCE8C8FFFFFF2DB20400008945F48B068B403C03068B407803068BC88B512003168B5924031E895DF08B591C031E895DEC8B41188BC84985C9725A4133C08BD8C1E30203DA8B3B033E813F4765745075408BDF83C304813B726F634175338BDF83C308813B64647265752683C70C66813F7373751C8BD003D20355F00FB712C1E2"
	strings:
		$1 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 5D EC 8B 41 18 8B C8 49 85 C9 72 5A 41 33 C0 8B D8 C1 E3 02 03 DA 8B 3B 03 3E 81 3F 47 65 74 50 75 40 8B DF 83 C3 04 81 3B 72 6F 63 41 75 33 8B DF 83 C3 08 81 3B 64 64 72 65 75 26 83 C7 0C 66 81 3F 73 73 75 1C 8B D0 03 D2 03 55 F0 0F B7 12 C1 E2 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_462_Exe_Locker {
	meta:
		tool = "P"
		name = "Exe Locker"
		version = "1.0"
		pattern = "E800000000608B6C242081ED05000000"
	strings:
		$1 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_463_EXE_Manager {
	meta:
		tool = "P"
		name = "EXE Manager"
		version = "3.0"
		source = "(c) Solar Designer"
		pattern = "B4301E06CD212E??????BF????B9????33C02E????47E2"
	strings:
		$1 = { B4 30 1E 06 CD 21 2E ?? ?? ?? BF ?? ?? B9 ?? ?? 33 C0 2E ?? ?? 47 E2 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_464_EXE_Packer {
	meta:
		tool = "P"
		name = "EXE Packer"
		version = "7.0"
		pattern = "1E068CC383????2E????????B9????8CC88ED88BF14E8BFE"
	strings:
		$1 = { 1E 06 8C C3 83 ?? ?? 2E ?? ?? ?? ?? B9 ?? ?? 8C C8 8E D8 8B F1 4E 8B FE }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_465_EXE_Stealth {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "1.1"
		pattern = "60E8000000005D81EDFB1D4000B97B0900008BF7AC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED FB 1D 40 00 B9 7B 09 00 00 8B F7 AC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_466_EXE_Stealth {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.50"
		pattern = "6090EB22457865537465616C7468202D207777772E776562746F6F6C6D61737465722E636F6DE800000000"
	strings:
		$1 = { 60 90 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D E8 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_467_EXE_Stealth {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.7"
		pattern = "EB0060EB00E8000000005D81EDD32640"
	strings:
		$1 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_468_EXE_Stealth {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.71"
		pattern = "EB0060EB00E8000000005D81EDB02740"
	strings:
		$1 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED B0 27 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_469_HASP_Protection {
	meta:
		tool = "P"
		name = "HASP Protection"
		pattern = "6A??602EFF35????????2EFF35????????68????????E8????????6683C4??2EFF35????????2EFF35????????B8????????83C0??50"
	strings:
		$1 = { 6A ?? 60 2E FF 35 ?? ?? ?? ?? 2E FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 83 C4 ?? 2E FF 35 ?? ?? ?? ?? 2E FF 35 ?? ?? ?? ?? B8 ?? ?? ?? ?? 83 C0 ?? 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_470_EXE_Stealth {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.73"
		pattern = "EB00EB2F536861726577617265202D20457865537465616C746800EB167777772E776562746F6F6C6D61737465722E636F6D006090E8000000005D81EDF0274000B91500000083C105EB05EBFE83C756EB0083E90281C178432765EB0081C11025940081E963850000B9770C0000908DBD612840008BF7AC"
	strings:
		$1 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 EB 16 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 60 90 E8 00 00 00 00 5D 81 ED F0 27 40 00 B9 15 00 00 00 83 C1 05 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 77 0C 00 00 90 8D BD 61 28 40 00 8B F7 AC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_471_EXE_Stealth {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.74"
		pattern = "EB00EB17??????????????????????????????????????????????6090E8000000005D"
	strings:
		$1 = { EB 00 EB 17 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 60 90 E8 00 00 00 00 5D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_472_EXE_Stealth {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.74"
		pattern = "EB00EB17536861726577617265202D20457865537465616C7468006090E8000000005D81EDC4274000B91500000083C10483C101EB05EBFE83C756EB0083E90281C178432765EB0081C11025940081E963850000B9910C0000908DBD382840008BF7AC????????????????????????????????????????????????????????????????????????????????????????????????AAE2CC"
	strings:
		$1 = { EB 00 EB 17 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 60 90 E8 00 00 00 00 5D 81 ED C4 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 91 0C 00 00 90 8D BD 38 28 40 00 8B F7 AC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? AA E2 CC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_473_EXE_Stealth {
	meta:
		tool = "P"
		name = "EXE Stealth"
		version = "2.75"
		pattern = "906090E8000000005D81EDD1274000B915000000"
	strings:
		$1 = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_474_Exe_Stealth {
	meta:
		tool = "P"
		name = "Exe Stealth"
		version = "2.75a"
		pattern = "EB585368617265776172652D56657273696F6E20457865537465616C74682C20636F6E7461637420737570706F727440776562746F6F6C6D61737465722E636F6D202D207777772E776562746F6F6C6D61737465722E636F6D00906090E8000000005D81EDF7274000B91500000083C10483C101EB05EBFE83C756EB00EB0083E90281C178432765EB0081C11025940081E963850000B9960C0000908DBD742840008BF7AC"
	strings:
		$1 = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 90 60 90 E8 00 00 00 00 5D 81 ED F7 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 74 28 40 00 8B F7 AC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
