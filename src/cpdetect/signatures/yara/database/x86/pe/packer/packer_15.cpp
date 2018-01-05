/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_15.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_15 =
R"x86_pe_packer(
rule rule_416_DotFix_Nice_Protect {
	meta:
		tool = "P"
		name = "DotFix Nice Protect"
		version = "vna"
		pattern = "60E8550000008DBD0010400068??????00033C248BF79068311040009BDBE355DB04248BC7DB442404DEC1DB1C248B1C2466AD51DB04249090DA8D77104000DB1C24D1E129"
	strings:
		$1 = { 60 E8 55 00 00 00 8D BD 00 10 40 00 68 ?? ?? ?? 00 03 3C 24 8B F7 90 68 31 10 40 00 9B DB E3 55 DB 04 24 8B C7 DB 44 24 04 DE C1 DB 1C 24 8B 1C 24 66 AD 51 DB 04 24 90 90 DA 8D 77 10 40 00 DB 1C 24 D1 E1 29 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_417_Dr_Web_Virus_Finding_Engine {
	meta:
		tool = "P"
		name = "Dr.Web Virus-Finding Engine"
		pattern = "B801000000C20C008D80000000008BD28B??2404"
	strings:
		$1 = { B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_418_DragonArmor {
	meta:
		tool = "P"
		name = "DragonArmor"
		pattern = "BF4C????0083C9FF33C06834????00F2AEF7D14951684C????00E8110A000083C40C684C????00FF1500????008BF0BF4C????0083C9FF33C0F2AEF7D149BF4C????008BD16834????00C1E902F3AB8BCA83E103F3AABF5C????0083C9FF33C0F2AEF7D14951685C????00E8C00900008B1D04????0083C40C685C????0056FFD3A3D4????00BF5C????0083C9FF33C0F2AEF7D149BF5C????008BD16834????00C1E902F3AB8BCA83E1"
	strings:
		$1 = { BF 4C ?? ?? 00 83 C9 FF 33 C0 68 34 ?? ?? 00 F2 AE F7 D1 49 51 68 4C ?? ?? 00 E8 11 0A 00 00 83 C4 0C 68 4C ?? ?? 00 FF 15 00 ?? ?? 00 8B F0 BF 4C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 4C ?? ?? 00 8B D1 68 34 ?? ?? 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF 5C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 5C ?? ?? 00 E8 C0 09 00 00 8B 1D 04 ?? ?? 00 83 C4 0C 68 5C ?? ?? 00 56 FF D3 A3 D4 ?? ?? 00 BF 5C ?? ?? 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 5C ?? ?? 00 8B D1 68 34 ?? ?? 00 C1 E9 02 F3 AB 8B CA 83 E1 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_419_Dropper_Creator {
	meta:
		tool = "P"
		name = "Dropper Creator"
		version = "0.1"
		pattern = "60E8000000005D8D05????????29C58D85????????31C064034030780C8B400C8B701CAD8B4008EB09"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 8D 05 ?? ?? ?? ?? 29 C5 8D 85 ?? ?? ?? ?? 31 C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_420_DSHIELD {
	meta:
		tool = "P"
		name = "DSHIELD"
		pattern = "06E8????5E83EE??16179C58B9????25????2E"
	strings:
		$1 = { 06 E8 ?? ?? 5E 83 EE ?? 16 17 9C 58 B9 ?? ?? 25 ?? ?? 2E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_421_Dual_s_Cryptor {
	meta:
		tool = "P"
		name = "Dual's Cryptor"
		pattern = "558BEC81EC00050000E8000000005D81ED0E"
	strings:
		$1 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_422_dUP {
	meta:
		tool = "P"
		name = "dUP"
		version = "2.x"
		pattern = "E8????????E8????????8BF06A0068????????56E8????????A2????????6A0068????????56E8????????A2????????6A0068????????56E8????????A2????????68????????68????????56E8????????3C017519BE????????68000200005668"
	strings:
		$1 = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A2 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 3C 01 75 19 BE ?? ?? ?? ?? 68 00 02 00 00 56 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_423_dUP {
	meta:
		tool = "P"
		name = "dUP"
		version = "2.x patcher"
		pattern = "8BCB85C974??803A017408ACAE750A4249EBEF47464249EBE9"
	strings:
		$1 = { 8B CB 85 C9 74 ?? 80 3A 01 74 08 AC AE 75 0A 42 49 EB EF 47 46 42 49 EB E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_424_DXPACK {
	meta:
		tool = "P"
		name = "DXPACK"
		pattern = "60E8000000005D8BFD81ED061040002BBD9412400081EF0600000083BD14134000010F842F010000C785141340000100000089BD1C1340008D9DB21140008DB56511400046803E00742456FF953412400046803E0075FA46803E0074E7505650"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00 C7 85 14 13 40 00 01 00 00 00 89 BD 1C 13 40 00 8D 9D B2 11 40 00 8D B5 65 11 40 00 46 80 3E 00 74 24 56 FF 95 34 12 40 00 46 80 3E 00 75 FA 46 80 3E 00 74 E7 50 56 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_425_DxPack {
	meta:
		tool = "P"
		name = "DxPack"
		version = "0.86"
		pattern = "60E8000000005D8BFD81ED061040002BBD9412400081EF0600000083BD14134000010F842F010000"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_426_DxPack {
	meta:
		tool = "P"
		name = "DxPack"
		version = "1.0"
		pattern = "60E8????????5D8BFD81ED????????2BB9????????81EF????????83BD??????????0F84"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_427_DzA_Patcher {
	meta:
		tool = "P"
		name = "DzA Patcher"
		version = "1.3 Loader"
		pattern = "BF0040400099684820400068002040005252525252525257E81501000085C0751C9952525752E8CB000000FF354C204000E8D20000006A00E8BF000000996858204000525268631040005252E8DB0000006AFFFF3548204000E8C2000000E8C8FFFFFFBF40404000FF354C204000E8A10000008B0F83F90074B1606A006A046A0151FF3548204000E8750000006160BB5C2040006A006A015351FF3548204000E87500000061A0"
	strings:
		$1 = { BF 00 40 40 00 99 68 48 20 40 00 68 00 20 40 00 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35 4C 20 40 00 E8 D2 00 00 00 6A 00 E8 BF 00 00 00 99 68 58 20 40 00 52 52 68 63 10 40 00 52 52 E8 DB 00 00 00 6A FF FF 35 48 20 40 00 E8 C2 00 00 00 E8 C8 FF FF FF BF 40 40 40 00 FF 35 4C 20 40 00 E8 A1 00 00 00 8B 0F 83 F9 00 74 B1 60 6A 00 6A 04 6A 01 51 FF 35 48 20 40 00 E8 75 00 00 00 61 60 BB 5C 20 40 00 6A 00 6A 01 53 51 FF 35 48 20 40 00 E8 75 00 00 00 61 A0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_428_E_You_Di_Dai {
	meta:
		tool = "P"
		name = "E.You.Di.Dai"
		pattern = "558BECB8????????E8????????5356570F318BD80F318BD02BD3C1EA10B8????????0F6EC0B8????????0F6EC80FF5C10F7EC00F7703C2??????????FFE0"
	strings:
		$1 = { 55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 57 0F 31 8B D8 0F 31 8B D0 2B D3 C1 EA 10 B8 ?? ?? ?? ?? 0F 6E C0 B8 ?? ?? ?? ?? 0F 6E C8 0F F5 C1 0F 7E C0 0F 77 03 C2 ?? ?? ?? ?? ?? FF E0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_429_E2C {
	meta:
		tool = "P"
		name = "E2C"
		pattern = "BE????BF????B9????FC57F3A5C3"
	strings:
		$1 = { BE ?? ?? BF ?? ?? B9 ?? ?? FC 57 F3 A5 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_430_EEXE {
	meta:
		tool = "P"
		name = "EEXE"
		version = "1.12"
		pattern = "B430CD213C0373??BA1F000E1FB409CD21B8FF4CCD21"
	strings:
		$1 = { B4 30 CD 21 3C 03 73 ?? BA 1F 00 0E 1F B4 09 CD 21 B8 FF 4C CD 21 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_431_Elicense_System {
	meta:
		tool = "P"
		name = "Elicense System"
		version = "4.0.0.0"
		pattern = "0000000063796200656C6963656E34302E646C6C00000000"
	strings:
		$1 = { 00 00 00 00 63 79 62 00 65 6C 69 63 65 6E 34 30 2E 64 6C 6C 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_432_EmbedPE {
	meta:
		tool = "P"
		name = "EmbedPE"
		version = "1.00 - 1.24"
		pattern = "00000000????????0000000000000000????????????????0000000000000000000000000000000000000000????????????????????????00000000????????????????????????000000004B45524E454C33322E646C6C0000000047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C69627261727941000000000000000000"
	strings:
		$1 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_433_EmbedPE {
	meta:
		tool = "P"
		name = "EmbedPE"
		version = "1.13"
		pattern = "83EC5060685DB9525AE82F990000DC99F3570568"
	strings:
		$1 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_434_EmbedPE {
	meta:
		tool = "P"
		name = "EmbedPE"
		version = "1.13"
		pattern = "83EC5060685DB9525AE82F990000DC99F3570568B85E2DC6DAFD4863053C71B85E977C367E327C084F06516410A3F14ECF25CB80D2995446EDE1D346862D106893835C464D439B8CD67CBB996997712A2FA3386B33A3F50B85977CBA1D96DD07F8FDD23A9883CC46999DDF6F899254469F9443CC41439B8C61B9D86F963BD1073224DD07058ECB6FA1075C6220E0DBBA9D835446E683517A2B9454648A830568D75E2DC6B75700"
	strings:
		$1 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 B8 5E 2D C6 DA FD 48 63 05 3C 71 B8 5E 97 7C 36 7E 32 7C 08 4F 06 51 64 10 A3 F1 4E CF 25 CB 80 D2 99 54 46 ED E1 D3 46 86 2D 10 68 93 83 5C 46 4D 43 9B 8C D6 7C BB 99 69 97 71 2A 2F A3 38 6B 33 A3 F5 0B 85 97 7C BA 1D 96 DD 07 F8 FD D2 3A 98 83 CC 46 99 9D DF 6F 89 92 54 46 9F 94 43 CC 41 43 9B 8C 61 B9 D8 6F 96 3B D1 07 32 24 DD 07 05 8E CB 6F A1 07 5C 62 20 E0 DB BA 9D 83 54 46 E6 83 51 7A 2B 94 54 64 8A 83 05 68 D7 5E 2D C6 B7 57 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_435_EmbedPE {
	meta:
		tool = "P"
		name = "EmbedPE"
		version = "1.24"
		pattern = "83EC506068????????E8CBFF0000"
	strings:
		$1 = { 83 EC 50 60 68 ?? ?? ?? ?? E8 CB FF 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_436_EncryptPE {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "1.2003.3.18 - 1.2003.5.18"
		pattern = "609C64FF3500000000E879"
	strings:
		$1 = { 60 9C 64 FF 35 00 00 00 00 E8 79 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_437_EncryptPE {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2004.6.16 - 2.2006.6.30"
		pattern = "609C64FF3500000000E87A"
	strings:
		$1 = { 60 9C 64 FF 35 00 00 00 00 E8 7A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_438_EncryptPE {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2006.1.15"
		pattern = "4550453A20456E637279707450452056322E323030362E312E3135"
	strings:
		$1 = { 45 50 45 3A 20 45 6E 63 72 79 70 74 50 45 20 56 32 2E 32 30 30 36 2E 31 2E 31 35 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_439_EncryptPE {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2006.7.10 - 2.2006.10.25"
		pattern = "609C64FF3500000000E873010000"
	strings:
		$1 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_440_EncryptPE {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2007.04.11"
		pattern = "609C64FF3500000000E81B020000000000000000000000000000????????????????0000000000000000000000000000000000000000????????????????????????????????????????????????????????????????????????000000006B65726E656C33322E646C6C00000047657454656D70506174684100000043726561746546696C654100000043726561746546696C654D617070696E67410000004D6170566965774F6646696C65000000556E6D6170566965774F6646696C65000000436C6F736548616E646C650000004C6F61644C6962726172794100000047657450726F63416464726573730000004578697450726F63657373"
	strings:
		$1 = { 60 9C 64 FF 35 00 00 00 00 E8 1B 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_441_EncryptPE {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2007.12.1"
		pattern = "000000000000000000000000000000004550453A20456E637279707450452056322E323030372E31322E312C20436F7079726967687420284329205746530000486F6D65506167653A207777772E656E637279707470652E636F6D0000000000454D61696C3A2077667323656E637279707470652E636F6D0000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 45 50 45 3A 20 45 6E 63 72 79 70 74 50 45 20 56 32 2E 32 30 30 37 2E 31 32 2E 31 2C 20 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 57 46 53 00 00 48 6F 6D 65 50 61 67 65 3A 20 77 77 77 2E 65 6E 63 72 79 70 74 70 65 2E 63 6F 6D 00 00 00 00 00 45 4D 61 69 6C 3A 20 77 66 73 23 65 6E 63 72 79 70 74 70 65 2E 63 6F 6D 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_442_EncryptPE {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2008.6.18"
		pattern = "000000000000000000000000000000000000000000000000000000000000006B65726E656C33322E646C6C0047657454656D7050617468410043726561746546696C65410043726561746546696C654D617070696E6741004D6170566965774F6646696C6500556E6D6170566965774F6646696C6500436C6F736548616E646C65004C6F61644C69627261727941004578697450726F63657373000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000563232303038303631382E455045000000456E637279707450455F496E697400"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 43 72 65 61 74 65 46 69 6C 65 41 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 32 32 30 30 38 30 36 31 38 2E 45 50 45 00 00 00 45 6E 63 72 79 70 74 50 45 5F 49 6E 69 74 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_443_EncryptPE {
	meta:
		tool = "P"
		name = "EncryptPE"
		version = "2.2008.6.18"
		pattern = "68??????00E8520100000000000000000000000000000000000000000000000000000000000000000000000000006B65726E656C33322E646C6C0047657454656D70506174684100437265617465"
	strings:
		$1 = { 68 ?? ?? ?? 00 E8 52 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 43 72 65 61 74 65 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
