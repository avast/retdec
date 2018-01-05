/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_51.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_51 =
R"x86_pe_packer(
rule rule_1388_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.70"
		pattern = "60E8BD100000C383E200F975FA70"
	strings:
		$1 = { 60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1389_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.71"
		pattern = "60E8ED100000C383"
	strings:
		$1 = { 60 E8 ED 10 00 00 C3 83 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1390_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.71b2"
		pattern = "60E844110000C383"
	strings:
		$1 = { 60 E8 44 11 00 00 C3 83 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1391_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.71b7"
		pattern = "60E848110000C383"
	strings:
		$1 = { 60 E8 48 11 00 00 C3 83 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1392_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.7x - 0.84"
		pattern = "60E80000C383"
	strings:
		$1 = { 60 E8 00 00 C3 83 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1393_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.80"
		pattern = "60E8F9110000C383"
	strings:
		$1 = { 60 E8 F9 11 00 00 C3 83 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1394_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.85f"
		pattern = "60E802000000CD20E8000000005E2BC9587402"
	strings:
		$1 = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1395_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.90"
		pattern = "????E802000000E800E8000000005E2B"
	strings:
		$1 = { ?? ?? E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1396_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.92a"
		pattern = "E97EE9FFFF00"
	strings:
		$1 = { E9 7E E9 FF FF 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1397_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.95"
		pattern = "E9D5E4FFFF00"
	strings:
		$1 = { E9 D5 E4 FF FF 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1398_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.96"
		pattern = "E959E4FFFF00000000000000????????EE????0000000000000000000E????00FE????00F6????0000000000000000001B????0006????00000000000000000000000000000000000000000026????000000000039????000000000026????000000000039????00000000006B65726E656C33322E646C6C"
	strings:
		$1 = { E9 59 E4 FF FF 00 00 00 00 00 00 00 ?? ?? ?? ?? EE ?? ?? 00 00 00 00 00 00 00 00 00 0E ?? ?? 00 FE ?? ?? 00 F6 ?? ?? 00 00 00 00 00 00 00 00 00 1B ?? ?? 00 06 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 26 ?? ?? 00 00 00 00 00 39 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1399_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.98 - 1.0"
		pattern = "E9????FFFF000000??????????????000000000000000000"
	strings:
		$1 = { E9 ?? ?? FF FF 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1400_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.98 special build"
		pattern = "E999D7FFFF000000????????AA????000000000000000000CA"
	strings:
		$1 = { E9 99 D7 FF FF 00 00 00 ?? ?? ?? ?? AA ?? ?? 00 00 00 00 00 00 00 00 00 CA }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1401_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.98"
		pattern = "E925E4FFFF000000????????1E????0000000000000000003E????002E????0026????0000000000000000004B????0036????00000000000000000000000000000000000000000056????000000000069????000000000056????000000000069????00000000006B65726E656C33322E646C6C00757365"
	strings:
		$1 = { E9 25 E4 FF FF 00 00 00 ?? ?? ?? ?? 1E ?? ?? 00 00 00 00 00 00 00 00 00 3E ?? ?? 00 2E ?? ?? 00 26 ?? ?? 00 00 00 00 00 00 00 00 00 4B ?? ?? 00 36 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 56 ?? ?? 00 00 00 00 00 69 ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1402_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.98b2"
		pattern = "E91BE4FFFF"
	strings:
		$1 = { E9 1B E4 FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1403_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.99 special build"
		pattern = "E95EDFFFFF000000????????E5????00000000000000000005????00F5????00ED????00000000000000000012????00FD????0000000000000000000000000000000000000000001D????000000000030????00000000001D????000000000030????0000000000"
	strings:
		$1 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 ?? ?? 00 F5 ?? ?? 00 ED ?? ?? 00 00 00 00 00 00 00 00 00 12 ?? ?? 00 FD ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00 1D ?? ?? 00 00 00 00 00 30 ?? ?? 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1404_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.99"
		pattern = "E95EDFFFFF000000????????E5????00000000000000000005"
	strings:
		$1 = { E9 5E DF FF FF 00 00 00 ?? ?? ?? ?? E5 ?? ?? 00 00 00 00 00 00 00 00 00 05 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1405_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "0.99c private ECLIPSE"
		pattern = "E93FDFFFFF000000????????04????00000000000000000024????0014????000C????00000000000000000031????001C????0000000000000000000000000000000000000000003C????00000000004F????00000000003C????00000000004F????00000000006B65726E656C33322E646C6C00757365"
	strings:
		$1 = { E9 3F DF FF FF 00 00 00 ?? ?? ?? ?? 04 ?? ?? 00 00 00 00 00 00 00 00 00 24 ?? ?? 00 14 ?? ?? 00 0C ?? ?? 00 00 00 00 00 00 00 00 00 31 ?? ?? 00 1C ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 3C ?? ?? 00 00 00 00 00 4F ?? ?? 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1406_tElock {
	meta:
		tool = "P"
		name = "tElock"
		version = "1.00"
		pattern = "E9E5E2FFFF"
	strings:
		$1 = { E9 E5 E2 FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1410_Themida {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.0.0.0 - 1.8.0.0"
		pattern = "B80000????600BC07458E8????????5805??0000008038E9??????????E8"
	strings:
		$1 = { B8 00 00 ?? ?? 60 0B C0 74 58 E8 ?? ?? ?? ?? 58 05 ?? 00 00 00 80 38 E9 ?? ?? ?? ?? ?? E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1411_Themida {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.0.x - 1.8.x"
		pattern = "B8????????600BC07458E8000000005805????????8038E9750361EB35E800000000582500F0FFFF33FF66BB????6683????66391875120FB7503C03D0BB????????83C3??391A74072D00100000EBDA8BF8B8????????03C7B9????????03CFEB0AB8????????B9????????5051E884000000E800000000582D????????B9????????C600E983E9??89480161E9"
	strings:
		$1 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? ?? ?? ?? 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? C6 00 E9 83 E9 ?? 89 48 01 61 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1412_Themida {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.0.x - 1.8.x no compression"
		pattern = "558BEC83C4D860E8000000005A81EA????????8BDAC745D8000000008B45D8408945D8817DD880000000740F8B45088983????????FF450843EBE18945DC618B45DCC9C20400558BEC81C47CFFFFFF60E800000000"
	strings:
		$1 = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1413_Themida {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.x"
		pattern = "8BC58BD460E8000000005D81ED????????8995????????89B5????????8985????????83BD??????????740C8BE88BE2B801000000C20C008B4424248985????????6A45E8A3000000689A748307E8DF00000068254B890AE8D5000000E9????????0000000000000000000000000000000000000000"
	strings:
		$1 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 ?? ?? ?? ?? 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1414_Themida {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.8.0.2+ WinLicense"
		pattern = "B80000????600BC07468E8????????5805??0000008038E9??????????DB2D??????????????FFFFFFFFFF"
	strings:
		$1 = { B8 00 00 ?? ?? 60 0B C0 74 68 E8 ?? ?? ?? ?? 58 05 ?? 00 00 00 80 38 E9 ?? ?? ?? ?? ?? DB 2D ?? ?? ?? ?? ?? ?? ?? FF FF FF FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1415_Themida {
	meta:
		tool = "P"
		name = "Themida"
		version = "1.8.x - 2.x WinLicense"
		pattern = "B8????????600BC07468E8000000005805530000008038E9751361EB45DB2D????????FFFFFFFFFFFFFFFF3D????????0000582500F0FFFF33FF66BB????6683????66391875120FB7503C03D0BB????????83C3??391A74072D????????EBDA8BF8B8????????03C7B9????????03CFEB0AB8????????B9????????5051E8????????E8????????58"
	strings:
		$1 = { B8 ?? ?? ?? ?? 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D ?? ?? ?? ?? 00 00 58 25 00 F0 FF FF 33 FF 66 BB ?? ?? 66 83 ?? ?? 66 39 18 75 12 0F B7 50 3C 03 D0 BB ?? ?? ?? ?? 83 C3 ?? 39 1A 74 07 2D ?? ?? ?? ?? EB DA 8B F8 B8 ?? ?? ?? ?? 03 C7 B9 ?? ?? ?? ?? 03 CF EB 0A B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 58 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1416_Themida {
	meta:
		tool = "P"
		name = "Themida"
		version = "2.0.1.0+ WinLicense"
		pattern = "00000000????????000000006B65726E656C33322E646C6C00????????0000000000000000????????????????00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		$1
}
rule rule_1417_theWRAP {
	meta:
		tool = "P"
		name = "theWRAP"
		pattern = "558BEC83C4F053565733C08945F0B848D24B00E8BC87F4FFBB040B4D0033C05568E8D54B0064FF30648920E89CF4FFFFE8F7FBFFFF6A408D55F0A1F0ED4B008B00E8422EF7FF8B4DF0B201A1F4C24000E8F720F5FF8BF0B201A1B4C34000E8F15BF4FF890333D28B03E8421EF5FF66B90200BAFCFFFFFF8BC68B38FF570CBAB8A74D00B9040000008BC68B38FF5704833DB8A74D00000F845E0100008B15B8A74D0083C204F7DA66B902008BC68B38FF570C8B0DB8A74D008BD68B03E82B1FF5FF8BC6E8B45BF4FF33D28B03E8DF1DF5FFBAF0444E00B9010000008B038B30FF5604803DF0444E000A753FBAB8A74D00B9040000008B038B30FF56048B15B8A7"
	strings:
		$1 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 48 D2 4B 00 E8 BC 87 F4 FF BB 04 0B 4D 00 33 C0 55 68 E8 D5 4B 00 64 FF 30 64 89 20 E8 9C F4 FF FF E8 F7 FB FF FF 6A 40 8D 55 F0 A1 F0 ED 4B 00 8B 00 E8 42 2E F7 FF 8B 4D F0 B2 01 A1 F4 C2 40 00 E8 F7 20 F5 FF 8B F0 B2 01 A1 B4 C3 40 00 E8 F1 5B F4 FF 89 03 33 D2 8B 03 E8 42 1E F5 FF 66 B9 02 00 BA FC FF FF FF 8B C6 8B 38 FF 57 0C BA B8 A7 4D 00 B9 04 00 00 00 8B C6 8B 38 FF 57 04 83 3D B8 A7 4D 00 00 0F 84 5E 01 00 00 8B 15 B8 A7 4D 00 83 C2 04 F7 DA 66 B9 02 00 8B C6 8B 38 FF 57 0C 8B 0D B8 A7 4D 00 8B D6 8B 03 E8 2B 1F F5 FF 8B C6 E8 B4 5B F4 FF 33 D2 8B 03 E8 DF 1D F5 FF BA F0 44 4E 00 B9 01 00 00 00 8B 03 8B 30 FF 56 04 80 3D F0 44 4E 00 0A 75 3F BA B8 A7 4D 00 B9 04 00 00 00 8B 03 8B 30 FF 56 04 8B 15 B8 A7 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1418_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		pattern = "????????????????????????????????FFFFFF8BC18B4C2404898829040000C7400C010000000FB64901D1E9894810C7401480000000C204008B442404C7410C"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1419_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "1.9 - 2.460"
		pattern = "558BEC515356576A006A00FF15????????50E887FCFFFF5959A1????????8B40100305????????8945FC8B45FCFFE05F5E5BC9C3000000"
	strings:
		$1 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 ?? ?? ?? ?? 50 E8 87 FC FF FF 59 59 A1 ?? ?? ?? ?? 8B 40 10 03 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1420_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.312 - 2.403"
		pattern = "6A00FF15????????E8D4F8FFFFE9E9ADFFFFFF8BC18B4C2404898829040000C7400C010000000FB64901D1E9894810C7401480000000C204008B442404C7410C010000008981290400000FB64001D1E8894110C741"
	strings:
		$1 = { 6A 00 FF 15 ?? ?? ?? ?? E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1421_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.4 - 2.5"
		pattern = "558BECB8??????????????????50E800000000582D????????B9????????BA????????BE????????BF????????BD????????03E8"
	strings:
		$1 = { 55 8B EC B8 ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? BD ?? ?? ?? ?? 03 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
