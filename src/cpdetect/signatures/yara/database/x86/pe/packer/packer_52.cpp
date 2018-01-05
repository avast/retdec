/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_52.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_52 =
R"x86_pe_packer(
rule rule_1422_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.547 - 2.628"
		pattern = "E80000000058BB????00002BC35068????????68????000068????0000E8????FFFFE9??FFFFFF"
	strings:
		$1 = { E8 00 00 00 00 58 BB ?? ?? 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? 00 00 68 ?? ?? 00 00 E8 ?? ?? FF FF E9 ?? FF FF FF }
	condition:
		for any of them : ( $ in (pe.entry_point .. pe.entry_point + 12) )
}
rule rule_1423_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.7xx"
		pattern = "9C60E80000000058BB????????2BC35068????????68????????68????????E8????????E9"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1424_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "3.035 - 3.043"
		pattern = "9C60685374416C685468496EE80000000058BB371F00002BC35068????????68002800006804010000E8BAFEFFFFE990FFFFFFCCCCCCCCCCCCCC558BEC83C4F4FC5357568B75088B7D0CC745FC0800000033DBBA00"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1425_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.0x embedded"
		pattern = "B8EFBEADDE506A00FF15????????E9ADFFFFFF8BC18B4C2404898829040000C7400C010000000FB64901D1E9894810C7401480000000C204008B442404C7410C010000008981290400000FB64001D1E8894110C7411480000000C20400558BEC53565733C033FF39450C8BF1760C8B4D08033C81403B450C72F48BCEE8430000008B461433D2F7F78B5E1033D28BF88BC3F7F7897E1889450C33C033C98B5508030C8240394D0C73F4488B14822BCA0FAFCF2BD90FAFFA897E14895E105F5E5B5DC20800"
	strings:
		$1 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1426_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.2xx - 2.308 embedded"
		pattern = "B8EFBEADDE506A00FF15????????E9B9FFFFFF8BC18B4C2404898829040000C7400C010000000FB64901D1E9894810C7401480000000C204008B442404C7410C010000008981290400000FB64001D1E8894110C7411480000000C20400558BEC53565733C033FF39450C8BF1760C8B4D08033C81403B450C72F48BCEE8430000008B461433D2F7F78B5E1033D28BF88BC3F7F7897E1889450C33C033C98B5508030C8240394D0C73F4488B14822BCA0FAFCF2BD90FAFFA897E14895E105F5E5B5DC20800"
	strings:
		$1 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 B9 FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1427_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.545 embedded"
		pattern = "E8F2FFFFFF5068????????68401B0000E842FFFFFFE99DFFFFFF000000000000"
	strings:
		$1 = { E8 F2 FF FF FF 50 68 ?? ?? ?? ?? 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1428_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "3.049 - 3.080 virtualization suite"
		pattern = "9C60685374416C685468496EE80000000058BB371F00002BC35068????????68002C00006804010000E8BAFEFFFFE990FFFFFFCCCCCCCCCCCCCC558BEC83C4F4FC5357568B75088B7D0CC745FC0800000033DBBA00"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 2C 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1429_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "3.0xx virtualization suite"
		pattern = "9C6068????????68????????E80000000058BB????????2BC35068????????68????????68????????E8BAFEFFFFE9????????CCCCCCCCCCCCCC558BEC83C4F4FC5357568B75088B7D0CC745FC0800000033DBBA"
	strings:
		$1 = { 9C 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 BA FE FF FF E9 ?? ?? ?? ?? CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1430_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "3.100 - 3.332 virtualization suite"
		pattern = "9C60685374416C685468496EE80000000058BB????????2BC35068????????68????????68????????E82CFFFFFFE990FFFFFFCCCC558BEC83C4F4FC5357568B75088B7D0CC745FC0800000033DBBA000000804333C0E819010000730E8B4DF8E8270100000245F7AAEBE9"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 2C FF FF FF E9 90 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1431_Thinstall {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "3.348 - 3.350 virtualization suite"
		pattern = "9C60685374416C685468496EE80000000058BB591900002BC35068????????68????????68AC000000E82CFFFFFFE9??FFFFFFCCCCCCCCCC558BEC83C4F4FC5357568B75088B7D0CC745FC0800000033DBBA000000804333C0E819010000730E8B4DF8E8270100000245F7AAEBE9E8040100000F8296000000E8F9000000735BB904000000E8050100004874DE0F89C6000000E8DF000000731B55BD00010000E8DF0000008807474D75F5E8C700000072E95DEBA2B901000000E8D000000083C0078945F8C645F70083F8087489E8B10000008845F7E97CFFFFFFB907000000E8AA0000005033C9B102E8A00000008BC84141580BC074048BD8EB5E83F902746A41E8880000008945FCE948FFFFFFE88700000049E2098BC3E87D000000EB3A498BC1558B4DFC8BE833C0D3E5E85D0000000BC55D8BD8E85F0000003D0000010073143DFF370000730E3D7F020000730883F87F770441414141568BF72BF0F3A45EE9F0FEFFFF33C0EB058BC72B450C5E5F5BC9C2080003D275088B1683C604F913D2C3B908000000E801000000C333C0E8E1FFFFFF13C0E2F7C333C941E8D4FFFFFF13C9E8CDFFFFFF72F2C3000000000000"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 59 19 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 AC 00 00 00 E8 2C FF FF FF E9 ?? FF FF FF CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 C3 B9 08 00 00 00 E8 01 00 00 00 C3 33 C0 E8 E1 FF FF FF 13 C0 E2 F7 C3 33 C9 41 E8 D4 FF FF FF 13 C9 E8 CD FF FF FF 72 F2 C3 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1432_Thunderbolt {
	meta:
		tool = "P"
		name = "Thunderbolt"
		version = "0.02"
		pattern = "E90000000060E8140000005D81ED000000006A45E8A30000006800000000E85861E8AA000000????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????5D6800FE9F0753E85D000000EBFF71E8C25000EBD65EF36889742448742458FF8D7424585E83C64C75F4598D71E8750981F6EBFF51B9010083EEFC49FF71C775198B74240000813650568B36EBFF77C43681F6EB8734248B8B1C2483ECFCEB01E883ECFCE9E70000005BEBFFF3EBFFC3"
	strings:
		$1 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 E8 AA 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5D 68 00 FE 9F 07 53 E8 5D 00 00 00 EB FF 71 E8 C2 50 00 EB D6 5E F3 68 89 74 24 48 74 24 58 FF 8D 74 24 58 5E 83 C6 4C 75 F4 59 8D 71 E8 75 09 81 F6 EB FF 51 B9 01 00 83 EE FC 49 FF 71 C7 75 19 8B 74 24 00 00 81 36 50 56 8B 36 EB FF 77 C4 36 81 F6 EB 87 34 24 8B 8B 1C 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 5B EB FF F3 EB FF C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1433_TMT_Pascal {
	meta:
		tool = "P"
		name = "TMT-Pascal"
		version = "0.40"
		pattern = "0E1F068C06????26A1????A3????8EC06633FF6633C9"
	strings:
		$1 = { 0E 1F 06 8C 06 ?? ?? 26 A1 ?? ?? A3 ?? ?? 8E C0 66 33 FF 66 33 C9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1434_TopSpeed {
	meta:
		tool = "P"
		name = "TopSpeed"
		version = "3.01"
		pattern = "1EBA????8EDA8B??????8B??????FF??????5053"
	strings:
		$1 = { 1E BA ?? ?? 8E DA 8B ?? ?? ?? 8B ?? ?? ?? FF ?? ?? ?? 50 53 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1435_TPAV_Cryptor {
	meta:
		tool = "P"
		name = "TPAV Cryptor"
		version = "1.1"
		pattern = "8D8508FFFFFF508D85C4FEFFFF506A006A006A046A006A006A008D95C0FEFFFF33C0E8????FFFF8B85C0FEFFFFE8????FFFF506A00FF152C????70"
	strings:
		$1 = { 8D 85 08 FF FF FF 50 8D 85 C4 FE FF FF 50 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 8D 95 C0 FE FF FF 33 C0 E8 ?? ?? FF FF 8B 85 C0 FE FF FF E8 ?? ?? FF FF 50 6A 00 FF 15 2C ?? ?? 70 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1436_TPPpack {
	meta:
		tool = "P"
		name = "TPPpack"
		pattern = "E8000000005D81EDF58F40006033??E8"
	strings:
		$1 = { E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 ?? E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1437_Trainer_Creation_Kit {
	meta:
		tool = "P"
		name = "Trainer Creation Kit"
		version = "5"
		pattern = "6A0068800000006A026A006A0068000000406825454000E83C020000506A0068404540006800100000680030400050E8540200005850E8170200006A00E82E020000A3704540006825454000E82B020000A3304540"
	strings:
		$1 = { 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 68 25 45 40 00 E8 3C 02 00 00 50 6A 00 68 40 45 40 00 68 00 10 00 00 68 00 30 40 00 50 E8 54 02 00 00 58 50 E8 17 02 00 00 6A 00 E8 2E 02 00 00 A3 70 45 40 00 68 25 45 40 00 E8 2B 02 00 00 A3 30 45 40 }
	condition:
		$1
}
rule rule_1438_Trivial173 {
	meta:
		tool = "P"
		name = "Trivial173"
		pattern = "EB????285472697669616C31373320627920534D542F534D4629"
	strings:
		$1 = { EB ?? ?? 28 54 72 69 76 69 61 6C 31 37 33 20 62 79 20 53 4D 54 2F 53 4D 46 29 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1439_UG2002_Cruncher {
	meta:
		tool = "P"
		name = "UG2002 Cruncher"
		version = "0.3b3"
		pattern = "60E8????????5D81ED????????E80D????????????????????????????????58"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? E8 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1440_UltraPro {
	meta:
		tool = "P"
		name = "UltraPro"
		version = "1.0"
		pattern = "A1????????85C00F853B0600005556C705????????01000000FF15"
	strings:
		$1 = { A1 ?? ?? ?? ?? 85 C0 0F 85 3B 06 00 00 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1441_UnderGround_Crypter {
	meta:
		tool = "P"
		name = "UnderGround Crypter"
		pattern = "558BEC83C4F0B8743C0011E894F9FFFFE8BFFEFFFFE80AF3FFFF8BC0"
	strings:
		$1 = { 55 8B EC 83 C4 F0 B8 74 3C 00 11 E8 94 F9 FF FF E8 BF FE FF FF E8 0A F3 FF FF 8B C0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1442_UNICOPS {
	meta:
		tool = "P"
		name = "UNICOPS"
		pattern = "68F136ADB6871C2460E8000000005F8DB7EAF7FFFF81C7320000008B0E8AD183C604C1E908740B8A0732C32AF8AAD3D3E2F580FA007407011F83C704EBDD615B"
	strings:
		$1 = { 68 F1 36 AD B6 87 1C 24 60 E8 00 00 00 00 5F 8D B7 EA F7 FF FF 81 C7 32 00 00 00 8B 0E 8A D1 83 C6 04 C1 E9 08 74 0B 8A 07 32 C3 2A F8 AA D3 D3 E2 F5 80 FA 00 74 07 01 1F 83 C7 04 EB DD 61 5B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1443_Unknown_encryptor__01 {
	meta:
		tool = "P"
		name = "unknown encryptor 1"
		pattern = "EB??2E90????8CDB8CCA8EDAFA8BECBE????BC????BF"
	strings:
		$1 = { EB ?? 2E 90 ?? ?? 8C DB 8C CA 8E DA FA 8B EC BE ?? ?? BC ?? ?? BF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1444_Unknown_encryptor__02____PK7Tjrvx {
	meta:
		tool = "P"
		name = "unknown encryptor 2"
		pattern = "06B452CD2107E8????B462CD21E8"
	strings:
		$1 = { 06 B4 52 CD 21 07 E8 ?? ?? B4 62 CD 21 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1445_Unknown_Joiner {
	meta:
		tool = "P"
		name = "unknown joiner"
		pattern = "44904C90B9DE000000BA0010400083C20344904CB90700000044904C33C9C705083040000000000090680001000068213040006A00E8C5020000906A006880"
	strings:
		$1 = { 44 90 4C 90 B9 DE 00 00 00 BA 00 10 40 00 83 C2 03 44 90 4C B9 07 00 00 00 44 90 4C 33 C9 C7 05 08 30 40 00 00 00 00 00 90 68 00 01 00 00 68 21 30 40 00 6A 00 E8 C5 02 00 00 90 6A 00 68 80 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1446_Unknown_packer__01 {
	meta:
		tool = "P"
		name = "unknown packer 1"
		pattern = "EB????BE????BF????2E"
	strings:
		$1 = { EB ?? ?? BE ?? ?? BF ?? ?? 2E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1447_Unknown_packer__02 {
	meta:
		tool = "P"
		name = "unknown packer 2"
		pattern = "FA8CDE8CCF8EDF8EC783C7??BB"
	strings:
		$1 = { FA 8C DE 8C CF 8E DF 8E C7 83 C7 ?? BB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1448_Unknown_packer__03 {
	meta:
		tool = "P"
		name = "unknown packer 3"
		pattern = "061E575650535152BD????0E1F8C"
	strings:
		$1 = { 06 1E 57 56 50 53 51 52 BD ?? ?? 0E 1F 8C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1449_Unknown_packer__04 {
	meta:
		tool = "P"
		name = "unknown packer 4"
		pattern = "BC????C32EFF2E????CF"
	strings:
		$1 = { BC ?? ?? C3 2E FF 2E ?? ?? CF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1450_Unknown_packer__05 {
	meta:
		tool = "P"
		name = "unknown packer 5"
		pattern = "FABB????B9????87E5872703E3918ACB80E1??D3C49133E38727"
	strings:
		$1 = { FA BB ?? ?? B9 ?? ?? 87 E5 87 27 03 E3 91 8A CB 80 E1 ?? D3 C4 91 33 E3 87 27 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
