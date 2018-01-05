/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_61.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_61 =
R"x86_pe_packer(
rule rule_1704_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.00, 3.01 extractable"
		pattern = "B8????8CCA03D08CC981C1????516A??06068CD383????536A??FC"
	strings:
		$1 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 6A ?? 06 06 8C D3 83 ?? ?? 53 6A ?? FC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1705_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.00, 3.01 relocations pack"
		pattern = "BE????BA????BF????B9????8CCD8EDD81ED????06068BDD2BDA8BD3FC"
	strings:
		$1 = { BE ?? ?? BA ?? ?? BF ?? ?? B9 ?? ?? 8C CD 8E DD 81 ED ?? ?? 06 06 8B DD 2B DA 8B D3 FC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1706_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.02, v3.02a extractable"
		pattern = "B8????8CCA03D08CC981C1????5133C9B1??510606BB????538CD3"
	strings:
		$1 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 33 C9 B1 ?? 51 06 06 BB ?? ?? 53 8C D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1707_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.02, 3.02a, 3.04 relocations pack"
		pattern = "BE????BF????B9????8CCD81ED????8BDD81EB????8BD3FCFA1E8EDB011533C02EAC"
	strings:
		$1 = { BE ?? ?? BF ?? ?? B9 ?? ?? 8C CD 81 ED ?? ?? 8B DD 81 EB ?? ?? 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1708_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.03"
		pattern = "B8????8CCA03D08CC981C1????51B9????510606BB????53"
	strings:
		$1 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 BB ?? ?? 53 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1709_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.05c4 extractable + password checking + virus shield"
		pattern = "0305C01AB8????8CCA03D08CC981C1????51B9????510606B1??518CD3"
	strings:
		$1 = { 03 05 C0 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1710_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.05c4 extractable + password checking"
		pattern = "0305801AB8????8CCA03D08CC981C1????51B9????510606B1??518CD3"
	strings:
		$1 = { 03 05 80 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1711_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.05c4 extractable + virus shield"
		pattern = "0305401AB8????8CCA03D08CC981C1????51B9????510606B1??518CD3"
	strings:
		$1 = { 03 05 40 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1712_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.05c4 extractable"
		pattern = "0305001AB8????8CCA03D08CC981C1????51B9????510606B1??518CD3"
	strings:
		$1 = { 03 05 00 1A B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1713_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.05c4 modified"
		pattern = "B8????8CCA03D08CC981C1????51B9????510606B1??518CD3"
	strings:
		$1 = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1714_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.05c4 unextractable + password checking + virus shield"
		pattern = "0305C01BB8????8CCA03D08CC981C1????51B9????510606B1??518CD3"
	strings:
		$1 = { 03 05 C0 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1715_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.05c4 unextractable + password checking"
		pattern = "0305801BB8????8CCA03D08CC981C1????51B9????510606B1??518CD3"
	strings:
		$1 = { 03 05 80 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1716_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.05c4 unextractable + virus shield"
		pattern = "0305401BB8????8CCA03D08CC981C1????51B9????510606B1??518CD3"
	strings:
		$1 = { 03 05 40 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1717_WWPACK {
	meta:
		tool = "P"
		name = "WWPACK"
		version = "3.05c4 unextractable"
		pattern = "0305001BB8????8CCA03D08CC981C1????51B9????510606B1??518CD3"
	strings:
		$1 = { 03 05 00 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1718_WWPack32 {
	meta:
		tool = "P"
		name = "WWPack32"
		version = "1.x"
		pattern = "53558BE833DBEB60"
	strings:
		$1 = { 53 55 8B E8 33 DB EB 60 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1719_X_Hider {
	meta:
		tool = "P"
		name = "X-Hider"
		version = "1.0"
		comment = "GlobaL"
		pattern = "558BEC83C4EC33C08945ECB854204444E8DFF8FFFF33C055680821444464FF306489208D55ECB81C214444E8E0F9FFFF8B55ECB840????44E88BF5FFFF6A006A006A026A006A016800000040A140????44E87EF6FFFF50E84CF9FFFF6A0050E84CF9FFFFA328????44E8CEFEFFFF33C05A5959648910680F2144448D45ECE8F1F4FFFFC3E9BBF2FFFFEBF0E8FCF3FFFFFFFFFFFF0E000000633A5C303030303030312E64617400"
	strings:
		$1 = { 55 8B EC 83 C4 EC 33 C0 89 45 EC B8 54 20 44 44 E8 DF F8 FF FF 33 C0 55 68 08 21 44 44 64 FF 30 64 89 20 8D 55 EC B8 1C 21 44 44 E8 E0 F9 FF FF 8B 55 EC B8 40 ?? ?? 44 E8 8B F5 FF FF 6A 00 6A 00 6A 02 6A 00 6A 01 68 00 00 00 40 A1 40 ?? ?? 44 E8 7E F6 FF FF 50 E8 4C F9 FF FF 6A 00 50 E8 4C F9 FF FF A3 28 ?? ?? 44 E8 CE FE FF FF 33 C0 5A 59 59 64 89 10 68 0F 21 44 44 8D 45 EC E8 F1 F4 FF FF C3 E9 BB F2 FF FF EB F0 E8 FC F3 FF FF FF FF FF FF 0E 00 00 00 63 3A 5C 30 30 30 30 30 30 31 2E 64 61 74 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1720_X_Hider {
	meta:
		tool = "P"
		name = "X-Hider"
		version = "1.0"
		comment = "GlobaL"
		pattern = "85D274238B4AF8417F1A50528B42FCE83000000089C258528B48FCE848FBFFFF5A58EB03FF42F8871085D274138B4AF8497C0DFF4AF875088D42F8E85CFAFFFFC38D400085C07E245083C00A83E0FE50E82FFAFFFF5A66C74402FE000083C0085A8950FCC740F801000000C331C0C390"
	strings:
		$1 = { 85 D2 74 23 8B 4A F8 41 7F 1A 50 52 8B 42 FC E8 30 00 00 00 89 C2 58 52 8B 48 FC E8 48 FB FF FF 5A 58 EB 03 FF 42 F8 87 10 85 D2 74 13 8B 4A F8 49 7C 0D FF 4A F8 75 08 8D 42 F8 E8 5C FA FF FF C3 8D 40 00 85 C0 7E 24 50 83 C0 0A 83 E0 FE 50 E8 2F FA FF FF 5A 66 C7 44 02 FE 00 00 83 C0 08 5A 89 50 FC C7 40 F8 01 00 00 00 C3 31 C0 C3 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1721_X_Pack {
	meta:
		tool = "P"
		name = "X-Pack"
		version = "1.4.2"
		pattern = "72??C38BDE83????C1????8CD803C38ED88BDF83????C1????8CC003C38EC0C3"
	strings:
		$1 = { 72 ?? C3 8B DE 83 ?? ?? C1 ?? ?? 8C D8 03 C3 8E D8 8B DF 83 ?? ?? C1 ?? ?? 8C C0 03 C3 8E C0 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1722_X_Pack {
	meta:
		tool = "P"
		name = "X-Pack"
		version = "1.52 - 1.64"
		pattern = "8BECFA33C08ED0BC????2E????????2E????????EB"
	strings:
		$1 = { 8B EC FA 33 C0 8E D0 BC ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1723_X_Pack {
	meta:
		tool = "P"
		name = "X-Pack"
		version = "1.67 COM"
		pattern = "E95300FFFDFFFBFFF9FFBC03008BE54C4CC3"
	strings:
		$1 = { E9 53 00 FF FD FF FB FF F9 FF BC 03 00 8B E5 4C 4C C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1724_X_Pack {
	meta:
		tool = "P"
		name = "X-Pack"
		version = "1.67"
		pattern = "B88CD3153375813EE80F009AE8F9FF9A9CEB019A5980CD01519DEB"
	strings:
		$1 = { B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1725_X_PEOR {
	meta:
		tool = "P"
		name = "X-PEOR"
		version = "0.99b"
		pattern = "E8????????5D8BCD81ED7A2940??89AD0F6D40"
	strings:
		$1 = { E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1726_X_PEOR {
	meta:
		tool = "P"
		name = "X-PEOR"
		version = "0.99b"
		pattern = "E8000000005D8BCD81ED7A29400089AD0F6D4000"
	strings:
		$1 = { E8 00 00 00 00 5D 8B CD 81 ED 7A 29 40 00 89 AD 0F 6D 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1727_XComp_XPack {
	meta:
		tool = "P"
		name = "XComp/XPack"
		version = "0.97 - 0.98"
		pattern = "68????????9C60E8????????????????0000000000000000????????????????0000000000000000000000000000000000000000????????????????????????????????????????000000004B45524E454C33322E444C4C00000047657450726F63416464726573730000004C6F61644C696272617279410000005669727475616C416C6C6F630000005669727475616C467265650000005669727475616C50726F7465637400"
	strings:
		$1 = { 68 ?? ?? ?? ?? 9C 60 E8 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1728_XComp_XPack {
	meta:
		tool = "P"
		name = "XComp/XPack"
		version = "0.97 - 0.98"
		pattern = "68????????9C60E8????????????????0000000000000000????????????????0000000000000000000000000000000000000000????????????????????????000000004B45524E454C33322E444C4C00000047657450726F63416464726573730000004C6F61644C696272617279410000005669727475616C50726F7465637400"
	strings:
		$1 = { 68 ?? ?? ?? ?? 9C 60 E8 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1729_XComp_XPack {
	meta:
		tool = "P"
		name = "XComp/XPack"
		version = "0.9X"
		pattern = "AC84C07403AAEBF8E80B000000206E6F7420666F756E64005EACAA84C075FA6A0057526A00E8060000004572726F72005EACAA84C075FAE80B0000005553455233322E444C4C00FF552CE80C0000004D657373616765426F78410050FF5528FFD083C47C48C3"
	strings:
		$1 = { AC 84 C0 74 03 AA EB F8 E8 0B 00 00 00 20 6E 6F 74 20 66 6F 75 6E 64 00 5E AC AA 84 C0 75 FA 6A 00 57 52 6A 00 E8 06 00 00 00 45 72 72 6F 72 00 5E AC AA 84 C0 75 FA E8 0B 00 00 00 55 53 45 52 33 32 2E 44 4C 4C 00 FF 55 2C E8 0C 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 50 FF 55 28 FF D0 83 C4 7C 48 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1730_XCR {
	meta:
		tool = "P"
		name = "XCR"
		version = "0.12"
		pattern = "609CE8????????8BDD5D81ED????????899D"
	strings:
		$1 = { 60 9C E8 ?? ?? ?? ?? 8B DD 5D 81 ED ?? ?? ?? ?? 89 9D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1731_XCR {
	meta:
		tool = "P"
		name = "XCR"
		version = "0.13"
		pattern = "937108????????????????8BD878E2????????9C33C3????????6079CE????????E801????????83C404E8ABFFFFFF????????2BE8????????03C5FF30????????C6??EB"
	strings:
		$1 = { 93 71 08 ?? ?? ?? ?? ?? ?? ?? ?? 8B D8 78 E2 ?? ?? ?? ?? 9C 33 C3 ?? ?? ?? ?? 60 79 CE ?? ?? ?? ?? E8 01 ?? ?? ?? ?? 83 C4 04 E8 AB FF FF FF ?? ?? ?? ?? 2B E8 ?? ?? ?? ?? 03 C5 FF 30 ?? ?? ?? ?? C6 ?? EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1732_Xenocode {
	meta:
		tool = "P"
		name = "Xenocode"
		version = "8.1.1353"
		source = "Generated based on AVG tests"
		pattern = "558BEC83E4F881EC1C090000535657E887FBFFFF8B350C?0????FFD683E0113D110100000F8426040000FFD68B5C2428A30C50????E853FCFFFF8BC82B0D0C50????6A0333D28BC15EF7F6F7C10080FFFF0F858602000033C033FF89BC24240900006689"
	strings:
		$1 = { 55 8B EC 83 E4 F8 81 EC 1C 09 00 00 53 56 57 E8 87 FB FF FF 8B 35 0C ?0 ?? ?? FF D6 83 E0 11 3D 11 01 00 00 0F 84 26 04 00 00 FF D6 8B 5C 24 28 A3 0C 50 ?? ?? E8 53 FC FF FF 8B C8 2B 0D 0C 50 ?? ?? 6A 03 33 D2 8B C1 5E F7 F6 F7 C1 00 80 FF FF 0F 85 86 02 00 00 33 C0 33 FF 89 BC 24 24 09 00 00 66 89 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1733_XJ___XPAL {
	meta:
		tool = "P"
		name = "XJ / XPAL"
		pattern = "558BEC6AFF68????400068????400064A100000000506489250000000083EC44535657669C"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 44 53 56 57 66 9C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1734_xPEP {
	meta:
		tool = "P"
		name = "xPEP"
		version = "0.3x"
		pattern = "555356515257E816000000"
	strings:
		$1 = { 55 53 56 51 52 57 E8 16 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1735_Xtreme_Protector {
	meta:
		tool = "P"
		name = "Xtreme-Protector"
		version = "1.05"
		pattern = "E9????0000000000000000"
	strings:
		$1 = { E9 ?? ?? 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1736_Xtreme_Protector {
	meta:
		tool = "P"
		name = "Xtreme-Protector"
		version = "1.06"
		pattern = "B8??????00B975????005051E805000000E94A010000608B7424248B7C2428FCB2808A0646880747BB0200000002D275058A164612D273EA02D275058A164612D2734F33C002D275058A164612D20F83DF00000002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C002D275058A164612D213C07406572BF88A075F880747BB02000000EB9BB80100000002D275058A164612D213C002D275058A"
	strings:
		$1 = { B8 ?? ?? ?? 00 B9 75 ?? ?? 00 50 51 E8 05 00 00 00 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A 16 46 12 D2 13 C0 74 06 57 2B F8 8A 07 5F 88 07 47 BB 02 00 00 00 EB 9B B8 01 00 00 00 02 D2 75 05 8A 16 46 12 D2 13 C0 02 D2 75 05 8A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
