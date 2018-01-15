/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_49.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_49 =
R"x86_pe_packer(
rule rule_1324_SLVc0deProtector {
	meta:
		tool = "P"
		name = "SLVc0deProtector"
		version = "0.60"
		pattern = "EB02FA04E84900000069E84900000095E84F00000068E81F00000049E8E9FFFFFF67E81F00000093E83100000078E8DD"
	strings:
		$1 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1325_SLVc0deProtector {
	meta:
		tool = "P"
		name = "SLVc0deProtector"
		version = "0.61"
		pattern = "????????????????????????????????????????????????????????????????????????????????????????????????EB02FA04E84900000069E84900000095E84F00000068E81F00000049E8E9FFFFFF67E81F00"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1326_SLVc0deProtector {
	meta:
		tool = "P"
		name = "SLVc0deProtector"
		version = "1.1"
		pattern = "E80000000058C600EBC6400108FFE0E94C"
	strings:
		$1 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1327_SLVc0deProtector {
	meta:
		tool = "P"
		name = "SLVc0deProtector"
		version = "1.1"
		pattern = "E801000000A05DEB016981ED5F1A40008D85921A4000F38D95831A40008BC08BD22BC283E805894201E8FBFFFFFF6983C408E80600000069E8F2FFFFFFF3B905000000518DB5BF1A40008BFEB958150000AC32C1F6D0EB0100D0C0FEC802C1AAE2EF59E2DEB7FEABE124C80C887AE1B16AF795831BA87FF8A8B01A8B0891476C5A886C653985DBCB543DB924CF4CAEC663742C63F0C8180B976B7963A8ABB878A9302F2BDA18AC"
	strings:
		$1 = { E8 01 00 00 00 A0 5D EB 01 69 81 ED 5F 1A 40 00 8D 85 92 1A 40 00 F3 8D 95 83 1A 40 00 8B C0 8B D2 2B C2 83 E8 05 89 42 01 E8 FB FF FF FF 69 83 C4 08 E8 06 00 00 00 69 E8 F2 FF FF FF F3 B9 05 00 00 00 51 8D B5 BF 1A 40 00 8B FE B9 58 15 00 00 AC 32 C1 F6 D0 EB 01 00 D0 C0 FE C8 02 C1 AA E2 EF 59 E2 DE B7 FE AB E1 24 C8 0C 88 7A E1 B1 6A F7 95 83 1B A8 7F F8 A8 B0 1A 8B 08 91 47 6C 5A 88 6C 65 39 85 DB CB 54 3D B9 24 CF 4C AE C6 63 74 2C 63 F0 C8 18 0B 97 6B 79 63 A8 AB B8 78 A9 30 2F 2B DA 18 AC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1328_SmartE {
	meta:
		tool = "P"
		name = "SmartE"
		pattern = "EB1503000000??0000000000000000000000680000000055E8000000005D81ED1D0000008BC555609C2B858F070000898583070000FF74242CE8BB0100000F822F060000E88E040000490F882306"
	strings:
		$1 = { EB 15 03 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 8F 07 00 00 89 85 83 07 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 2F 06 00 00 E8 8E 04 00 00 49 0F 88 23 06 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1329_SmartLoader {
	meta:
		tool = "P"
		name = "SmartLoader"
		pattern = "555657E8000000005D81EDE25F0010EB05E9670100008B85E561001085C0740A8B4424108985D96100108B85D961001003403C05800000008B08038DD9610010"
	strings:
		$1 = { 55 56 57 E8 00 00 00 00 5D 81 ED E2 5F 00 10 EB 05 E9 67 01 00 00 8B 85 E5 61 00 10 85 C0 74 0A 8B 44 24 10 89 85 D9 61 00 10 8B 85 D9 61 00 10 03 40 3C 05 80 00 00 00 8B 08 03 8D D9 61 00 10 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1330_SmokesCrypt {
	meta:
		tool = "P"
		name = "SmokesCrypt"
		version = "1.2"
		pattern = "60B8????????B8????????8A140880F2??8814084183F9??75F1"
	strings:
		$1 = { 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1331_Soft_Defender {
	meta:
		tool = "P"
		name = "Soft Defender"
		version = "1.0 - 1.1"
		pattern = "74077505193267E8E8741F751DE8683944CD??599C50740A7508E859C204??558BECE8F4FFFFFF565753780F790DE8349947493433EF313452472368A2AF470159E8????????5805BA01????03C874BE75BCE8"
	strings:
		$1 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD ?? 59 9C 50 74 0A 75 08 E8 59 C2 04 ?? 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 ?? ?? ?? ?? 58 05 BA 01 ?? ?? 03 C8 74 BE 75 BC E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1332_Soft_Defender {
	meta:
		tool = "P"
		name = "Soft Defender"
		version = "1.12"
		pattern = "74077505193267E8E8741F751DE8683944CD00599C50740A7508E859C20400558BECE8F4FFFFFF565753780F790DE8349947493433EF313452472368A2AF470159E801000000FF5805BE01000003C874BD75BBE8"
	strings:
		$1 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 BE 01 00 00 03 C8 74 BD 75 BB E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1333_Soft_Defender {
	meta:
		tool = "P"
		name = "Soft Defender"
		version = "1.1x"
		pattern = "74077505??????????741F751D??68??????00599C50740A7508??59C20400??????E8F4FFFFFF??????780F790D"
	strings:
		$1 = { 74 07 75 05 ?? ?? ?? ?? ?? 74 1F 75 1D ?? 68 ?? ?? ?? 00 59 9C 50 74 0A 75 08 ?? 59 C2 04 00 ?? ?? ?? E8 F4 FF FF FF ?? ?? ?? 78 0F 79 0D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1334_Soft_Defender {
	meta:
		tool = "P"
		name = "Soft Defender"
		version = "1.x"
		pattern = "74077505193267E8E8741F751DE8683944CD00599C50740A7508E859C20400558BECE8F4FFFFFF565753780F790DE8349947493433EF313452472368A2AF470159E801000000FF5805E601000003C874BD75BBE800"
	strings:
		$1 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 E6 01 00 00 03 C8 74 BD 75 BB E8 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1335_SoftComp {
	meta:
		tool = "P"
		name = "SoftComp"
		version = "1.x"
		pattern = "E800000000812C243A1041005DE800000000812C24310100008B852A0F41002904248B042489852A0F4100588B852A0F4100"
	strings:
		$1 = { E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 8B 04 24 89 85 2A 0F 41 00 58 8B 85 2A 0F 41 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1336_SoftProtect {
	meta:
		tool = "P"
		name = "SoftProtect"
		pattern = "E8????????8D??????????C70000000000E8????????E8????????8D??????????50E8????????83??????????01"
	strings:
		$1 = { E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? C7 00 00 00 00 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1337_SoftProtect {
	meta:
		tool = "P"
		name = "SoftProtect"
		pattern = "EB01E360E803??????D2EB0B58EB014840EB0135FFE0E76160E803??????83EB0EEB010C58EB013540EB0136FFE00B61EB01839CEB01D5EB08359DEB0189EB030BEBF7E8????????58E8????????5983010180395C75F233C4740C23C40BC4C60159C60159EBE290E84414????8D85CF13????C7??????????E8610E????E82E14????8D85E401????50E8E215????83BD2301????017507E8210D????EB098D85CF13????8308"
	strings:
		$1 = { EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 60 E8 03 ?? ?? ?? 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 EB 01 83 9C EB 01 D5 EB 08 35 9D EB 01 89 EB 03 0B EB F7 E8 ?? ?? ?? ?? 58 E8 ?? ?? ?? ?? 59 83 01 01 80 39 5C 75 F2 33 C4 74 0C 23 C4 0B C4 C6 01 59 C6 01 59 EB E2 90 E8 44 14 ?? ?? 8D 85 CF 13 ?? ?? C7 ?? ?? ?? ?? ?? E8 61 0E ?? ?? E8 2E 14 ?? ?? 8D 85 E4 01 ?? ?? 50 E8 E2 15 ?? ?? 83 BD 23 01 ?? ?? 01 75 07 E8 21 0D ?? ?? EB 09 8D 85 CF 13 ?? ?? 83 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1338_SoftSentry {
	meta:
		tool = "P"
		name = "SoftSentry"
		version = "2.11"
		pattern = "558BEC83EC??535657E950"
	strings:
		$1 = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1339_SoftSentry {
	meta:
		tool = "P"
		name = "SoftSentry"
		version = "3.00"
		pattern = "558BEC83EC??535657E9B006"
	strings:
		$1 = { 55 8B EC 83 EC ?? 53 56 57 E9 B0 06 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1340_Software_Compress {
	meta:
		tool = "P"
		name = "Software Compress"
		version = "1.2"
		pattern = "E9BE000000608B7424248B7C2428FCB28033DBA4B302E86D0000"
	strings:
		$1 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1341_Software_Compress {
	meta:
		tool = "P"
		name = "Software Compress"
		version = "1.4 LITE"
		pattern = "E800000000812C24AA1A41005DE800000000832C246E8B855D1A41002904248B042489855D1A4100588B855D1A41008B503C03D08B928000000003D08B4A58898D491A41008B4A5C898D4D1A41008B4A60898D551A"
	strings:
		$1 = { E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00 29 04 24 8B 04 24 89 85 5D 1A 41 00 58 8B 85 5D 1A 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 03 D0 8B 4A 58 89 8D 49 1A 41 00 8B 4A 5C 89 8D 4D 1A 41 00 8B 4A 60 89 8D 55 1A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1342_SoftWrap {
	meta:
		tool = "P"
		name = "SoftWrap"
		pattern = "525351565755E8????????5D81ED36??????E8??01????60BA????????E8????????5F"
	strings:
		$1 = { 52 53 51 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED 36 ?? ?? ?? E8 ?? 01 ?? ?? 60 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1344_Solidshield_Protector {
	meta:
		tool = "P"
		name = "Solidshield Protector"
		version = "1.x DLL"
		pattern = "8B44240848750AFF742404E8????????5933C040C20C00558BEC568B750885F6752868????????BE????????56FF15????????59596A??68????????566A??FF??????????E98000000083FE0175075E5DE9D2F6FFFF83FE02578B7D107553FF7524FF7520FF751CFF751868????????68????????FF15????????BE????????5657E8????????83C4203C0175048BC6EB6A57FF750CE8????????57E8????????5657E8????????83C4143C0174DF6A035E83FE03751B57E8????????C70424????????E8????????596A00FF15????????83FE04750DFF752CFF7528E8????????595983FE057511FF7530FF752CFF7528E8????????83C40C33C05F5E5DC3"
	strings:
		$1 = { 8B 44 24 08 48 75 0A FF 74 24 04 E8 ?? ?? ?? ?? 59 33 C0 40 C2 0C 00 55 8B EC 56 8B 75 08 85 F6 75 28 68 ?? ?? ?? ?? BE ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 59 59 6A ?? 68 ?? ?? ?? ?? 56 6A ?? FF ?? ?? ?? ?? ?? E9 80 00 00 00 83 FE 01 75 07 5E 5D E9 D2 F6 FF FF 83 FE 02 57 8B 7D 10 75 53 FF 75 24 FF 75 20 FF 75 1C FF 75 18 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? BE ?? ?? ?? ?? 56 57 E8 ?? ?? ?? ?? 83 C4 20 3C 01 75 04 8B C6 EB 6A 57 FF 75 0C E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 56 57 E8 ?? ?? ?? ?? 83 C4 14 3C 01 74 DF 6A 03 5E 83 FE 03 75 1B 57 E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 6A 00 FF 15 ?? ?? ?? ?? 83 FE 04 75 0D FF 75 2C FF 75 28 E8 ?? ?? ?? ?? 59 59 83 FE 05 75 11 FF 75 30 FF 75 2C FF 75 28 E8 ?? ?? ?? ?? 83 C4 0C 33 C0 5F 5E 5D C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1345_Solidshield_Protector {
	meta:
		tool = "P"
		name = "Solidshield Protector"
		version = "1.x"
		pattern = "68????????FF35????????C3006089000A00000046330000000000000000"
	strings:
		$1 = { 68 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? C3 00 60 89 00 0A 00 00 00 46 33 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1346_SPEC {
	meta:
		tool = "P"
		name = "SPEC"
		version = "b2"
		pattern = "55575153E8????????5D8BC581ED????????2B85????????83E8098985????????0FB6"
	strings:
		$1 = { 55 57 51 53 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 83 E8 09 89 85 ?? ?? ?? ?? 0F B6 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1347_SPEC {
	meta:
		tool = "P"
		name = "SPEC"
		version = "b3"
		pattern = "5B535045435DE8????????5D8BC581ED412440??2B85892640??83E80B89858D2640??0FB6B5912640??8BFD"
	strings:
		$1 = { 5B 53 50 45 43 5D E8 ?? ?? ?? ?? 5D 8B C5 81 ED 41 24 40 ?? 2B 85 89 26 40 ?? 83 E8 0B 89 85 8D 26 40 ?? 0F B6 B5 91 26 40 ?? 8B FD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1348_Special_EXE_Pasword_Protector {
	meta:
		tool = "P"
		name = "Special EXE Pasword Protector"
		version = "1.01"
		pattern = "60E8000000005D81ED0600000089AD8C0100008BC52B85FE75000089853E"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1349_Splash_Bitmap {
	meta:
		tool = "P"
		name = "Splash Bitmap"
		version = "1.00"
		extra = "with unpack code"
		pattern = "E800000000608B6C24205581ED????????8DBD????????8D8D????????29F931C0FCF3AA8B042448662500F06681384D5A75F48B483C813C015045000075E88985????????6A40"
	strings:
		$1 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 6A 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1350_Splash_Bitmap {
	meta:
		tool = "P"
		name = "Splash Bitmap"
		version = "1.00"
		pattern = "E800000000608B6C24205581ED????????8DBD????????8D8D????????29F931C0FCF3AA8B042448662500F06681384D5A75F48B483C813C015045000075E88985????????8DBD????????6A00"
	strings:
		$1 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? 6A 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1351_Splasher {
	meta:
		tool = "P"
		name = "Splasher"
		version = "1.0 - 3.0"
		pattern = "9C608B442424E8????????5D81ED????????50E8ED02????8CC00F84"
	strings:
		$1 = { 9C 60 8B 44 24 24 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 50 E8 ED 02 ?? ?? 8C C0 0F 84 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1352_SPLayer {
	meta:
		tool = "P"
		name = "SPLayer"
		version = "0.08"
		pattern = "8D4000B9????????6A??58C00C????48????6613F0913BD9????????????????00000000"
	strings:
		$1 = { 8D 40 00 B9 ?? ?? ?? ?? 6A ?? 58 C0 0C ?? ?? 48 ?? ?? 66 13 F0 91 3B D9 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
