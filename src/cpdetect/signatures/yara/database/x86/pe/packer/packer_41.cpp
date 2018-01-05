/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_41.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_41 =
R"x86_pe_packer(
rule rule_1134_Pi_Cryptor {
	meta:
		tool = "P"
		name = "Pi Cryptor"
		version = "1.0"
		pattern = "558BEC83C4EC53565731C08945ECB8401E0600E848FAFFFF33C05568361F060064FF306489206A0068800000006A036A006A0168000000808D55EC31C0E84EF4FFFF8B45ECE8F6F7FFFF50E8CCFAFFFF8BD883FBFF744E6A0053E8CDFAFFFF8BF881EFAC2600006A006A0068AC26000053E8DEFAFFFF89F8E8E3F1FFFF89C66A006828310600575653E8AEFAFFFF53E880FAFFFF89FA81EA720100008BC6E855FEFFFF89C689F009C07405E8A8FBFFFF31C0"
	strings:
		$1 = { 55 8B EC 83 C4 EC 53 56 57 31 C0 89 45 EC B8 40 1E 06 00 E8 48 FA FF FF 33 C0 55 68 36 1F 06 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 31 C0 E8 4E F4 FF FF 8B 45 EC E8 F6 F7 FF FF 50 E8 CC FA FF FF 8B D8 83 FB FF 74 4E 6A 00 53 E8 CD FA FF FF 8B F8 81 EF AC 26 00 00 6A 00 6A 00 68 AC 26 00 00 53 E8 DE FA FF FF 89 F8 E8 E3 F1 FF FF 89 C6 6A 00 68 28 31 06 00 57 56 53 E8 AE FA FF FF 53 E8 80 FA FF FF 89 FA 81 EA 72 01 00 00 8B C6 E8 55 FE FF FF 89 C6 89 F0 09 C0 74 05 E8 A8 FB FF FF 31 C0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1135_Pi_Cryptor {
	meta:
		tool = "P"
		name = "Pi Cryptor"
		version = "1.0"
		pattern = "8955F8BB010000008A041F240F8B55FC8A143280E20F32C28A141F80E2F002D088141F468D45F48B55FCE8????????8B45F4E8????????3BF07E05BE0100000043FF4DF875C2????????5A595964891068????????8D45F4E8????????C3E9"
	strings:
		$1 = { 89 55 F8 BB 01 00 00 00 8A 04 1F 24 0F 8B 55 FC 8A 14 32 80 E2 0F 32 C2 8A 14 1F 80 E2 F0 02 D0 88 14 1F 46 8D 45 F4 8B 55 FC E8 ?? ?? ?? ?? 8B 45 F4 E8 ?? ?? ?? ?? 3B F0 7E 05 BE 01 00 00 00 43 FF 4D F8 75 C2 ?? ?? ?? ?? 5A 59 59 64 89 10 68 ?? ?? ?? ?? 8D 45 F4 E8 ?? ?? ?? ?? C3 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1136_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.00, 1.03"
		pattern = "B8????BA????8CDB03D83B"
	strings:
		$1 = { B8 ?? ?? BA ?? ?? 8C DB 03 D8 3B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1137_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.00c"
		pattern = "2E8C1E????8B1E????8CDA81C2????3BDA72??81EB????83EB??FA8ED3BC????FBFDBE????8BFE"
	strings:
		$1 = { 2E 8C 1E ?? ?? 8B 1E ?? ?? 8C DA 81 C2 ?? ?? 3B DA 72 ?? 81 EB ?? ?? 83 EB ?? FA 8E D3 BC ?? ?? FB FD BE ?? ?? 8B FE }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1138_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.00c"
		pattern = "BA????A1????2D????8CCB81C3????3BC377??05????3BC377??B409BA????CD21CD2090"
	strings:
		$1 = { BA ?? ?? A1 ?? ?? 2D ?? ?? 8C CB 81 C3 ?? ?? 3B C3 77 ?? 05 ?? ?? 3B C3 77 ?? B4 09 BA ?? ?? CD 21 CD 20 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1139_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.1"
		pattern = "504B4C495445333220436F707972696768742031"
	strings:
		$1 = { 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1140_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.1"
		pattern = "558BECA1????????85C07409B801??????5DC20C??8B450C5756538B5D10"
	strings:
		$1 = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D 10 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1141_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.1"
		pattern = "68????????68????????6800000000E8??????????????????????????504B4C495445333220436F707972696768742031"
	strings:
		$1 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 00 00 00 00 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1142_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.1"
		pattern = "68????????68????????B8????????2B44240C50"
	strings:
		$1 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 44 24 0C 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1143_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.12, 1.15, 1.20"
		pattern = "B8????BA????05????3B06????73??2D????FA8ED0FB2D????8EC050B9????33FF57BE????FCF3A5CBB409BA????CD21CD20"
	strings:
		$1 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 73 ?? 2D ?? ?? FA 8E D0 FB 2D ?? ?? 8E C0 50 B9 ?? ?? 33 FF 57 BE ?? ?? FC F3 A5 CB B4 09 BA ?? ?? CD 21 CD 20 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1144_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.12, 1.15, 1.20"
		pattern = "B8????BA????3BC473"
	strings:
		$1 = { B8 ?? ?? BA ?? ?? 3B C4 73 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1145_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.14, 1.15, 1.20"
		pattern = "B8????BA????05????3B??????72??B409BA????CD21CD20"
	strings:
		$1 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B ?? ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 CD 20 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1146_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.20"
		pattern = "B8????BA????05????3B06????72??B409BA????CD21B44CCD21"
	strings:
		$1 = { B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 09 BA ?? ?? CD 21 B4 4C CD 21 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1147_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.50 (device driver compression)"
		pattern = "B409BA1401CD21B8004CCD21F89C505351525657551E06BB"
	strings:
		$1 = { B4 09 BA 14 01 CD 21 B8 00 4C CD 21 F8 9C 50 53 51 52 56 57 55 1E 06 BB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1148_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.50 with CRC check"
		pattern = "1FB409BA????CD21B8????CD21"
	strings:
		$1 = { 1F B4 09 BA ?? ?? CD 21 B8 ?? ?? CD 21 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1149_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "1.50"
		pattern = "50B8????BA????05????3B06????72??B4??BA????CD21B8????CD21"
	strings:
		$1 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 ?? ?? 72 ?? B4 ?? BA ?? ?? CD 21 B8 ?? ?? CD 21 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1150_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "2.00b"
		pattern = "50B8????BA????05????3B06020072??B409BA????CD21B8014CCD21"
	strings:
		$1 = { 50 B8 ?? ?? BA ?? ?? 05 ?? ?? 3B 06 02 00 72 ?? B4 09 BA ?? ?? CD 21 B8 01 4C CD 21 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1151_PKLite {
	meta:
		tool = "P"
		name = "PKLite"
		version = "2.00c"
		pattern = "50B8????BA????3BC473??8BC42D????25????8BF8B9????BE????FC"
	strings:
		$1 = { 50 B8 ?? ?? BA ?? ?? 3B C4 73 ?? 8B C4 2D ?? ?? 25 ?? ?? 8B F8 B9 ?? ?? BE ?? ?? FC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1152_Pksmart {
	meta:
		tool = "P"
		name = "Pksmart"
		version = "1.0b"
		pattern = "BA????8CC88BC803C281??????51B9????511E8CD3"
	strings:
		$1 = { BA ?? ?? 8C C8 8B C8 03 C2 81 ?? ?? ?? 51 B9 ?? ?? 51 1E 8C D3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1153_PKTINY {
	meta:
		tool = "P"
		name = "PKTINY"
		version = "1.0 with TINYPROG v3.8"
		pattern = "2EC606??????2EC606??????2EC606??????E9????E8????83"
	strings:
		$1 = { 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? 2E C6 06 ?? ?? ?? E9 ?? ?? E8 ?? ?? 83 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1154_PKZIP_SFX {
	meta:
		tool = "P"
		name = "PKZIP-SFX"
		version = "1.1 1989-90"
		pattern = "FC2E8C0E????A1????8CCB81C3????3BC372??2D????2D????FABC????8ED0FB"
	strings:
		$1 = { FC 2E 8C 0E ?? ?? A1 ?? ?? 8C CB 81 C3 ?? ?? 3B C3 72 ?? 2D ?? ?? 2D ?? ?? FA BC ?? ?? 8E D0 FB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1155_PLINK86 {
	meta:
		tool = "P"
		name = "PLINK86"
		version = "1984, 1985"
		pattern = "FA8CC78CD68BCCBA????8EC226"
	strings:
		$1 = { FA 8C C7 8C D6 8B CC BA ?? ?? 8E C2 26 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1156_PluginToExe {
	meta:
		tool = "P"
		name = "PluginToExe"
		version = "1.00"
		pattern = "E80000000029C05D81EDD140400050FF95B8404000898509404000FF95B440400089851140400050FF95C04040008A0880F922750750FF95C440400089850D4040008B9D09404000606A006A015381C3??????00FFD3616A006844694550FFB50D4040006A0081C3??????00FFD383C410FF95B0404000"
	strings:
		$1 = { E8 00 00 00 00 29 C0 5D 81 ED D1 40 40 00 50 FF 95 B8 40 40 00 89 85 09 40 40 00 FF 95 B4 40 40 00 89 85 11 40 40 00 50 FF 95 C0 40 40 00 8A 08 80 F9 22 75 07 50 FF 95 C4 40 40 00 89 85 0D 40 40 00 8B 9D 09 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 0D 40 40 00 6A 00 81 C3 ?? ?? ?? 00 FF D3 83 C4 10 FF 95 B0 40 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1157_PluginToExe {
	meta:
		tool = "P"
		name = "PluginToExe"
		version = "1.01"
		pattern = "E80000000029C05D81EDC6414000508F857140400050FF95A541400089856D404000FF95A141400050FF95B541400080380074168A0880F922750750FF95B9414000898575404000EB6C6A018F85714040006A586A40FF95A941400089856940400089C768000800006A40FF95A941400089471CC70758000000C7472000080000C7471801000000C74734041088008D8DB9404000894F0C8D8DDB404000894F30FFB569404000FF9595414000FF771C8F85754040008B9D6D404000606A006A015381C3??????00FFD3616A006844694550FFB5754040006A0081C3????0000FFD383C41083BD71404000007410FF771CFF95AD41400057FF95AD4140006A00FF959D414000"
	strings:
		$1 = { E8 00 00 00 00 29 C0 5D 81 ED C6 41 40 00 50 8F 85 71 40 40 00 50 FF 95 A5 41 40 00 89 85 6D 40 40 00 FF 95 A1 41 40 00 50 FF 95 B5 41 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 B9 41 40 00 89 85 75 40 40 00 EB 6C 6A 01 8F 85 71 40 40 00 6A 58 6A 40 FF 95 A9 41 40 00 89 85 69 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 A9 41 40 00 89 47 1C C7 07 58 00 00 00 C7 47 20 00 08 00 00 C7 47 18 01 00 00 00 C7 47 34 04 10 88 00 8D 8D B9 40 40 00 89 4F 0C 8D 8D DB 40 40 00 89 4F 30 FF B5 69 40 40 00 FF 95 95 41 40 00 FF 77 1C 8F 85 75 40 40 00 8B 9D 6D 40 40 00 60 6A 00 6A 01 53 81 C3 ?? ?? ?? 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 75 40 40 00 6A 00 81 C3 ?? ?? 00 00 FF D3 83 C4 10 83 BD 71 40 40 00 00 74 10 FF 77 1C FF 95 AD 41 40 00 57 FF 95 AD 41 40 00 6A 00 FF 95 9D 41 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1158_PluginToExe {
	meta:
		tool = "P"
		name = "PluginToExe"
		version = "1.02"
		pattern = "E80000000029C05D81ED32424000508F85DD40400050FF95114240008985D9404000FF950D42400050FF952142400080380074168A0880F922750750FF95254240008985E1404000EB6C6A018F85DD4040006A586A40FF95154240008985D540400089C768000800006A40FF951542400089471CC7075800"
	strings:
		$1 = { E8 00 00 00 00 29 C0 5D 81 ED 32 42 40 00 50 8F 85 DD 40 40 00 50 FF 95 11 42 40 00 89 85 D9 40 40 00 FF 95 0D 42 40 00 50 FF 95 21 42 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 25 42 40 00 89 85 E1 40 40 00 EB 6C 6A 01 8F 85 DD 40 40 00 6A 58 6A 40 FF 95 15 42 40 00 89 85 D5 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 15 42 40 00 89 47 1C C7 07 58 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1159_PMODE_W {
	meta:
		tool = "P"
		name = "PMODE/W"
		version = ".1.12, 1.16, 1.21, 1.33 DOS extender"
		pattern = "FC1607BF????8BF757B9????F3A5061E071F5FBE????060EA4"
	strings:
		$1 = { FC 16 07 BF ?? ?? 8B F7 57 B9 ?? ?? F3 A5 06 1E 07 1F 5F BE ?? ?? 06 0E A4 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1160_Pohernah {
	meta:
		tool = "P"
		name = "Pohernah"
		version = "1.0.0"
		pattern = "5860E8000000005D81ED202540008BBD862540008B8D8E2540006BC00583F00489859225400083F900742D817F1CAB000000751E8B770C03B58A25400031C03B4710740E508B85922540003006584046EBED83C72849EBCE8B85822540008944241C61FFE0"
	strings:
		$1 = { 58 60 E8 00 00 00 00 5D 81 ED 20 25 40 00 8B BD 86 25 40 00 8B 8D 8E 25 40 00 6B C0 05 83 F0 04 89 85 92 25 40 00 83 F9 00 74 2D 81 7F 1C AB 00 00 00 75 1E 8B 77 0C 03 B5 8A 25 40 00 31 C0 3B 47 10 74 0E 50 8B 85 92 25 40 00 30 06 58 40 46 EB ED 83 C7 28 49 EB CE 8B 85 82 25 40 00 89 44 24 1C 61 FF E0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1161_Pohernah {
	meta:
		tool = "P"
		name = "Pohernah"
		version = "1.0.1 Crypter"
		pattern = "60E8000000005D81EDF12640008BBD182840008B8D20284000B83828400001E880300583F9007471817F1CAB00000075628B570C03951C28400031C05131C966B9FA006683F90074498B570C03951C2840008B852428400083F802750681C200020000518B4F1083F802750681E90002000057BFC800000089CEE82700000089C15FB83828400001E8E8240000005949EBB15983C72849EB8A8B85142840008944241C61FFE0"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED F1 26 40 00 8B BD 18 28 40 00 8B 8D 20 28 40 00 B8 38 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 1C 28 40 00 31 C0 51 31 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 1C 28 40 00 8B 85 24 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 38 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 14 28 40 00 89 44 24 1C 61 FF E0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1162_Pohernah {
	meta:
		tool = "P"
		name = "Pohernah"
		version = "1.0.2 Crypter"
		pattern = "60E8000000005D81EDDE2640008BBD052840008B8D0D284000B82528400001E880300583F9007471817F1CAB00000075628B570C03950928400031C05131C966B9F7006683F90074498B570C0395092840008B851128400083F802750681C200020000518B4F1083F802750681E90002000057BFC800000089CEE82700000089C15FB82528400001E8E8240000005949EBB15983C72849EB8A8B85012840008944241C61FFE0"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED DE 26 40 00 8B BD 05 28 40 00 8B 8D 0D 28 40 00 B8 25 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 09 28 40 00 31 C0 51 31 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 09 28 40 00 8B 85 11 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 25 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 01 28 40 00 89 44 24 1C 61 FF E0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1163_Pohernah {
	meta:
		tool = "P"
		name = "Pohernah"
		version = "1.0.3 Crypter"
		pattern = "60E8000000005D81ED2A27400031C04083F006403D401F00007507BE6A274000EB02EBEB8B859E28400083F801751731C001EE3D99000000740C8B8D86284000300E4046EBED"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 2A 27 40 00 31 C0 40 83 F0 06 40 3D 40 1F 00 00 75 07 BE 6A 27 40 00 EB 02 EB EB 8B 85 9E 28 40 00 83 F8 01 75 17 31 C0 01 EE 3D 99 00 00 00 74 0C 8B 8D 86 28 40 00 30 0E 40 46 EB ED }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
