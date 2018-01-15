/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_40.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_40 =
R"x86_pe_packer(
rule rule_1103_PESpin {
	meta:
		tool = "P"
		name = "PESpin"
		version = "1.100"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C247DDE46000BE4749E7501??817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800??????????5D33C941E217EB07??????????????E801000000??5A83EA0BFFE2EB04??EB0400EBFB????????????????????????????????????EB02????F97208730EF983042417C3E8040000000FF57311EB06????????????F5720EF572F868EBEC83042407F5FF3424C341C1E1078B0C0103CAE803000000EB04??EBFB"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 ?? 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 ?? ?? ?? ?? ?? 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 ?? ?? ?? ?? ?? ?? F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 41 C1 E1 07 8B 0C 01 03 CA E8 03 00 00 00 EB 04 ?? EB FB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1104_PESPin {
	meta:
		tool = "P"
		name = "PESPin"
		version = "1.300"
		pattern = "EB016860E8000000008B1C2483C312812BE8B10600FE4BFD822C24ACDF46000BE4749E7501C7817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800A3687201FF5D33C941E217EB07EAEB01EBEB0DFFE801000000EA5A83EA0BFFE2EB049AEB0400EBFBFF8B950D4F40008B423C03C28985174F4000EB021277F97208730EF983042417C3E8040000000FF57311EB069A72ED1FEB07F5720EF572F868EBEC830424"
	strings:
		$1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A EB 04 00 EB FB FF 8B 95 0D 4F 40 00 8B 42 3C 03 C2 89 85 17 4F 40 00 EB 02 12 77 F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1105_PESpin {
	meta:
		tool = "P"
		name = "PESpin"
		version = "1.300b"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C2471DF46000BE4749E7501C7817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800A3687201FF5D33C941E217EB07??????????????E801000000??5A83EA0BFFE2EB04??EB04??EBFB??????????????8B423C03C2????????????EB02????F97208730EF983042417C3E8040000000FF57311EB069A72ED1FEB07F5720EF572F868EBEC83042407F5FF3424C3"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB ?? ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 0F F5 73 11 EB 06 9A 72 ED 1F EB 07 F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1106_PESpin {
	meta:
		tool = "P"
		name = "PESpin"
		version = "1.304"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C2488DF46000BE4749E7501C7817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800A3687201FF5D33C941E217EB07??EB01??EB0D??E801000000??5A83EA0BFFE2EB04??EB04??EBFB??????????????8B423C03C2????????????EB02????F97208730EF983042417C3E804000000????????EB06????????????F5720EF572F868EBEC83042407F5FF3424C3"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? EB 01 ?? EB 0D ?? E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 ?? EB FB ?? ?? ?? ?? ?? ?? ?? 8B 42 3C 03 C2 ?? ?? ?? ?? ?? ?? EB 02 ?? ?? F9 72 08 73 0E F9 83 04 24 17 C3 E8 04 00 00 00 ?? ?? ?? ?? EB 06 ?? ?? ?? ?? ?? ?? F5 72 0E F5 72 F8 68 EB EC 83 04 24 07 F5 FF 34 24 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1107_PESpin {
	meta:
		tool = "P"
		name = "PESpin"
		version = "1.320"
		pattern = "EB01??60E8000000008B1C2483C312812BE8B10600FE4BFD822C2417E646000BE4749E7501C7817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800A3687201FF5D33C941E217EB07??EB01??EB0DFFE801000000??5A83EA0BFFE2EB04??EB0400EBFBFFE802000000????5A81??????????83EAFE8995A95740002BC02BC983F1060985CB5740009CD32C2480C1FB210C245052B836C709FF05FE37F600F76424088D8428B1354000894424085A588D642404FF6424FCCD20BB6974580BC1C3"
	strings:
		$1 = { EB 01 ?? 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 17 E6 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 ?? EB 01 ?? EB 0D FF E8 01 00 00 00 ?? 5A 83 EA 0B FF E2 EB 04 ?? EB 04 00 EB FB FF E8 02 00 00 00 ?? ?? 5A 81 ?? ?? ?? ?? ?? 83 EA FE 89 95 A9 57 40 00 2B C0 2B C9 83 F1 06 09 85 CB 57 40 00 9C D3 2C 24 80 C1 FB 21 0C 24 50 52 B8 36 C7 09 FF 05 FE 37 F6 00 F7 64 24 08 8D 84 28 B1 35 40 00 89 44 24 08 5A 58 8D 64 24 04 FF 64 24 FC CD 20 BB 69 74 58 0B C1 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1108_PESpin {
	meta:
		tool = "P"
		name = "PESpin"
		version = "1.330"
		pattern = "EB016860E8000000008B1C2483C312812BE8B10600FE4BFD822C2477E746000BE4749E7501C7817304D77AF72F817319770043B7F6C36BB70000F9FFE3C9C20800A3687201FF5D33C941E217EB07EAEB01EBEB0DFFE801000000EA5A83EA0BFFE2EB049A"
	strings:
		$1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 77 E7 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 EB 04 9A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1109_PEStubOEP {
	meta:
		tool = "P"
		name = "PEStubOEP"
		version = "1.x"
		pattern = "4048BE00????0040486033C0B8??????00FFE0C3C3"
	strings:
		$1 = { 40 48 BE 00 ?? ?? 00 40 48 60 33 C0 B8 ?? ?? ?? 00 FF E0 C3 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1110_PeStubOEP {
	meta:
		tool = "P"
		name = "PeStubOEP"
		version = "1.x"
		pattern = "9033C933D2B8??????00B9FF"
	strings:
		$1 = { 90 33 C9 33 D2 B8 ?? ?? ?? 00 B9 FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1111_PeStubOEP {
	meta:
		tool = "P"
		name = "PeStubOEP"
		version = "1.x"
		pattern = "E80500000033C04048C3E805"
	strings:
		$1 = { E8 05 00 00 00 33 C0 40 48 C3 E8 05 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1112_Petite {
	meta:
		tool = "P"
		name = "Petite"
		pattern = "B8????????669C6050"
	strings:
		$1 = { B8 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1113_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.2"
		pattern = "9C60E8CA??????03??04??05??06??07??08"
	strings:
		$1 = { 9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1114_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.3"
		pattern = "????????????9C60508D8800??????8D90????00008BDC8BE1680000????53508004240850800424425080042461508004249D50800424BB833A000F84DA1400008B442418F64203807419FD807203808BF08BF8037204037A088B0AF3A583C20CFCEBD48B7A0803F88B5A0485DB7413525357030250E87B00000085C0742E5F5F585A8B4A0CC1F902F3AB8B4A0C83E103F3AA83C210EBA04552524F522100436F727275707420"
	strings:
		$1 = { ?? ?? ?? ?? ?? ?? 9C 60 50 8D 88 00 ?? ?? ?? 8D 90 ?? ?? 00 00 8B DC 8B E1 68 00 00 ?? ?? 53 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 DA 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03 72 04 03 7A 08 8B 0A F3 A5 83 C2 0C FC EB D4 8B 7A 08 03 F8 8B 5A 04 85 DB 74 13 52 53 57 03 02 50 E8 7B 00 00 00 85 C0 74 2E 5F 5F 58 5A 8B 4A 0C C1 F9 02 F3 AB 8B 4A 0C 83 E1 03 F3 AA 83 C2 10 EB A0 45 52 52 4F 52 21 00 43 6F 72 72 75 70 74 20 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1115_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.3"
		pattern = "??????????669C60508D88??F?????8D900416????8BDC8BE168????????5350800424085080042442"
	strings:
		$1 = { ?? ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? F? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1116_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.3a"
		pattern = "??????????669C60508D88????????8D90F815????8BDC8BE168????????5350800424085080042442"
	strings:
		$1 = { ?? ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 F8 15 ?? ?? 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1117_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.4"
		pattern = "??????????669C60508BD803006854BC00006A00FF50148BCC8DA054BC0000508BC38D90??160000680000????51508004240850800424425080042461508004249D50800424BB833A000F84D81400008B442418F64203807419FD807203808BF08BF8037204037A088B0AF3A583C20CFCEBD48B7A0803F88B5A0485DB7413525357030250E87900000085C074305F5F585A8B4A0CC1F90233C0F3AB8B4A0C83E103F3AA83C210"
	strings:
		$1 = { ?? ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC 8D A0 54 BC 00 00 50 8B C3 8D 90 ?? 16 00 00 68 00 00 ?? ?? 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 D8 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03 72 04 03 7A 08 8B 0A F3 A5 83 C2 0C FC EB D4 8B 7A 08 03 F8 8B 5A 04 85 DB 74 13 52 53 57 03 02 50 E8 79 00 00 00 85 C0 74 30 5F 5F 58 5A 8B 4A 0C C1 F9 02 33 C0 F3 AB 8B 4A 0C 83 E1 03 F3 AA 83 C2 10 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1118_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.4"
		pattern = "669C60508BD803??6854BC????6A??FF50148BCC"
	strings:
		$1 = { 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 14 8B CC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1119_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.4"
		pattern = "B8????????669C60508BD8030068????????6A00"
	strings:
		$1 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1120_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "1.4+"
		pattern = "B8????????669C60508D??????????68????????83"
	strings:
		$1 = { B8 ?? ?? ?? ?? 66 9C 60 50 8D ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 83 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1121_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.0"
		pattern = "B8????????669C60508BD803??6854BC????6A??FF50188BCC8DA054BC????8BC38D90E015????68"
	strings:
		$1 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 ?? 68 54 BC ?? ?? 6A ?? FF 50 18 8B CC 8D A0 54 BC ?? ?? 8B C3 8D 90 E0 15 ?? ?? 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1122_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.1"
		pattern = "B8????????68????????64????????????64????????????669C6050"
	strings:
		$1 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 64 ?? ?? ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1123_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.1"
		pattern = "B8????????6A??68????????64FF35????????648925????????669C6050"
	strings:
		$1 = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1124_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.2"
		pattern = "B8??????????68????????64FF350000000064892500000000669C6050680000????8B3C248B306681C780078D74060889388B5E1050566A026880080000576A??6A06566A04688008000057FFD383EE0859F3A5596683C76881C6????0000F3A5FFD3588D90B80100008B0A0FBAF11F73168B0424FD8BF08BF8037204037A08F3A583C20CFCEBE283C2108B5AF485DB74D88B04248B7AF803F8528D3401EB175858585A74C4E91C"
	strings:
		$1 = { B8 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 68 00 00 ?? ?? 8B 3C 24 8B 30 66 81 C7 80 07 8D 74 06 08 89 38 8B 5E 10 50 56 6A 02 68 80 08 00 00 57 6A ?? 6A 06 56 6A 04 68 80 08 00 00 57 FF D3 83 EE 08 59 F3 A5 59 66 83 C7 68 81 C6 ?? ?? 00 00 F3 A5 FF D3 58 8D 90 B8 01 00 00 8B 0A 0F BA F1 1F 73 16 8B 04 24 FD 8B F0 8B F8 03 72 04 03 7A 08 F3 A5 83 C2 0C FC EB E2 83 C2 10 8B 5A F4 85 DB 74 D8 8B 04 24 8B 7A F8 03 F8 52 8D 34 01 EB 17 58 58 58 5A 74 C4 E9 1C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1125_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.2"
		pattern = "B8????????68????????64FF35????????648925????????669C6050"
	strings:
		$1 = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1126_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.2"
		pattern = "B800?04?006?00????0???????????0000"
	strings:
		$1 = { B8 00 ?0 4? 00 6? 00 ?? ?? 0? ?? ?? ?? ?? ?? 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1127_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.2+"
		pattern = "B8????????6A??68????????64FF350000000064892500000000669C60508BD8030068????????6A00FF50"
	strings:
		$1 = { B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00 FF 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1128_Petite {
	meta:
		tool = "P"
		name = "Petite"
		version = "2.3"
		source = "Generated based on AVG tests"
		pattern = "B800?0??0068????4?0064FF350000000064892500000000669C60508BD8030068????0?006A00FF501C89430868000040008B3C248B336681C780078D741E08893B538B5E10B880080000566A0250576A??6A0A566A045057FFD383EE0859F3A5596683"
	strings:
		$1 = { B8 00 ?0 ?? 00 68 ?? ?? 4? 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68 ?? ?? 0? 00 6A 00 FF 50 1C 89 43 08 68 00 00 40 00 8B 3C 24 8B 33 66 81 C7 80 07 8D 74 1E 08 89 3B 53 8B 5E 10 B8 80 08 00 00 56 6A 02 50 57 6A ?? 6A 0A 56 6A 04 50 57 FF D3 83 EE 08 59 F3 A5 59 66 83 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1129_PeX {
	meta:
		tool = "P"
		name = "PeX"
		version = "0.99"
		pattern = "60E801????????83C404E801????????5D81"
	strings:
		$1 = { 60 E8 01 ?? ?? ?? ?? 83 C4 04 E8 01 ?? ?? ?? ?? 5D 81 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1130_PeX {
	meta:
		tool = "P"
		name = "PeX"
		version = "0.99"
		pattern = "E9F50000000D0AC4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C40D0A205065582028632920627920626172745E437261636B506C20626574612072656C65617365202020202020202020202020202020202020202020202020202020202020202020202020202020202020"
	strings:
		$1 = { E9 F5 00 00 00 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 20 50 65 58 20 28 63 29 20 62 79 20 62 61 72 74 5E 43 72 61 63 6B 50 6C 20 62 65 74 61 20 72 65 6C 65 61 73 65 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
