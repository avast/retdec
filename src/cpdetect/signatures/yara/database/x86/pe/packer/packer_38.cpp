/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_38.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_38 =
R"x86_pe_packer(
rule rule_1043_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.24.2 - 1.24.3"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B85A67040??0185037040??66C785704090??9001859E7040BB??D209"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 09 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1044_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.25"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B85A67040??0185037040??66C785704090??9001859E7040BB??F30D"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? F3 0D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1045_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.26b1 - 1.26b2"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F7040??87DD8B85A67040??0185037040??66C785704090??9001859E7040BB??050E"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? 05 0E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1046_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.33"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F8040??87DD8B85A68040??0185038040??66C785008040??909001859E8040??BBE80E"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 00 80 40 ?? 90 90 01 85 9E 80 40 ?? BB E8 0E }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1047_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.34 - 1.40b1"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F8040??87DD8B85A68040??0185038040??66C785??0080??40909001859E80??40BBF810"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 00 80 ?? 40 90 90 01 85 9E 80 ?? 40 BB F8 10 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1048_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.40 - 1.45"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0FA040??87DD8B85A6A040??018503A040??66C785??A040??909001859EA040??BBC311"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB C3 11 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1049_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.40b2 - 1.40b4"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0FA040??87DD8B85A6A040??018503A040??66C785??A040??909001859EA040??BB8611"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 86 11 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1050_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.40b5 - 1.40b6"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0FA040??87DD8B85A6A040??018503A040??66C785??A040??909001859EA040??BB8A11"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 8A 11 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1051_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.46"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0FA040??87DD8B85A6A040??018503A040??66C785??A040??909001859EA040??BB6012"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 60 12 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1052_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.47 - 1.50"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0FA040??87DD8B85A6A040??018503A040??66C785??A040??909001859EA040??BB5B12"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 5B 12 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1053_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.55"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F8040??87DD8B85A28040??0185038040??66C785??8040??909001859E8040??BB2D12"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A2 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB 2D 12 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1054_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.56"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB0F9040??87DD8B85A29040??0185039040??66C785??9040??909001859E9040??BB2D12"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 90 40 ?? 87 DD 8B 85 A2 90 40 ?? 01 85 03 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 9E 90 40 ?? BB 2D 12 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1055_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.60 - 1.65"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB3F8040??87DD8B85D28040??0185338040??66C785??8040??90900185CE8040??BBBB12"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 ?? 87 DD 8B 85 D2 80 40 ?? 01 85 33 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 CE 80 40 ?? BB BB 12 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1056_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.66"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB3F9040??87DD8B85E69040??0185339040??66C785??9040??90900185DA9040??0185DE9040??0185E29040??BB5B11"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 5B 11 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1057_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.67"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB3F904087DD8B85E69040018533904066C785904090900185DA90400185DE90400185E29040BB8B11"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 8B 11 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1058_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.68 - 1.84"
		pattern = "EB0668????????C39C60E802??????33C08BC483C004938BE38B5BFC81EB3F904087DD8B85E69040018533904066C785904090900185DA90400185DE90400185E29040BB7B11"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 7B 11 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1059_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "1.xx"
		pattern = "EB0668????????C39C60E8????????33C08BC483C004938BE38B5BFC81EB????4000"
	strings:
		$1 = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1060_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.0b"
		pattern = "B8??????EE05121313125064FF350000000064892500"
	strings:
		$1 = { B8 ?? ?? ?? EE 05 12 13 13 12 50 64 FF 35 00 00 00 00 64 89 25 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1061_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.00a38"
		pattern = "B8????????80B8BF10001001747AC680BF100010019C5553515752568D980F1000108B53148BE86A406800100000FF73046A008B4B1003CA8B01FFD08BF8508B338B531403F28B4B0C03CA8D85B7100010FF73048F00505756FFD1580343088BF88B53148BF08B46FC83C0042BF08956088B4B10894E18FFD78985BB1000105E5A5F595B5D9DFFE08B80BB100010FFE00000000000000000000000000000000000000000000000"
	strings:
		$1 = { B8 ?? ?? ?? ?? 80 B8 BF 10 00 10 01 74 7A C6 80 BF 10 00 10 01 9C 55 53 51 57 52 56 8D 98 0F 10 00 10 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 8B F8 50 8B 33 8B 53 14 03 F2 8B 4B 0C 03 CA 8D 85 B7 10 00 10 FF 73 04 8F 00 50 57 56 FF D1 58 03 43 08 8B F8 8B 53 14 8B F0 8B 46 FC 83 C0 04 2B F0 89 56 08 8B 4B 10 89 4E 18 FF D7 89 85 BB 10 00 10 5E 5A 5F 59 5B 5D 9D FF E0 8B 80 BB 10 00 10 FF E0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1062_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.00b"
		pattern = "B8????????05????????5064FF350000000064892500000000CC90909090"
	strings:
		$1 = { B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1063_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.5 retail slim"
		pattern = "B8??????015064FF35000000006489250000000033C089085045433200"
	strings:
		$1 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1064_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.5 retail"
		pattern = "B8??????015064FF35000000006489250000000033C089085045436F6D706163743200"
	strings:
		$1 = { B8 ?? ?? ?? 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1065_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.53 slim DLL"
		pattern = "B8????????5064FF35000000006489250000000033C08908504543320000080C0048E101565753558B5C241C85DB0F84AB21E8BD0EE6600D0B6B65726E6C3332"
	strings:
		$1 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D 0B 6B 65 72 6E 6C 33 32 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1066_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.53 DLL"
		pattern = "B8????????5064FF35000000006489250000000033C089085045436F6D706163743200000000080C0048E101565753558B5C241C85DB0F84AB21E8BD0EE6600D"
	strings:
		$1 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 00 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1067_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.53 - 2.76"
		pattern = "B8????????5553515756528D98C91100108B5318528BE86A406800100000FF73046A008B4B1003CA8B01FFD05A8BF850528B338B432003C28B08894B208B431C03C28B08894B1C03F28B4B0C03CA8D431C505756FF"
	strings:
		$1 = { B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 C9 11 00 10 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 5A 8B F8 50 52 8B 33 8B 43 20 03 C2 8B 08 89 4B 20 8B 43 1C 03 C2 8B 08 89 4B 1C 03 F2 8B 4B 0C 03 CA 8D 43 1C 50 57 56 FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1068_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.xxb"
		pattern = "B8??????0080002840"
	strings:
		$1 = { B8 ?? ?? ?? 00 80 00 28 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1069_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.xx slim"
		pattern = "B8????????5064FF35000000006489250000000033C089085045433200"
	strings:
		$1 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1070_PECompact {
	meta:
		tool = "P"
		name = "PECompact"
		version = "2.xx"
		pattern = "B8????????5064FF35000000006489250000000033C089085045436F6D706163743200"
	strings:
		$1 = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1071_PECrc32 {
	meta:
		tool = "P"
		name = "PECrc32"
		version = "0.88"
		pattern = "60E8000000005D81EDB6A445008DBDB0A4450081EF82000000"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED B6 A4 45 00 8D BD B0 A4 45 00 81 EF 82 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1072_PEiD_Bundle {
	meta:
		tool = "P"
		name = "PEiD-Bundle"
		version = "1.00 - 1.01"
		pattern = "60E8??0200008B44240452486631C06681384D5A75F58B503C813C025045000075E95AC204006089DD89C38B453C8B54287801EA528B522001EA31C9418B348A"
	strings:
		$1 = { 60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1073_PEiD_Bundle {
	meta:
		tool = "P"
		name = "PEiD-Bundle"
		version = "1.00"
		pattern = "60E8210200008B44240452486631C06681384D5A75F58B503C813C025045000075E95AC204006089DD89C38B453C8B54287801EA528B522001EA31C9418B348A"
	strings:
		$1 = { 60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1074_PEiD_Bundle {
	meta:
		tool = "P"
		name = "PEiD-Bundle"
		version = "1.01"
		pattern = "60E8230200008B44240452486631C06681384D5A75F58B503C813C025045000075E95AC204006089DD89C38B453C8B54287801EA528B522001EA31C9418B348A"
	strings:
		$1 = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1075_PEiD_Bundle {
	meta:
		tool = "P"
		name = "PEiD-Bundle"
		version = "1.02 - 1.03 DLL"
		pattern = "837C2408010F85????????60E89C0000000000000000000000000000004100080039000800000000000000000000000000000000000000000001000080000000"
	strings:
		$1 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
