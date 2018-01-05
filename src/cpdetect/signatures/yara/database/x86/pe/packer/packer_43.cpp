/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_43.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_43 =
R"x86_pe_packer(
rule rule_1190_Protect_Shareware {
	meta:
		tool = "P"
		name = "Protect Shareware"
		version = "1.1"
		pattern = "53007400720069006E006700460069006C00650049006E0066006F000000??01000001003000340030003900300034004200300000003400??00010043006F006D00700061006E0079004E0061006D006500000000"
	strings:
		$1 = { 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 ?? 01 00 00 01 00 30 00 34 00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 34 00 ?? 00 01 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1191_PROTECT__EXE_COM {
	meta:
		tool = "P"
		name = "PROTECT! EXE/COM"
		version = "5.0"
		pattern = "1E0E0E1F07"
	strings:
		$1 = { 1E 0E 0E 1F 07 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1192_PROTECT__EXE_COM {
	meta:
		tool = "P"
		name = "PROTECT! EXE/COM"
		version = "6.0"
		pattern = "1EB430CD213C0273??CD20BE????E8"
	strings:
		$1 = { 1E B4 30 CD 21 3C 02 73 ?? CD 20 BE ?? ?? E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1193_Protection_Plus {
	meta:
		tool = "P"
		name = "Protection Plus"
		pattern = "506029C064FF30E8????????5D83ED3C89E889A514??????2B851C??????89851C??????8D852703????508B??85C00F85C0??????8DBD5B03????8DB54303"
	strings:
		$1 = { 50 60 29 C0 64 FF 30 E8 ?? ?? ?? ?? 5D 83 ED 3C 89 E8 89 A5 14 ?? ?? ?? 2B 85 1C ?? ?? ?? 89 85 1C ?? ?? ?? 8D 85 27 03 ?? ?? 50 8B ?? 85 C0 0F 85 C0 ?? ?? ?? 8D BD 5B 03 ?? ?? 8D B5 43 03 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1194_PROTEXT {
	meta:
		tool = "P"
		name = "PROTEXT"
		pattern = "E91D010000E87D00000005E5EBFFF7C0E9408D098D00C1E720C0E6200F88D2010000790468949EAC0F89C601000034B821C966C1E12066C1ED4088E47103E77D"
	strings:
		$1 = { E9 1D 01 00 00 E8 7D 00 00 00 05 E5 EB FF F7 C0 E9 40 8D 09 8D 00 C1 E7 20 C0 E6 20 0F 88 D2 01 00 00 79 04 68 94 9E AC 0F 89 C6 01 00 00 34 B8 21 C9 66 C1 E1 20 66 C1 ED 40 88 E4 71 03 E7 7D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1195_pscrambler {
	meta:
		tool = "P"
		name = "pscrambler"
		version = "1.2"
		pattern = "558BECB9040000006A006A004975F95153????????10E82DF3FFFF33C05568E831001064FF306489208D45E0E853F5FFFF8B45E08D55E4E830F6FFFF8B45E48D55E8E8A9F4FFFF8B45E88D55ECE8EEF7FFFF8B55ECB8C4540010E8D9ECFFFF833DC4540010000F8405010000803DA0400010007441A1C4540010E8D9EDFFFFE848E0FFFF8BD8A1C4540010E8C8EDFFFF50B8C4540010E865EFFFFF8BD359E869E1FFFF8BC3E812FAFFFF8BC3E833E0FFFFE9AD000000B805010000E80CE0FFFF8BD8536805010000E857F3FFFF8D45DC8BD3E839EDFFFF8B55DCB814560010B900320010E8BBEDFFFF8B1514560010B8C8540010E853E5FFFFBA01000000B8C8540010E88CE8FFFFE8DFE0FFFF85C075526A00A1C4540010E83BEDFFFF50B8C4540010E8D8EEFFFF8BD0B8C854001059E83BE6FFFFE876E0FFFFB8C8540010E84CE6FFFFE867E0FFFF6A006A006A00A114560010E853EEFFFF506A006A00E841F3FFFF803D9C400010007405E8EFFBFFFF33C05A595964891068EF3100108D45DCBA05000000E87DEBFFFFC3E923E9FFFFEBEB5BE863EAFFFF000000FFFFFFFF0800000074656D702E657865"
	strings:
		$1 = { 55 8B EC B9 04 00 00 00 6A 00 6A 00 49 75 F9 51 53 ?? ?? ?? ?? 10 E8 2D F3 FF FF 33 C0 55 68 E8 31 00 10 64 FF 30 64 89 20 8D 45 E0 E8 53 F5 FF FF 8B 45 E0 8D 55 E4 E8 30 F6 FF FF 8B 45 E4 8D 55 E8 E8 A9 F4 FF FF 8B 45 E8 8D 55 EC E8 EE F7 FF FF 8B 55 EC B8 C4 54 00 10 E8 D9 EC FF FF 83 3D C4 54 00 10 00 0F 84 05 01 00 00 80 3D A0 40 00 10 00 74 41 A1 C4 54 00 10 E8 D9 ED FF FF E8 48 E0 FF FF 8B D8 A1 C4 54 00 10 E8 C8 ED FF FF 50 B8 C4 54 00 10 E8 65 EF FF FF 8B D3 59 E8 69 E1 FF FF 8B C3 E8 12 FA FF FF 8B C3 E8 33 E0 FF FF E9 AD 00 00 00 B8 05 01 00 00 E8 0C E0 FF FF 8B D8 53 68 05 01 00 00 E8 57 F3 FF FF 8D 45 DC 8B D3 E8 39 ED FF FF 8B 55 DC B8 14 56 00 10 B9 00 32 00 10 E8 BB ED FF FF 8B 15 14 56 00 10 B8 C8 54 00 10 E8 53 E5 FF FF BA 01 00 00 00 B8 C8 54 00 10 E8 8C E8 FF FF E8 DF E0 FF FF 85 C0 75 52 6A 00 A1 C4 54 00 10 E8 3B ED FF FF 50 B8 C4 54 00 10 E8 D8 EE FF FF 8B D0 B8 C8 54 00 10 59 E8 3B E6 FF FF E8 76 E0 FF FF B8 C8 54 00 10 E8 4C E6 FF FF E8 67 E0 FF FF 6A 00 6A 00 6A 00 A1 14 56 00 10 E8 53 EE FF FF 50 6A 00 6A 00 E8 41 F3 FF FF 80 3D 9C 40 00 10 00 74 05 E8 EF FB FF FF 33 C0 5A 59 59 64 89 10 68 EF 31 00 10 8D 45 DC BA 05 00 00 00 E8 7D EB FF FF C3 E9 23 E9 FF FF EB EB 5B E8 63 EA FF FF 00 00 00 FF FF FF FF 08 00 00 00 74 65 6D 70 2E 65 78 65 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1196_PUNiSHER {
	meta:
		tool = "P"
		name = "PUNiSHER"
		version = "1.5 Demo"
		pattern = "EB0483A4BCCE60EB0480BC0411E800000000"
	strings:
		$1 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1197_PUNiSHER {
	meta:
		tool = "P"
		name = "PUNiSHER"
		version = "1.5"
		pattern = "3F0000806620??007E20??009220??00A420??00000000004B45524E454C3332"
	strings:
		$1 = { 3F 00 00 80 66 20 ?? 00 7E 20 ?? 00 92 20 ?? 00 A4 20 ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1198_PuNkMoD {
	meta:
		tool = "P"
		name = "PuNkMoD"
		version = "1.x"
		pattern = "94B9????0000BC????????80340C"
	strings:
		$1 = { 94 B9 ?? ?? 00 00 BC ?? ?? ?? ?? 80 34 0C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1199_QinYingShieldLicense {
	meta:
		tool = "P"
		name = "QinYingShieldLicense"
		version = "1.0X-V1.21"
		pattern = "E8000000005805????????9C50C20400558BEC565753349947493433EF31CDF5B0CBB5B0A3A1A3A1B9FEB9FEB9FEB9FEBFC9CFA7D1BDA3ACC4E3B2BBD6AAB5C0D5E2C0EFB5C4D6B8C1EECAC7CAB2C3B4A3A1B9FEB9FEB9FE00000000000000"
	strings:
		$1 = { E8 00 00 00 00 58 05 ?? ?? ?? ?? 9C 50 C2 04 00 55 8B EC 56 57 53 34 99 47 49 34 33 EF 31 CD F5 B0 CB B5 B0 A3 A1 A3 A1 B9 FE B9 FE B9 FE B9 FE BF C9 CF A7 D1 BD A3 AC C4 E3 B2 BB D6 AA B5 C0 D5 E2 C0 EF B5 C4 D6 B8 C1 EE CA C7 CA B2 C3 B4 A3 A1 B9 FE B9 FE B9 FE 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1200_QrYPt0r {
	meta:
		tool = "P"
		name = "QrYPt0r"
		pattern = "80F9000F848D0100008AC3????????????????????????????????????????????????????????????????????????????????????????????????????32C13CF37589????????????????????????????????????????????????????????????????????????????????????????????????????BAD9040000E8000000005F81C716010000802C3A01"
	strings:
		$1 = { 80 F9 00 0F 84 8D 01 00 00 8A C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 C1 3C F3 75 89 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? BA D9 04 00 00 E8 00 00 00 00 5F 81 C7 16 01 00 00 80 2C 3A 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1201_QrYPt0r {
	meta:
		tool = "P"
		name = "QrYPt0r"
		pattern = "8618CC64FF3500000000????????????????????????????????????????????????????????????????????????????????????????????????????64892500000000BB0000F7BF????????????????????????????????????????????????????????????????????????????????????????????????????B8785634128703E8CDFEFFFFE8B3"
	strings:
		$1 = { 86 18 CC 64 FF 35 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 89 25 00 00 00 00 BB 00 00 F7 BF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? B8 78 56 34 12 87 03 E8 CD FE FF FF E8 B3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1202_QrYPt0r {
	meta:
		tool = "P"
		name = "QrYPt0r"
		pattern = "EB00E8B5000000E92E01000064FF3500000000????????????????????????????????????????????????????????????????????????????????????????????????????648925000000008B442404"
	strings:
		$1 = { EB 00 E8 B5 00 00 00 E9 2E 01 00 00 64 FF 35 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 89 25 00 00 00 00 8B 44 24 04 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1203_R_SC_s_Process_Patcher {
	meta:
		tool = "P"
		name = "R!SC's Process Patcher"
		version = "1.4"
		pattern = "E8E10100008038227513803800742E80382075068078FF22741840EBED803800741BEB19408078FF2075F9803800740DEB0B40803800740580382274008BF8B8046040006800204000C705A220400044000000689220400068A22040006A006A006A046A006A006A005750E87C01000085C00F842A010000B8006040008B00A31C224000BE40604000837EFC000F84F60000008B3E83C60485FF0F848300000081FF722173630F"
	strings:
		$1 = { E8 E1 01 00 00 80 38 22 75 13 80 38 00 74 2E 80 38 20 75 06 80 78 FF 22 74 18 40 EB ED 80 38 00 74 1B EB 19 40 80 78 FF 20 75 F9 80 38 00 74 0D EB 0B 40 80 38 00 74 05 80 38 22 74 00 8B F8 B8 04 60 40 00 68 00 20 40 00 C7 05 A2 20 40 00 44 00 00 00 68 92 20 40 00 68 A2 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 7C 01 00 00 85 C0 0F 84 2A 01 00 00 B8 00 60 40 00 8B 00 A3 1C 22 40 00 BE 40 60 40 00 83 7E FC 00 0F 84 F6 00 00 00 8B 3E 83 C6 04 85 FF 0F 84 83 00 00 00 81 FF 72 21 73 63 0F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1204_R_SC_s_Process_Patcher {
	meta:
		tool = "P"
		name = "R!SC's Process Patcher"
		version = "1.5.1"
		pattern = "6800204000E8C3010000803800740D668178FE22207502EB0340EBEE8BF8B80460400068C420400068D42040006A006A006A046A006A006A005750E89F01000085C00F8439010000BE006040008B06A32821400083C640837EFC000F848F0000008B3E83C60485FF0F84E500000081FF72217363747A0FB71E8BCF8D7E02C70524214000000000008305242140000150A128214000390524214000580F84D8000000606A005368"
	strings:
		$1 = { 68 00 20 40 00 E8 C3 01 00 00 80 38 00 74 0D 66 81 78 FE 22 20 75 02 EB 03 40 EB EE 8B F8 B8 04 60 40 00 68 C4 20 40 00 68 D4 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 9F 01 00 00 85 C0 0F 84 39 01 00 00 BE 00 60 40 00 8B 06 A3 28 21 40 00 83 C6 40 83 7E FC 00 0F 84 8F 00 00 00 8B 3E 83 C6 04 85 FF 0F 84 E5 00 00 00 81 FF 72 21 73 63 74 7A 0F B7 1E 8B CF 8D 7E 02 C7 05 24 21 40 00 00 00 00 00 83 05 24 21 40 00 01 50 A1 28 21 40 00 39 05 24 21 40 00 58 0F 84 D8 00 00 00 60 6A 00 53 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1205_RatPacker__Glue__stub {
	meta:
		tool = "P"
		name = "RatPacker (Glue) stub"
		pattern = "4020FF00000000000000??BE006040008DBE00B0FFFF"
	strings:
		$1 = { 40 20 FF 00 00 00 00 00 00 00 ?? BE 00 60 40 00 8D BE 00 B0 FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1206_RAZOR_1911_encryptor {
	meta:
		tool = "P"
		name = "RAZOR 1911 encryptor"
		pattern = "E8????BF????3BFC72??B44CCD21BE????B9????FDF3A5FC"
	strings:
		$1 = { E8 ?? ?? BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1207_RCryptor {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.1"
		pattern = "8B042483E84F68????????FFD0"
	strings:
		$1 = { 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1208_RCryptor {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.3 / 1.4"
		pattern = "558BEC8B44240483E84F68????????FFD0585950"
	strings:
		$1 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1209_RCryptor {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.3b"
		pattern = "6183EF4F6068????????FFD7"
	strings:
		$1 = { 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1210_RCryptor {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.5"
		pattern = "832C244F68????????FF542404834424044F"
	strings:
		$1 = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1211_RCryptor {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.6"
		pattern = "33D068????????FFD2"
	strings:
		$1 = { 33 D0 68 ?? ?? ?? ?? FF D2 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1212_RCryptor {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.6b / 1.6c"
		pattern = "8BC70304242BC78038500F851B8B1FFF68"
	strings:
		$1 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1213_RCryptor {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.6"
		pattern = "60906161807FF04590600F851B8B1FFF68"
	strings:
		$1 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1214_RCryptor {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "1.x"
		pattern = "90589050908B00903C5090580F8567D6EF115068"
	strings:
		$1 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1215_RCryptor {
	meta:
		tool = "P"
		name = "RCryptor"
		version = "2.0"
		pattern = "F7D183F1FF6A00F7D183F1FF810424????????F7D183F1FF"
	strings:
		$1 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1216_RE_Crypt {
	meta:
		tool = "P"
		name = "RE-Crypt"
		version = "0.7x"
		pattern = "60E8000000005D558104240A000000C38BF581C5????0000896D348975388B7D3881E700FFFFFF81C74800000047037D608B4D5C83F9007E0F8B17335558891783C70483C1FCEBEC8B"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B 17 33 55 58 89 17 83 C7 04 83 C1 FC EB EC 8B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1217_RE_Crypt {
	meta:
		tool = "P"
		name = "RE-Crypt"
		version = "0.7x"
		pattern = "60E8000000005D81EDF31D4000B97B0900008DBD3B1E40008BF76160E8000000005D558104240A000000C38BF581C5????0000896D348975388B7D3881E700FFFFFF81C74800000047037D608B4D5C83F9007E0F8B"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 61 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 ?? ?? 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1218_Reflexive_Arcade_Wrapper {
	meta:
		tool = "P"
		name = "Reflexive Arcade Wrapper"
		pattern = "558BEC6AFF68986842006814FA410064A100000000506489250000000083EC585356578965E8FF15F850420033D28AD489153CE842008BC881E1FF000000890D38E84200C1E10803CA890D34E84200C1E810A330E8420033F656E8584300005985C075086A1CE8B0000000598975FCE823400000FF1518514200A344FE4200E8E13E0000A378E84200E88A3C0000E8CC3B0000E83EF5FFFF8975D08D45A450FF1514514200E85D"
	strings:
		$1 = { 55 8B EC 6A FF 68 98 68 42 00 68 14 FA 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 F8 50 42 00 33 D2 8A D4 89 15 3C E8 42 00 8B C8 81 E1 FF 00 00 00 89 0D 38 E8 42 00 C1 E1 08 03 CA 89 0D 34 E8 42 00 C1 E8 10 A3 30 E8 42 00 33 F6 56 E8 58 43 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 23 40 00 00 FF 15 18 51 42 00 A3 44 FE 42 00 E8 E1 3E 00 00 A3 78 E8 42 00 E8 8A 3C 00 00 E8 CC 3B 00 00 E8 3E F5 FF FF 89 75 D0 8D 45 A4 50 FF 15 14 51 42 00 E8 5D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
