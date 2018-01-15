/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_09.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_09 =
R"x86_pe_packer(
rule rule_231_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "5.20"
		pattern = "E8383D0000E916FEFFFF6A0C68????????E8981E00008B4D0833FF3BCF762E6AE05833D2F7F13B450C1BC040751FE8EC1C0000C7000C0000005757575757E87D1C000083C41433C0E9D50000000FAF4D0C8BF18975083BF7750333F64633DB895DE483FEE07769833D??????????754B83C60F83E6F089750C8B45083B05????????77376A04E8FE1A000059897DFCFF7508E856450000598945E4C745FCFEFFFFFFE85F0000008B5DE43BDF7411FF75085753E896D3FFFF83C40C3BDF7561566A08FF35????????FF15????????8BD83BDF754C393D????????743356E8C0FAFFFF5985C00F8572FFFFFF8B45103BC70F8450FFFFFFC7000C000000E945FFFFFF33FF8B750C6A04E8A419000059C33BDF750D8B45103BC77406C7000C0000008BC3E8CC1D0000C3558BEC518365FC00578D45FC50FF750CFF7508E8CAFEFFFF8BF883C40C85FF7519568B75FC85F67410E8C91B000085C07407E8C01B000089305E8BC75FC9C36A0C68????????E83B1D00008B750885F67475833D??????????75436A04E8FF190000598365FC0056E8843C0000598945E485C074095650E8A03C00005959C745FCFEFFFFFFE80B000000837DE4007537FF7508EB0A6A04E8ED18000059C3"
	strings:
		$1 = { E8 38 3D 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 98 1E 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 EC 1C 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 7D 1C 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? ?? 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 FE 1A 00 00 59 89 7D FC FF 75 08 E8 56 45 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 96 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 C0 FA FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 A4 19 00 00 59 C3 3B DF 75 0D 8B 45 10 3B C7 74 06 C7 00 0C 00 00 00 8B C3 E8 CC 1D 00 00 C3 55 8B EC 51 83 65 FC 00 57 8D 45 FC 50 FF 75 0C FF 75 08 E8 CA FE FF FF 8B F8 83 C4 0C 85 FF 75 19 56 8B 75 FC 85 F6 74 10 E8 C9 1B 00 00 85 C0 74 07 E8 C0 1B 00 00 89 30 5E 8B C7 5F C9 C3 6A 0C 68 ?? ?? ?? ?? E8 3B 1D 00 00 8B 75 08 85 F6 74 75 83 3D ?? ?? ?? ?? ?? 75 43 6A 04 E8 FF 19 00 00 59 83 65 FC 00 56 E8 84 3C 00 00 59 89 45 E4 85 C0 74 09 56 50 E8 A0 3C 00 00 59 59 C7 45 FC FE FF FF FF E8 0B 00 00 00 83 7D E4 00 75 37 FF 75 08 EB 0A 6A 04 E8 ED 18 00 00 59 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_232_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "5.20b1"
		pattern = "E88E3F0000E916FEFFFF6A0C68????????E89E1600008B4D0833FF3BCF762E6AE05833D2F7F13B450C1BC040751FE8F5140000C7000C0000005757575757E88614000083C41433C0E9D50000000FAF4D0C8BF18975083BF7750333F64633DB895DE483FEE07769833D??????????754B83C60F83E6F089750C8B45083B05????????77376A04E80713000059897DFCFF7508E8AC470000598945E4C745FCFEFFFFFFE85F0000008B5DE43BDF7411FF75085753E87CD3FFFF83C40C3BDF7561566A08FF35????????FF15????????8BD83BDF754C393D????????743356E8C7F9FFFF5985C00F8572FFFFFF8B45103BC70F8450FFFFFFC7000C000000E945FFFFFF33FF8B750C6A04E8AD11000059C3"
	strings:
		$1 = { E8 8E 3F 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 9E 16 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 F5 14 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 86 14 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? ?? 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 07 13 00 00 59 89 7D FC FF 75 08 E8 AC 47 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 7C D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 C7 F9 FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 AD 11 00 00 59 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_233_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "5.40 - 5.42"
		pattern = "E8933E0000E916FEFFFF6A0C68????????E8B41F00008B4D0833FF3BCF762E6AE05833D2F7F13B450C1BC040751FE8AF1D0000C7000C0000005757575757E8401D000083C41433C0E9D50000000FAF4D0C8BF18975083BF7750333F64633DB895DE483FEE07769833D??????????754B83C60F83E6F089750C8B45083B05????????77376A04E8C11B000059897DFCFF7508E8B1460000598945E4C745FCFEFFFFFFE85F0000008B5DE43BDF7411FF75085753E886D3FFFF83C40C3BDF7561566A08FF35????????FF15????????8BD83BDF754C393D????????743356E8C4FAFFFF5985C00F8572FFFFFF8B45103BC70F8450FFFFFFC7000C000000E945FFFFFF33FF8B750C6A04E8671A000059C3"
	strings:
		$1 = { E8 93 3E 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 B4 1F 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 AF 1D 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 40 1D 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D ?? ?? ?? ?? ?? 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 ?? ?? ?? ?? 77 37 6A 04 E8 C1 1B 00 00 59 89 7D FC FF 75 08 E8 B1 46 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 86 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B D8 3B DF 75 4C 39 3D ?? ?? ?? ?? 74 33 56 E8 C4 FA FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 67 1A 00 00 59 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_234_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "6.x DLL"
		comment = "Silicon Realms Toolworks * Sign.By.fly * 20081227"
		pattern = "00000000000000000000000020000060????????????????????????????????00D00000????????00000000000000000000000020000060????????????????????????????????00600100????????000000000000000000000000400000C0????????????????????????????????00800000????????00000000000000000000000040000042????????????????????????????????????????????????000000000000000000000000400000C0"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 D0 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 60 01 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 80 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 42 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_235_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "6.x Minimum Protection"
		pattern = "E8????????E9????????6A0C68????????E8????????8365E4008B75083B35????????77226A04E8????????598365FC0056E8????????598945E4C745FCFEFF"
	strings:
		$1 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 65 E4 00 8B 75 08 3B 35 ?? ?? ?? ?? 77 22 6A 04 E8 ?? ?? ?? ?? 59 83 65 FC 00 56 E8 ?? ?? ?? ?? 59 89 45 E4 C7 45 FC FE FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_236_AsCrypt {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "80??????83????????90909051??????0100000083????E2"
	strings:
		$1 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 51 ?? ?? ?? 01 00 00 00 83 ?? ?? E2 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_237_AsCrypt {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "80??????83????????90909083????E2"
	strings:
		$1 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 83 ?? ?? E2 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_238_AsCrypt {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "80??????83????????909090E2"
	strings:
		$1 = { 80 ?? ?? ?? 83 ?? ?? ?? ?? 90 90 90 E2 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_239_AsCrypt {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "81????????????83??????????????83????E2??EB"
	strings:
		$1 = { 81 ?? ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? ?? 83 ?? ?? E2 ?? EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_240_AsCrypt {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "83????E2????E2??FF"
	strings:
		$1 = { 83 ?? ?? E2 ?? ?? E2 ?? FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_241_AsCrypt {
	meta:
		tool = "P"
		name = "AsCrypt"
		version = "0.1"
		pattern = "B9????????81????????????83042404??90909083E903E2ECEB??00000000000000000000"
	strings:
		$1 = { B9 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? ?? 83 04 24 04 ?? 90 90 90 83 E9 03 E2 EC EB ?? 00 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_242_ASDPack {
	meta:
		tool = "P"
		name = "ASDPack"
		pattern = "00000000????????0000000000000000????????????????0000000000000000000000000000000000000000????????000000004B65726E656C33322E646C6C008D49001F014765744D6F64756C6548616E646C65410090"
	strings:
		$1 = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8D 49 00 1F 01 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_243_ASDPack {
	meta:
		tool = "P"
		name = "ASDPack"
		version = "1.0"
		pattern = "558BEC5653E85C01000000000000000000000000000000100000??????00000000000000400000????000000000000000000??????00000000000000000000000000??????00000000000000000000????000010000000??000000????0000????0000????0000??000000????0000??000000????0000??000000????00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005B81EBE61D4000837D0C01751155E84F010000E86A0100005DE82C0000008BB31A1E400003B3FA1D40008B760CAD0BC0740DFF7510FF750CFF7508FFD0EBEEB8010000005B5EC9C20C00556A00FF93202140008983FA1D40006A406800100000FFB3021E40006A00FF932C2140008983061E40008B83F21D40000383FA1D400050FFB3061E400050E86D0100005F"
	strings:
		$1 = { 55 8B EC 56 53 E8 5C 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 ?? ?? ?? 00 00 00 00 00 00 00 40 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 00 10 00 00 00 ?? 00 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5B 81 EB E6 1D 40 00 83 7D 0C 01 75 11 55 E8 4F 01 00 00 E8 6A 01 00 00 5D E8 2C 00 00 00 8B B3 1A 1E 40 00 03 B3 FA 1D 40 00 8B 76 0C AD 0B C0 74 0D FF 75 10 FF 75 0C FF 75 08 FF D0 EB EE B8 01 00 00 00 5B 5E C9 C2 0C 00 55 6A 00 FF 93 20 21 40 00 89 83 FA 1D 40 00 6A 40 68 00 10 00 00 FF B3 02 1E 40 00 6A 00 FF 93 2C 21 40 00 89 83 06 1E 40 00 8B 83 F2 1D 40 00 03 83 FA 1D 40 00 50 FF B3 06 1E 40 00 50 E8 6D 01 00 00 5F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_244_ASDPack {
	meta:
		tool = "P"
		name = "ASDPack"
		version = "2.0"
		pattern = "5B43837B74000F8408000000894314E9"
	strings:
		$1 = { 5B 43 83 7B 74 00 0F 84 08 00 00 00 89 43 14 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_245_ASDPack {
	meta:
		tool = "P"
		name = "ASDPack"
		version = "2.0"
		pattern = "8B442404565753E8CD010000C30000000000000000000000000010000000"
	strings:
		$1 = { 8B 44 24 04 56 57 53 E8 CD 01 00 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_246_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "5D81ED??????00BB??????0003DD2B9D??????0083BD??????0000899D??????000F85????00008D85??????0050FF95??????008985"
	strings:
		$1 = { 5D 81 ED ?? ?? ?? 00 BB ?? ?? ?? 00 03 DD 2B 9D ?? ?? ?? 00 83 BD ?? ?? ?? 00 00 89 9D ?? ?? ?? 00 0F 85 ?? ?? 00 00 8D 85 ?? ?? ?? 00 50 FF 95 ?? ?? ?? 00 89 85 }
	condition:
		for any of them : ( $ in (pe.entry_point + 6 .. pe.entry_point + 7) )
}
rule rule_247_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8??????00E9????????????008BFEB997000000AD3578563412AB4975F6EB"
	strings:
		$1 = { 60 E8 ?? ?? ?? 00 E9 ?? ?? ?? ?? ?? ?? 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_248_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8??????00EB3387DB90"
	strings:
		$1 = { 60 E8 ?? ?? ?? 00 EB 33 87 DB 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_249_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8??????00EB4?0000000000000000"
	strings:
		$1 = { 60 E8 ?? ?? ?? 00 EB 4? 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ in (pe.entry_point .. pe.entry_point + 1) )
}
rule rule_250_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8????0000EB095D5581ED39394400C3E9????0000"
	strings:
		$1 = { 60 E8 ?? ?? 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 ?? ?? 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_251_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8000000005D81ED??????00B8??????0003C52B85??????008985??????0080BD??????00007515FE85??????00E81D000000E8????0000E8????00008B85"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? 00 B8 ?? ?? ?? 00 03 C5 2B 85 ?? ?? ?? 00 89 85 ?? ?? ?? 00 80 BD ?? ?? ?? 00 00 75 15 FE 85 ?? ?? ?? 00 E8 1D 00 00 00 E8 ?? ?? 00 00 E8 ?? ?? 00 00 8B 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_252_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E8000000005D81ED76AA4400BB70AA440003DD2B9DE1B2440083BDDCB2440000899DEDB0"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 76 AA 44 00 BB 70 AA 44 00 03 DD 2B 9D E1 B2 44 00 83 BD DC B2 44 00 00 89 9D ED B0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_253_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		pattern = "60E93D040000"
	strings:
		$1 = { 60 E9 3D 04 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_254_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.00b"
		pattern = "60E8????????5D81ED921A44??B88C1A44??03C52B85CD1D44??8985D91D44??80BDC41D44"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_255_ASPack {
	meta:
		tool = "P"
		name = "ASPack"
		version = "1.01b"
		pattern = "60E8????????5D81EDD22A44??B8CC2A44??03C52B85A52E44??8985B12E44??80BD9C2E44"
	strings:
		$1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
