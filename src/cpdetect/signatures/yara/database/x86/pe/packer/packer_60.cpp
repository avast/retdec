/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_60.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_60 =
R"x86_pe_packer(
rule rule_1657_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Noon.1163"
		pattern = "E8????5B5056B4CBCD213C07????81??????2E????4D5A????BF000189DEFC"
	strings:
		$1 = { E8 ?? ?? 5B 50 56 B4 CB CD 21 3C 07 ?? ?? 81 ?? ?? ?? 2E ?? ?? 4D 5A ?? ?? BF 00 01 89 DE FC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1658_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "November 17.768"
		pattern = "E8????5E81EE????5033C08ED8803E??????0E1F????FC"
	strings:
		$1 = { E8 ?? ?? 5E 81 EE ?? ?? 50 33 C0 8E D8 80 3E ?? ?? ?? 0E 1F ?? ?? FC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1659_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Number One"
		pattern = "F9073C536D696C653EE8"
	strings:
		$1 = { F9 07 3C 53 6D 69 6C 65 3E E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1660_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Phoenix.927"
		pattern = "E800005E81C6????BF0001B90400F3A4E8"
	strings:
		$1 = { E8 00 00 5E 81 C6 ?? ?? BF 00 01 B9 04 00 F3 A4 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1661_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Predator.2448"
		pattern = "0E1FBF????B8????B9????49????????2AC14F4F????F9CC"
	strings:
		$1 = { 0E 1F BF ?? ?? B8 ?? ?? B9 ?? ?? 49 ?? ?? ?? ?? 2A C1 4F 4F ?? ?? F9 CC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1662_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Quake.518"
		pattern = "1E068CC88ED8??????????????B82135CD2181"
	strings:
		$1 = { 1E 06 8C C8 8E D8 ?? ?? ?? ?? ?? ?? ?? B8 21 35 CD 21 81 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1663_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "SK"
		pattern = "CD20B80300CD1051E800005E83EE09"
	strings:
		$1 = { CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1664_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Slowload"
		pattern = "03D6B440CD21B8024233D233C9CD218BD6B97801"
	strings:
		$1 = { 03 D6 B4 40 CD 21 B8 02 42 33 D2 33 C9 CD 21 8B D6 B9 78 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1665_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Sonik Youth"
		pattern = "8A1602008A0732C2880743FEC281FB"
	strings:
		$1 = { 8A 16 02 00 8A 07 32 C2 88 07 43 FE C2 81 FB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1666_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Spanz"
		pattern = "E800005E81EE????8D94????B41ACD21C784"
	strings:
		$1 = { E8 00 00 5E 81 EE ?? ?? 8D 94 ?? ?? B4 1A CD 21 C7 84 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1667_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "SYP"
		pattern = "478BC2051E00528BD0B8023DCD218BD85A"
	strings:
		$1 = { 47 8B C2 05 1E 00 52 8B D0 B8 02 3D CD 21 8B D8 5A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1668_VX {
	meta:
		tool = "P"
		name = "VX:"
		version = "Tibs/Zhelatin (StormWorm) variant"
		pattern = "FF74241C588D80????7704506862343504E8"
	strings:
		$1 = { FF 74 24 1C 58 8D 80 ?? ?? 77 04 50 68 62 34 35 04 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1669_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "TravJack.883"
		pattern = "EB??9C9E26????5104??7D??00??2E????????8CC88EC08ED880????????74??8A??????BB????8A??32C288??FEC24381"
	strings:
		$1 = { EB ?? 9C 9E 26 ?? ?? 51 04 ?? 7D ?? 00 ?? 2E ?? ?? ?? ?? 8C C8 8E C0 8E D8 80 ?? ?? ?? ?? 74 ?? 8A ?? ?? ?? BB ?? ?? 8A ?? 32 C2 88 ?? FE C2 43 81 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1670_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Trivial.25"
		pattern = "B44EFEC6CD21B8??3DBA??00CD2193B440CD"
	strings:
		$1 = { B4 4E FE C6 CD 21 B8 ?? 3D BA ?? 00 CD 21 93 B4 40 CD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1671_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Trivial.46"
		pattern = "B44EB120BA????CD21BA????B8??3DCD21"
	strings:
		$1 = { B4 4E B1 20 BA ?? ?? CD 21 BA ?? ?? B8 ?? 3D CD 21 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1672_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Trojan.Telefoon"
		pattern = "601EE83B01BFCC012E033ECA012EC705"
	strings:
		$1 = { 60 1E E8 3B 01 BF CC 01 2E 03 3E CA 01 2E C7 05 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1673_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "Uddy.2617"
		pattern = "2E??????????2E??????????2E??????8CC88ED88C??????2B??????03??????A3????A1????A3????A1????A3????8CC82B??????03??????A3????B8AB9CCD2F3D7698"
	strings:
		$1 = { 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? 8C C8 8E D8 8C ?? ?? ?? 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? A1 ?? ?? A3 ?? ?? 8C C8 2B ?? ?? ?? 03 ?? ?? ?? A3 ?? ?? B8 AB 9C CD 2F 3D 76 98 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1674_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VCL (encrypted)"
		pattern = "01B9????8134????4646E2F8C3"
	strings:
		$1 = { 01 B9 ?? ?? 81 34 ?? ?? 46 46 E2 F8 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1675_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VCL (encrypted)"
		pattern = "01B9????8135????4747E2F8C3"
	strings:
		$1 = { 01 B9 ?? ?? 81 35 ?? ?? 47 47 E2 F8 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1676_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VCL"
		pattern = "ACB90080F2AEB90400ACAE75??E2FA89"
	strings:
		$1 = { AC B9 00 80 F2 AE B9 04 00 AC AE 75 ?? E2 FA 89 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1677_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VirusConstructor(IVP).based"
		pattern = "E9????E8????5D??????????81ED????????????E8????81FC????????8D??????BF????57A4A5"
	strings:
		$1 = { E9 ?? ?? E8 ?? ?? 5D ?? ?? ?? ?? ?? 81 ED ?? ?? ?? ?? ?? ?? E8 ?? ?? 81 FC ?? ?? ?? ?? 8D ?? ?? ?? BF ?? ?? 57 A4 A5 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1678_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VirusConstructor.based"
		pattern = "BB????B9????2E????????4343????8BECCC8B????81??????061EB8????CD213D????????8CD8488ED8"
	strings:
		$1 = { BB ?? ?? B9 ?? ?? 2E ?? ?? ?? ?? 43 43 ?? ?? 8B EC CC 8B ?? ?? 81 ?? ?? ?? 06 1E B8 ?? ?? CD 21 3D ?? ?? ?? ?? 8C D8 48 8E D8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1679_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "VirusConstructor.based"
		pattern = "E8????5D81??????061EE8????E8????????2E????????????B44ABBFFFFCD2183????B44ACD21"
	strings:
		$1 = { E8 ?? ?? 5D 81 ?? ?? ?? 06 1E E8 ?? ?? E8 ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B4 4A BB FF FF CD 21 83 ?? ?? B4 4A CD 21 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1680_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "XPEH.4768"
		pattern = "E8????5B81??????5056572E??????????2E????????????B8010050B8????50E8"
	strings:
		$1 = { E8 ?? ?? 5B 81 ?? ?? ?? 50 56 57 2E ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? B8 01 00 50 B8 ?? ?? 50 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1681_Vx {
	meta:
		tool = "P"
		name = "Vx:"
		version = "XRCV.1015"
		pattern = "E8????5E83????53511E06B499CD2180FC21??????????33C0508CD8488EC01FA1????8B"
	strings:
		$1 = { E8 ?? ?? 5E 83 ?? ?? 53 51 1E 06 B4 99 CD 21 80 FC 21 ?? ?? ?? ?? ?? 33 C0 50 8C D8 48 8E C0 1F A1 ?? ?? 8B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1687_WebCops {
	meta:
		tool = "P"
		name = "WebCops"
		version = "DLL"
		pattern = "A8BE58DCD6CCC4634A0FE002BBCEF35C5023FB62E73D2B"
	strings:
		$1 = { A8 BE 58 DC D6 CC C4 63 4A 0F E0 02 BB CE F3 5C 50 23 FB 62 E7 3D 2B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1688_WebCops {
	meta:
		tool = "P"
		name = "WebCops"
		version = "EXE"
		pattern = "EB0305EB02EBFC55EB03EB0405EBFBEB53E80400000072"
	strings:
		$1 = { EB 03 05 EB 02 EB FC 55 EB 03 EB 04 05 EB FB EB 53 E8 04 00 00 00 72 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1689_Werus_Crypter {
	meta:
		tool = "P"
		name = "Werus Crypter"
		version = "1.0"
		pattern = "68981140006A00E850000000C9C3EDB3FEFFFF6A00E80C000000FF2580104000FF2584104000FF2588104000FF258C104000FF2590104000FF2594104000FF2598104000FF259C104000FF25A0104000FF25A4104000FF25A8104000FF25B010400000000000000000000000000000000000000000000000000000000000000000000000BBE8124000803305E97DFFFFFF"
	strings:
		$1 = { 68 98 11 40 00 6A 00 E8 50 00 00 00 C9 C3 ED B3 FE FF FF 6A 00 E8 0C 00 00 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 A8 10 40 00 FF 25 B0 10 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 BB E8 12 40 00 80 33 05 E9 7D FF FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1690_Werus_Crypter {
	meta:
		tool = "P"
		name = "Werus Crypter"
		version = "1.0"
		pattern = "BBE8124000803305E97DFFFFFF"
	strings:
		$1 = { BB E8 12 40 00 80 33 05 E9 7D FF FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1691_WIBU_Key {
	meta:
		tool = "P"
		name = "WIBU-Key"
		version = "4.10A"
		pattern = "F705????????FF0000007512"
	strings:
		$1 = { F7 05 ?? ?? ?? ?? FF 00 00 00 75 12 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1692_Wind_of_Crypt {
	meta:
		tool = "P"
		name = "Wind of Crypt"
		version = "1.0"
		pattern = "558BEC83C4EC53????????8945ECB864400010E828EAFFFF33C05568CE51001064????????206A0068800000006A036A006A0168000000808D55EC33C0E8F6DBFFFF8B45ECE812E7FFFF50E83CEAFFFF8BD883FBFF0F84A60000006A0053E841EAFFFF8BF081EE005E00006A006A0068005E000053E852EAFFFFB8F49700108BD6E82EE7FFFFB8F89700108BD6E822E7FFFF8BC6E8ABD8FFFF8BF86A0068F097001056A1F49700105053E805EAFFFF53E8CFE9FFFFB8FC970010BAE8510010E874EAFFFFA1F497001085C0740583E8048B0050B9F8970010B8FC9700108B15F4970010E8D8EAFFFFB8FC970010E85AEBFFFF8BCE8B15F89700108BC7E8EBE9FFFF8BC785C07405E8E4EBFFFF33C05A595964891068D55100108D45ECE8BBE5FFFFC3E9A9DFFFFFEBF05F5E5BE8B7E4FFFF000000FFFFFFFF0A000000635A6C5630556C6B704D"
	strings:
		$1 = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 64 40 00 10 E8 28 EA FF FF 33 C0 55 68 CE 51 00 10 64 ?? ?? ?? ?? 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 F6 DB FF FF 8B 45 EC E8 12 E7 FF FF 50 E8 3C EA FF FF 8B D8 83 FB FF 0F 84 A6 00 00 00 6A 00 53 E8 41 EA FF FF 8B F0 81 EE 00 5E 00 00 6A 00 6A 00 68 00 5E 00 00 53 E8 52 EA FF FF B8 F4 97 00 10 8B D6 E8 2E E7 FF FF B8 F8 97 00 10 8B D6 E8 22 E7 FF FF 8B C6 E8 AB D8 FF FF 8B F8 6A 00 68 F0 97 00 10 56 A1 F4 97 00 10 50 53 E8 05 EA FF FF 53 E8 CF E9 FF FF B8 FC 97 00 10 BA E8 51 00 10 E8 74 EA FF FF A1 F4 97 00 10 85 C0 74 05 83 E8 04 8B 00 50 B9 F8 97 00 10 B8 FC 97 00 10 8B 15 F4 97 00 10 E8 D8 EA FF FF B8 FC 97 00 10 E8 5A EB FF FF 8B CE 8B 15 F8 97 00 10 8B C7 E8 EB E9 FF FF 8B C7 85 C0 74 05 E8 E4 EB FF FF 33 C0 5A 59 59 64 89 10 68 D5 51 00 10 8D 45 EC E8 BB E5 FF FF C3 E9 A9 DF FF FF EB F0 5F 5E 5B E8 B7 E4 FF FF 00 00 00 FF FF FF FF 0A 00 00 00 63 5A 6C 56 30 55 6C 6B 70 4D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1693_Winkript {
	meta:
		tool = "P"
		name = "Winkript"
		version = "1.0"
		pattern = "33C08BB800??????8B9004??????85FF741B33C950EB0C8A0439C0C804341B880439413BCA72F058"
	strings:
		$1 = { 33 C0 8B B8 00 ?? ?? ?? 8B 90 04 ?? ?? ?? 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1694_WinRAR {
	meta:
		tool = "P"
		name = "WinRAR"
		version = "32-bit SFX Module"
		pattern = "E9????000000000000909090????????????00??00??????????FF"
	strings:
		$1 = { E9 ?? ?? 00 00 00 00 00 00 90 90 90 ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1695_WinUpack {
	meta:
		tool = "P"
		name = "WinUpack"
		version = "0.39f"
		pattern = "BEB011????AD50FF7634EB7C4801????0B014C6F61644C6962726172794100001810000010000000????????0000????001000000002000004000000000039"
	strings:
		$1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 ?? ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1696_WinZip_Self_Extractor {
	meta:
		tool = "P"
		name = "WinZip Self-Extractor"
		pattern = "53FF15??????00B3223818740380C3FE8A48014033D23ACA740A3ACB74068A480140EBF23810"
	strings:
		$1 = { 53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1697_WinZip_Self_Extractor {
	meta:
		tool = "P"
		name = "WinZip Self-Extractor"
		pattern = "FF15??????00B12238087402B120408038007410"
	strings:
		$1 = { FF 15 ?? ?? ?? 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1698_WinZip_Self_Extractor {
	meta:
		tool = "P"
		name = "WinZip Self-Extractor"
		version = "2.2 personal edition"
		pattern = "53FF1558704000B3223818740380C3FE4033D28A083ACA74103ACB7407408A083ACA75F5381074014052505252FF155C70400050E815FBFFFF50FF158C7040005B"
	strings:
		$1 = { 53 FF 15 58 70 40 00 B3 22 38 18 74 03 80 C3 FE 40 33 D2 8A 08 3A CA 74 10 3A CB 74 07 40 8A 08 3A CA 75 F5 38 10 74 01 40 52 50 52 52 FF 15 5C 70 40 00 50 E8 15 FB FF FF 50 FF 15 8C 70 40 00 5B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1699_Wise_Installer_Stub {
	meta:
		tool = "I"
		name = "Wise Installer"
		version = "1.10.1029.1"
		pattern = "558BEC81EC400F00005356576A04FF15F4304000FF15743040008A088945E880F92275488A4801408945E833F684C9740E80F92274098A4801408945E8EBEE8038227504408945E880382075094080382074FA8945E88A0880F92F742B84C9741F80F93D741A8A480140EBF133F684C974D680F92074"
	strings:
		$1 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 E8 8A 08 80 F9 2F 74 2B 84 C9 74 1F 80 F9 3D 74 1A 8A 48 01 40 EB F1 33 F6 84 C9 74 D6 80 F9 20 74 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1700_Wise_Installer {
	meta:
		tool = "I"
		name = "Wise Installer"
		pattern = "558BEC81EC????00005356576A??????????????FF15????4000"
	strings:
		$1 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? 40 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
