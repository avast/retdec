/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_58.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_58 =
R"x86_pe_packer(
rule rule_1587_Vcasm_Protector {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.0x"
		pattern = "558BEC6AFF68????????68????????64A1000000005064892500000000E803000000"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1588_Vcasm_Protector {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.0x"
		pattern = "558BEC6AFF68????????68????????64A1000000005064892500000000E803000000C7840058EB01E983C00750"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1589_Vcasm_Protector {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.1 - 1.2"
		pattern = "EB0B5B5650726F746563745D"
	strings:
		$1 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1590_Vcasm_Protector {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.1"
		pattern = "B81AED4100B9ECEB41005051E874000000E8516A00005883E810B9B3000000"
	strings:
		$1 = { B8 1A ED 41 00 B9 EC EB 41 00 50 51 E8 74 00 00 00 E8 51 6A 00 00 58 83 E8 10 B9 B3 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1591_Vcasm_Protector {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.1a - 1.2"
		pattern = "00005669727475616C416C6C6F630000000000766361736D5F70726F746563745F323030355F335F31380000000000000000000000000000000000000000000000000033F6E8100000008B642408648F050000000058EB13C78364FF350000000064892500000000ADCD20EB010F31F0EB0C33C8EB03EB090F59740575F851EBF1B904000000E81F000000EBFAE816000000E9EBF8000058EB090F25E8F2FFFFFF0FB94975F1EB05EBF9EBF0D6E807000000C78383C013EB0B58EB02CD2083C002EB01E950C3"
	strings:
		$1 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F 32 30 30 35 5F 33 5F 31 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1592_Vcasm_Protector {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.3x"
		pattern = "0000000000????????0000000000000000????????????????0000000000000000000000000000000000000000????????????????????????000000006B65726E656C33322E646C6C0000000047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C6962726172794100608BB424240000008BBC2428000000FCC6C28033DBA4C6C302E8A90000000F83F1FFFFFF33C9E89C0000000F832D00000033C0E88F0000000F8337000000C6C30241C6C010E87D00000010C00F83F3FFFFFF"
	strings:
		$1 = { 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 60 8B B4 24 24 00 00 00 8B BC 24 28 00 00 00 FC C6 C2 80 33 DB A4 C6 C3 02 E8 A9 00 00 00 0F 83 F1 FF FF FF 33 C9 E8 9C 00 00 00 0F 83 2D 00 00 00 33 C0 E8 8F 00 00 00 0F 83 37 00 00 00 C6 C3 02 41 C6 C0 10 E8 7D 00 00 00 10 C0 0F 83 F3 FF FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1593_Vcasm_Protector {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.3x"
		pattern = "E9B9160000558BEC81EC74040000576800000000680000C21468FFFF000068????????9C81????????????????????9D54FF14246800000000680000C21068????????9C81????????????????????9D54FF1424680000000068????????9C81????????????????????9D54FF1424680000000068FFFFC21068????????9C81????????????????????9D54FF1424680000000068????????9C81????????????????????9D54FF14246800000000680000C21468FFFF000068????????9C81????????????????????9D54FF1424680000000068????????9C81????????????????????9D54FF14246800000000"
	strings:
		$1 = { E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 FF FF C2 10 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 68 ?? ?? ?? ?? 9C 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 9D 54 FF 14 24 68 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1594_Vcasm_Protector {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.x"
		pattern = "EB??5B5650726F746563745D"
	strings:
		$1 = { EB ?? 5B 56 50 72 6F 74 65 63 74 5D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1595_vfp_exeNc {
	meta:
		tool = "P"
		name = "vfp&exeNc"
		version = "5.00"
		pattern = "60E8000000005D????????????????????????5064FF350000000064892500000000CC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1596_vfp_exeNc {
	meta:
		tool = "P"
		name = "vfp&exeNc"
		version = "6.00"
		pattern = "60E8010000006358E8010000007A582D0D1040008D90C110400052508D80491040005D508D85651040005064FF350000000064892500000000CC"
	strings:
		$1 = { 60 E8 01 00 00 00 63 58 E8 01 00 00 00 7A 58 2D 0D 10 40 00 8D 90 C1 10 40 00 52 50 8D 80 49 10 40 00 5D 50 8D 85 65 10 40 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1597_Video_Lan_Client {
	meta:
		tool = "P"
		name = "Video-Lan-Client"
		pattern = "5589E583EC08??????????????????????????????FFFF??????????????????????????????????????00??????????????00"
	strings:
		$1 = { 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1598_Video_Lan_Client {
	meta:
		tool = "P"
		name = "Video-Lan-Client"
		pattern = "5589E583EC08??????????????????????????????FFFF"
	strings:
		$1 = { 55 89 E5 83 EC 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1599_Virogen_Crypt {
	meta:
		tool = "P"
		name = "Virogen Crypt"
		version = "0.75"
		pattern = "9C55E8EC00000087D55D6087D580BD1527400001"
	strings:
		$1 = { 9C 55 E8 EC 00 00 00 87 D5 5D 60 87 D5 80 BD 15 27 40 00 01 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1600_Virogen_s_PE_Shrinker {
	meta:
		tool = "P"
		name = "Virogen`s PE Shrinker"
		version = "0.14"
		pattern = "9C55E8????????87D55D6087D58D??????????8D??????????5756AD0BC074"
	strings:
		$1 = { 9C 55 E8 ?? ?? ?? ?? 87 D5 5D 60 87 D5 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 57 56 AD 0B C0 74 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1604_VISEMAN {
	meta:
		tool = "P"
		name = "VISEMAN"
		pattern = "45534956"
	strings:
		$1 = { 45 53 49 56 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1605_VISUAL_PROTECT {
	meta:
		tool = "P"
		name = "VISUAL PROTECT"
		pattern = "558BEC51535657C705??????000000000068??????00FF1500????00A3??????0068??????00A1??????0050FF1504????00A3??????006A00FF15??????00A3??????008B0D??????0051E8????000083C4048945FC837DFC007403FF65FC5F"
	strings:
		$1 = { 55 8B EC 51 53 56 57 C7 05 ?? ?? ?? 00 00 00 00 00 68 ?? ?? ?? 00 FF 15 00 ?? ?? 00 A3 ?? ?? ?? 00 68 ?? ?? ?? 00 A1 ?? ?? ?? 00 50 FF 15 04 ?? ?? 00 A3 ?? ?? ?? 00 6A 00 FF 15 ?? ?? ?? 00 A3 ?? ?? ?? 00 8B 0D ?? ?? ?? 00 51 E8 ?? ?? 00 00 83 C4 04 89 45 FC 83 7D FC 00 74 03 FF 65 FC 5F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1606_VMProtect {
	meta:
		tool = "P"
		name = "VMProtect"
		pattern = "68????????E8??????00"
	strings:
		$1 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1607_VMProtect {
	meta:
		tool = "P"
		name = "VMProtect"
		pattern = "68????????E8??????FF"
	strings:
		$1 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1608_VMProtect {
	meta:
		tool = "P"
		name = "VMProtect"
		version = "0.7x - 0.8"
		pattern = "5B20564D50726F74656374207620302E382028432920506F6C7954656368205D"
	strings:
		$1 = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1609_VMProtect {
	meta:
		tool = "P"
		name = "VMProtect"
		version = "1.x"
		pattern = "9C6068000000008B742428BF????????FC89F3033424AC00D8"
	strings:
		$1 = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1610_VOB_ProtectCD {
	meta:
		tool = "P"
		name = "VOB ProtectCD"
		pattern = "5F81EF????????BE????40??8B87????????03C657568CA7????????FF108987????????5E5F"
	strings:
		$1 = { 5F 81 EF ?? ?? ?? ?? BE ?? ?? 40 ?? 8B 87 ?? ?? ?? ?? 03 C6 57 56 8C A7 ?? ?? ?? ?? FF 10 89 87 ?? ?? ?? ?? 5E 5F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1611_VPacker {
	meta:
		tool = "P"
		name = "VPacker"
		pattern = "00000000FFFFFFFFFFFFFFFF????????????????0000000000000000000000000000000000000000????????????????????????????????????????????????????????????????000000006B65726E656C33322E646C6C0000004765744D6F64756C6548616E646C65410000004C6F61644C6962726172794100000047657450726F63416464726573730000005669727475616C416C6C6F630000005669727475616C467265650000005669727475616C50726F746563740000004865617043726561746500000048656170416C6C6F6300C38D4000558BEC51E828000000"
	strings:
		$1 = { 00 00 00 00 FF FF FF FF FF FF FF FF ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 48 65 61 70 43 72 65 61 74 65 00 00 00 48 65 61 70 41 6C 6C 6F 63 00 C3 8D 40 00 55 8B EC 51 E8 28 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1612_VPacker {
	meta:
		tool = "P"
		name = "VPacker"
		pattern = "89C6C745E001000000F7030000FFFF75180FB703508B45D850FF55F889078BC3E8??FEFFFF8BD8EB13538B45D850FF55F889078BC3E8??FEFFFF8BD883C704FF45E04E75C48BF3833E0075888B45E48B40100345DC8B551483C220890268008000006A008B45D450FF55EC8B55DC8B423C0345DC83C0048BD883C3148D45E0506A40680010000052FF55E88D4360"
	strings:
		$1 = { 89 C6 C7 45 E0 01 00 00 00 F7 03 00 00 FF FF 75 18 0F B7 03 50 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 EB 13 53 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 83 C7 04 FF 45 E0 4E 75 C4 8B F3 83 3E 00 75 88 8B 45 E4 8B 40 10 03 45 DC 8B 55 14 83 C2 20 89 02 68 00 80 00 00 6A 00 8B 45 D4 50 FF 55 EC 8B 55 DC 8B 42 3C 03 45 DC 83 C0 04 8B D8 83 C3 14 8D 45 E0 50 6A 40 68 00 10 00 00 52 FF 55 E8 8D 43 60 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1613_VProtector {
	meta:
		tool = "P"
		name = "VProtector"
		pattern = "000000004B45524E454C33322E646C6C00005553455233322E646C6C000047444933322E646C6C000000000000000047657450726F63416464726573730000004765744D6F64756C6548616E646C65410000004C6F61644C69627261727941000000536C65657000000047657456657273696F6E000000476574436F6D6D616E644C696E654100000047657453746172747570496E666F4100000047657441435000000043726561746554687265616400000044656657696E646F7750726F63410000005265676973746572436C61737345784100000043726561746557696E646F7745784100000047657453797374656D4D65747269637300000053686F7757696E646F77000000476574444300000052656C65617365444300000046696E6457696E646F77410000004765744D6573736167654100000044657374726F7957696E646F77000000536574506978656C00000000"
	strings:
		$1 = { 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 47 44 49 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 53 6C 65 65 70 00 00 00 47 65 74 56 65 72 73 69 6F 6E 00 00 00 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 00 00 47 65 74 53 74 61 72 74 75 70 49 6E 66 6F 41 00 00 00 47 65 74 41 43 50 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 47 65 74 44 43 00 00 00 52 65 6C 65 61 73 65 44 43 00 00 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 00 00 44 65 73 74 72 6F 79 57 69 6E 64 6F 77 00 00 00 53 65 74 50 69 78 65 6C 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
