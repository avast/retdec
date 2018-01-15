/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_07.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_07 =
R"x86_pe_packer(
rule rule_173_AntiDote {
	meta:
		tool = "P"
		name = "AntiDote"
		version = "1.2 demo"
		pattern = "E8F7FEFFFF05CB220000FFE0E8EBFEFFFF05BB190000FFE0E8BD00000008B262000152170C0F2C2B207F527901300717294F013C302B5A3DC726112606590E782E10140B131A1A3F641D7133572109248B1B093708610F1D1D2A0187354C07390B"
	strings:
		$1 = { E8 F7 FE FF FF 05 CB 22 00 00 FF E0 E8 EB FE FF FF 05 BB 19 00 00 FF E0 E8 BD 00 00 00 08 B2 62 00 01 52 17 0C 0F 2C 2B 20 7F 52 79 01 30 07 17 29 4F 01 3C 30 2B 5A 3D C7 26 11 26 06 59 0E 78 2E 10 14 0B 13 1A 1A 3F 64 1D 71 33 57 21 09 24 8B 1B 09 37 08 61 0F 1D 1D 2A 01 87 35 4C 07 39 0B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_174_AntiDote {
	meta:
		tool = "P"
		name = "AntiDote"
		version = "1.2 / 1.4 SE DLL"
		pattern = "EB1066623A432B2B484F4F4B90E9083290909090909090909090807C2408010F85????????60BE????????8DBE????????5783CDFFEB0B908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73EF75098B1E83EEFC11DB73E431C983E803720DC1E0088A064683F0FF747489C501DB75078B1E83EEFC11DB11C901DB75078B1E83EEFC11DB11C975204101DB75078B1E83EEFC11DB11C901DB73EF75098B1E83EEFC11DB73E483C10281FD00F3FFFF83D1018D142F83FDFC760F8A02428807474975F7E963FFFFFF908B0283C204890783C70483E90477F101CFE94CFFFFFF"
	strings:
		$1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_175_AntiDote {
	meta:
		tool = "P"
		name = "AntiDote"
		version = "1.4 SE"
		pattern = "6890030000E8C6FDFFFF6890030000E8BCFDFFFF6890030000E8B2FDFFFF50E8ACFDFFFF50E8A6FDFFFF6869D60000E89CFDFFFF50E896FDFFFF50E890FDFFFF83C420E878FFFFFF84C0744F680401000068102260006A00FF15081060006890030000E868FDFFFF6869D60000E85EFDFFFF50E858FDFFFF50E852FDFFFFE8DDFEFFFF5068A410600068941060006810226000E858FDFFFF83C42033C0C210008B4C2408568B74240833D28BC6F7F18BC685D2740833D2F7F1400FAFC15EC3"
	strings:
		$1 = { 68 90 03 00 00 E8 C6 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50 E8 AC FD FF FF 50 E8 A6 FD FF FF 68 69 D6 00 00 E8 9C FD FF FF 50 E8 96 FD FF FF 50 E8 90 FD FF FF 83 C4 20 E8 78 FF FF FF 84 C0 74 4F 68 04 01 00 00 68 10 22 60 00 6A 00 FF 15 08 10 60 00 68 90 03 00 00 E8 68 FD FF FF 68 69 D6 00 00 E8 5E FD FF FF 50 E8 58 FD FF FF 50 E8 52 FD FF FF E8 DD FE FF FF 50 68 A4 10 60 00 68 94 10 60 00 68 10 22 60 00 E8 58 FD FF FF 83 C4 20 33 C0 C2 10 00 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_176_AntiVirus_Vaccine {
	meta:
		tool = "P"
		name = "AntiVirus Vaccine"
		version = "1.03"
		pattern = "FA33DBB9????0E1F33F6FCAD35????03D8E2"
	strings:
		$1 = { FA 33 DB B9 ?? ?? 0E 1F 33 F6 FC AD 35 ?? ?? 03 D8 E2 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_177_aPack {
	meta:
		tool = "P"
		name = "aPack"
		version = "0.62"
		pattern = "1E068CC88ED8??????8EC050BE????33FFFCB6"
	strings:
		$1 = { 1E 06 8C C8 8E D8 ?? ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B6 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_178_aPack {
	meta:
		tool = "P"
		name = "aPack"
		version = "0.82"
		pattern = "1E068CCBBA????03DA8D??????FC33F633FF484B8EC08EDB"
	strings:
		$1 = { 1E 06 8C CB BA ?? ?? 03 DA 8D ?? ?? ?? FC 33 F6 33 FF 48 4B 8E C0 8E DB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_179_aPack {
	meta:
		tool = "P"
		name = "aPack"
		version = "0.98 -m"
		pattern = "1E068CC88ED805????8EC050BE????33FFFCB2??BD????33C950A4BB????3BF376"
	strings:
		$1 = { 1E 06 8C C8 8E D8 05 ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B2 ?? BD ?? ?? 33 C9 50 A4 BB ?? ?? 3B F3 76 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_180_aPack {
	meta:
		tool = "P"
		name = "aPack"
		version = "0.98b (DS&ES not saved)"
		pattern = "8CCBBA????03DAFC33F633FF4B8EDB8D??????8EC0B9????F3A54A75"
	strings:
		$1 = { 8C CB BA ?? ?? 03 DA FC 33 F6 33 FF 4B 8E DB 8D ?? ?? ?? 8E C0 B9 ?? ?? F3 A5 4A 75 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_181_aPack {
	meta:
		tool = "P"
		name = "aPack"
		version = "0.98b com"
		pattern = "BE????BF????8BCFFC57F3A4C3BF????5757BE????B2??BD????50A4"
	strings:
		$1 = { BE ?? ?? BF ?? ?? 8B CF FC 57 F3 A4 C3 BF ?? ?? 57 57 BE ?? ?? B2 ?? BD ?? ?? 50 A4 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_182_aPack {
	meta:
		tool = "P"
		name = "aPack"
		version = "0.98b"
		pattern = "93071F05????8ED0BC????EA"
	strings:
		$1 = { 93 07 1F 05 ?? ?? 8E D0 BC ?? ?? EA }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_183_APatch_GUI {
	meta:
		tool = "P"
		name = "APatch GUI"
		version = "1.1"
		pattern = "5231C0E8FFFFFFFF"
	strings:
		$1 = { 52 31 C0 E8 FF FF FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_184_Apex {
	meta:
		tool = "P"
		name = "Apex"
		version = "3.0a"
		pattern = "5FB91400000051BE00104000B900????008A07300646E2FB4759E2EA68??????00C3"
	strings:
		$1 = { 5F B9 14 00 00 00 51 BE 00 10 40 00 B9 00 ?? ?? 00 8A 07 30 06 46 E2 FB 47 59 E2 EA 68 ?? ?? ?? 00 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_185_APEX_C {
	meta:
		tool = "P"
		name = "APEX_C"
		version = "BLT Apex 4.0"
		pattern = "68????????B9FFFFFF0001D0F7E2720148E2F7B9FF0000008B34248036FD46E2FAC3"
	strings:
		$1 = { 68 ?? ?? ?? ?? B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_186_App_Encryptor {
	meta:
		tool = "P"
		name = "App Encryptor"
		pattern = "60E8000000005D81ED1F1F4000B97B0900008DBD671F40008BF7AC"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 1F 1F 40 00 B9 7B 09 00 00 8D BD 67 1F 40 00 8B F7 AC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_187_App_Protector {
	meta:
		tool = "P"
		name = "App Protector"
		pattern = "E9970000000D0A53696C656E74205465616D204170702050726F746563746F720D0A437265617465642062792053696C656E7420536F6674776172650D0A5468656E6B7A20746F20446F6368746F7220580D0A0D0A"
	strings:
		$1 = { E9 97 00 00 00 0D 0A 53 69 6C 65 6E 74 20 54 65 61 6D 20 41 70 70 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 72 65 61 74 65 64 20 62 79 20 53 69 6C 65 6E 74 20 53 6F 66 74 77 61 72 65 0D 0A 54 68 65 6E 6B 7A 20 74 6F 20 44 6F 63 68 74 6F 72 20 58 0D 0A 0D 0A }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_188_ARC_SFX_Archive {
	meta:
		tool = "P"
		name = "ARC-SFX Archive"
		pattern = "8CC88CDB8ED88EC089??????2BC3A3????89??????BE????B9????BF????BA????FCAC32C28AD8"
	strings:
		$1 = { 8C C8 8C DB 8E D8 8E C0 89 ?? ?? ?? 2B C3 A3 ?? ?? 89 ?? ?? ?? BE ?? ?? B9 ?? ?? BF ?? ?? BA ?? ?? FC AC 32 C2 8A D8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_189_ARM_Protector {
	meta:
		tool = "P"
		name = "ARM Protector"
		version = "0.1 - 0.3"
		pattern = "E8040000008360EB0C5DEB054555EB04B8EBF900C3E8000000005DEB010081ED5E1F4000EB0283098DB5EF1F4000EB028309BAA3110000EB01008D8D923140008B09E81400000083EB01008BFEE8000000005883C0"
	strings:
		$1 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_191_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		pattern = "E8????????E9????????6A0C68????????E8????????8B4D0833FF3BCF762E6AE05833D2F7F13B450C1BC040751FE8????????C7000C0000005757575757E8"
	strings:
		$1 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 ?? ?? ?? ?? C7 00 0C 00 00 00 57 57 57 57 57 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_194_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "1.9x, 2.00b1, 2.50b1"
		pattern = "558BEC6AFF6898??????6810??????64A1????????50648925????????83EC585356578965E8FF15"
	strings:
		$1 = { 55 8B EC 6A FF 68 98 ?? ?? ?? 68 10 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_196_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.00"
		pattern = "558BEC6AFF680002410068C4A0400064A100000000506489250000000083EC58"
	strings:
		$1 = { 55 8B EC 6A FF 68 00 02 41 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_197_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.50, 2.50b3"
		pattern = "558BEC6AFF68B8??????68F8??????64A1????????50648925????????83EC585356578965E8FF1520??????33D28AD48915D0"
	strings:
		$1 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 F8 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 ?? ?? ?? 33 D2 8A D4 89 15 D0 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_198_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.51"
		pattern = "558BEC6AFF68B8??????68D0??????64A1????????50648925????????83EC585356578965E8FF1520"
	strings:
		$1 = { 55 8B EC 6A FF 68 B8 ?? ?? ?? 68 D0 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 20 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_199_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.52b2"
		pattern = "558BEC6AFF68????????B0????????686064A100000000506489250000000083EC585356578965E8FF??????1524"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? B0 ?? ?? ?? ?? 68 60 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 24 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_200_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.52"
		pattern = "558BEC6AFF68????????E0????????68D464A100000000506489250000000083EC585356578965E8FF??????1538"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? E0 ?? ?? ?? ?? 68 D4 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 38 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_201_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.52"
		pattern = "558BEC6AFF68E0??????68D4??????64A1????????50648925????????83EC585356578965E8FF1538"
	strings:
		$1 = { 55 8B EC 6A FF 68 E0 ?? ?? ?? 68 D4 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 38 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_202_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.52b2"
		pattern = "558BEC6AFF68B0??????6860??????64A1????????50648925????????83EC585356578965E8FF1524"
	strings:
		$1 = { 55 8B EC 6A FF 68 B0 ?? ?? ?? 68 60 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 24 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_203_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.53"
		pattern = "558BEC6AFF68????????40????????685464A100000000506489250000000083EC585356578965E8FF??????155833D28AD489"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 40 ?? ?? ?? ?? 68 54 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF ?? ?? ?? 15 58 33 D2 8A D4 89 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_204_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.53"
		pattern = "558BEC6AFF6840??????6854??????64A1????????50648925????????83EC585356578965E8FF1558??????33D28AD48915EC"
	strings:
		$1 = { 55 8B EC 6A FF 68 40 ?? ?? ?? 68 54 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_205_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.53b3"
		pattern = "558BEC6AFF68D8??????6814??????64A1????????50648925????????83EC585356578965E8FF15"
	strings:
		$1 = { 55 8B EC 6A FF 68 D8 ?? ?? ?? 68 14 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_206_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.5x - v2.6x"
		pattern = "558BEC6AFF68????????68????????64A100000000506489250000000083EC585356578965E8FF1558??????33D28AD48915EC"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_207_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.60"
		pattern = "558BEC6AFF68D0??????6834??????64A1????????50648925????????83EC585356578965E8FF1568??????33D28AD4891584"
	strings:
		$1 = { 55 8B EC 6A FF 68 D0 ?? ?? ?? 68 34 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 68 ?? ?? ?? 33 D2 8A D4 89 15 84 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_208_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.60a"
		pattern = "558BEC6AFF68????????6894??????64A1????????50648925????????83EC585356578965E8FF156C??????33D28AD48915B4"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 94 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 6C ?? ?? ?? 33 D2 8A D4 89 15 B4 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_209_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.60b1"
		pattern = "558BEC6AFF6850??????6874??????64A1????????50648925????????83EC585356578965E8FF1558??????33D28AD48915FC"
	strings:
		$1 = { 55 8B EC 6A FF 68 50 ?? ?? ?? 68 74 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 FC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_210_Armadillo {
	meta:
		tool = "P"
		name = "Armadillo"
		version = "2.60b2"
		pattern = "558BEC6AFF6890??????6824??????64A1????????50648925????????83EC585356578965E8FF1560??????33D28AD489153C"
	strings:
		$1 = { 55 8B EC 6A FF 68 90 ?? ?? ?? 68 24 ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 53 56 57 89 65 E8 FF 15 60 ?? ?? ?? 33 D2 8A D4 89 15 3C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
