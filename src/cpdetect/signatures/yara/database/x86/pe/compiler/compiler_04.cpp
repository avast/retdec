/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/compiler/compiler_04.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PeCompiler_04 =
R"x86_pe_compiler(rule rule_141_GCC__MinGW {
	meta:
		tool = "C"
		name = "MinGW GCC"
		version = "3.2.x DLL"
		pattern = "5589E583EC188975FC8B750C895DF883FE01745C897424048B5510895424088B5508891424E87601000083EC0C83FE0189C3742C85F6750C8B0D0030001085C9751031DB89D88B5DF88B75FC89EC5DC20C00E859000000EBEB8DB4260000000085C075D0E847000000EBC9908D742600C7042480000000E8A4050000A30030001085C0741AC70000000000A310300010E81B020000E8A6010000E975FFFFFFE86C050000C7000C"
	strings:
		$1 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 76 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 00 00 EB EB 8D B4 26 00 00 00 00 85 C0 75 D0 E8 47 00 00 00 EB C9 90 8D 74 26 00 C7 04 24 80 00 00 00 E8 A4 05 00 00 A3 00 30 00 10 85 C0 74 1A C7 00 00 00 00 00 A3 10 30 00 10 E8 1B 02 00 00 E8 A6 01 00 00 E9 75 FF FF FF E8 6C 05 00 00 C7 00 0C }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_142_GCC__MinGW {
	meta:
		tool = "C"
		name = "MinGW GCC"
		version = "3.2.x"
		pattern = "5589E583EC08C7042401000000FF15E4404000E86800000089EC31C05DC389F65589E583EC08C7042402000000FF15E4404000E84800000089EC31C05DC389F65589E583EC088B5508891424FF150041400089EC5DC38D76008DBC27000000005589E583EC088B5508891424FF15F440400089EC5DC38D76008DBC27000000005589E55383EC24C70424A0114000E88D07000083EC04E885020000C70424002040008B15102040"
	strings:
		$1 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 E4 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 E4 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 00 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 F4 40 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 53 83 EC 24 C7 04 24 A0 11 40 00 E8 8D 07 00 00 83 EC 04 E8 85 02 00 00 C7 04 24 00 20 40 00 8B 15 10 20 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_143_GCC__MinGW {
	meta:
		tool = "C"
		name = "MinGW GCC"
		version = "3.2.x"
		pattern = "5589E583EC08C7042401000000FF15FC404000E86800000089EC31C05DC389F65589E583EC08C7042402000000FF15FC404000E84800000089EC31C05DC389F65589E583EC088B5508891424FF151841400089EC5DC38D76008DBC27000000005589E583EC088B5508891424FF150C41400089EC5DC38D76008DBC27000000005589E55383EC24C70424A0114000E85D08000083EC04E855030000C70424002040008B15102040"
	strings:
		$1 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 FC 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 FC 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 18 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 0C 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 53 83 EC 24 C7 04 24 A0 11 40 00 E8 5D 08 00 00 83 EC 04 E8 55 03 00 00 C7 04 24 00 20 40 00 8B 15 10 20 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_144_GCC__MinGW {
	meta:
		tool = "C"
		name = "MinGW GCC"
		version = "3.x"
		pattern = "5589E583EC08C70424??000000FF15????4000E8????????????????????????55??????????????????????????????????????????00"
	strings:
		$1 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? 40 00 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_145_GCC__MinGW {
	meta:
		tool = "C"
		name = "MinGW GCC"
		pattern = "5589E583EC08C70424??000000FF15??????00E8??FEFFFF908DB4260000000055"
	strings:
		$1 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 E8 ?? FE FF FF 90 8D B4 26 00 00 00 00 55 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_146_GCC__MinGW {
	meta:
		tool = "C"
		name = "MinGW GCC"
		version = "DLL 2xx"
		pattern = "5589E5??????????????????????000000????????????????????00"
	strings:
		$1 = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_147_GCC__mingw32 {
	meta:
		tool = "C"
		name = "MinGW GCC"
		version = "4.6.1"
		pattern = "5589E583EC18C7042401000000FF15??????00E87CFDFFFF5589E583EC18C7042402000000FF15??????00E864FDFFFF5589E583EC08A1??????00C9FFE066905589E583EC08A1??????00C9FFE090905589E583EC18C7042400?0??00E8??????005285"
	strings:
		$1 = { 55 89 E5 83 EC 18 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 7C FD FF FF 55 89 E5 83 EC 18 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 64 FD FF FF 55 89 E5 83 EC 08 A1 ?? ?? ?? 00 C9 FF E0 66 90 55 89 E5 83 EC 08 A1 ?? ?? ?? 00 C9 FF E0 90 90 55 89 E5 83 EC 18 C7 04 24 00 ?0 ?? 00 E8 ?? ?? ?? 00 52 85 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_148_GCC__mingw32_x86_pe {
	meta:
		tool = "C"
		name = "MinGW GCC"
		version = "4.7.3"
		pattern = "83EC0CC705??????0000000000E8?E??000083C40CE986FCFFFF909090909090A1??????0085C074435589E583EC18C7042420?0??00FF15???1??00BA0000000083EC0485C07416C74424042E?0??00890424FF15???1??0083EC0889C285D27409C704"
	strings:
		$1 = { 83 EC 0C C7 05 ?? ?? ?? 00 00 00 00 00 E8 ?E ?? 00 00 83 C4 0C E9 86 FC FF FF 90 90 90 90 90 90 A1 ?? ?? ?? 00 85 C0 74 43 55 89 E5 83 EC 18 C7 04 24 20 ?0 ?? 00 FF 15 ?? ?1 ?? 00 BA 00 00 00 00 83 EC 04 85 C0 74 16 C7 44 24 04 2E ?0 ?? 00 89 04 24 FF 15 ?? ?1 ?? 00 83 EC 08 89 C2 85 D2 74 09 C7 04 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_149_GCC__mingw32_x86_pe__MSYS2 {
	meta:
		tool = "C"
		name = "MinGW GCC"
		version = "5.2.0"
		pattern = "83EC0CC705??????0000000000E8?E??000083C40CE976FCFFFF9090909090905589E557565383EC2C8B35???1??00C7042400?0??00FFD683EC0485C00F84BD00000089C3C7042400?0??00FF15???1??008B15???1??0083EC04A3??????00C7442404"
	strings:
		$1 = { 83 EC 0C C7 05 ?? ?? ?? 00 00 00 00 00 E8 ?E ?? 00 00 83 C4 0C E9 76 FC FF FF 90 90 90 90 90 90 55 89 E5 57 56 53 83 EC 2C 8B 35 ?? ?1 ?? 00 C7 04 24 00 ?0 ?? 00 FF D6 83 EC 04 85 C0 0F 84 BD 00 00 00 89 C3 C7 04 24 00 ?0 ?? 00 FF 15 ?? ?1 ?? 00 8B 15 ?? ?1 ?? 00 83 EC 04 A3 ?? ?? ?? 00 C7 44 24 04 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_150_GCC {
	meta:
		tool = "C"
		name = "GCC or similar"
		pattern = "5589E556"
	strings:
		$1 = { 55 89 E5 56 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_151_GCC {
	meta:
		tool = "C"
		name = "GCC or similar"
		pattern = "5589E557"
	strings:
		$1 = { 55 89 E5 57 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_152_GCC {
	meta:
		tool = "C"
		name = "GCC or similar"
		pattern = "5589E581EC"
	strings:
		$1 = { 55 89 E5 81 EC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_153_GCC {
	meta:
		tool = "C"
		name = "Dev-C++ GCC"
		version = "4"
		pattern = "5589E583EC0883C4F46A??A1??????00FFD0E8??FFFFFF"
	strings:
		$1 = { 55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 ?? ?? ?? 00 FF D0 E8 ?? FF FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_154_GCC {
	meta:
		tool = "C"
		name = "Dev-C++ GCC"
		version = "4.9.9.2"
		pattern = "5589E583EC08C7042401000000FF15??????00E8C8FEFFFF908DB426000000005589E583EC08C7042402000000FF15??????00E8A8FEFFFF908DB42600000000558B0D??????0089E55DFFE18D742600558B0D"
	strings:
		$1 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_155_GCC {
	meta:
		tool = "C"
		name = "Dev-C++ GCC"
		extra = "5"
		pattern = "5589E583EC146A??FF15??????00????????????????????????????00000000"
	strings:
		$1 = { 55 89 E5 83 EC 14 6A ?? FF 15 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_156_GCC {
	meta:
		tool = "C"
		name = "GCC"
		extra = "GCC-like"
		pattern = "5589E583EC"
	strings:
		$1 = { 55 89 E5 83 EC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_157_GCC {
	meta:
		tool = "C"
		name = "GCC or similar"
		pattern = "5589E58B4508A3????????B801000000"
	strings:
		$1 = { 55 89 E5 8B 45 08 A3 ?? ?? ?? ?? B8 01 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_158_GCC {
	meta:
		tool = "C"
		name = "GCC or similar"
		pattern = "565383EC148B??242483F?0174??8B44242889??2404894424088B442420890424E8"
	strings:
		$1 = { 56 53 83 EC 14 8B ?? 24 24 83 F? 01 74 ?? 8B 44 24 28 89 ?? 24 04 89 44 24 08 8B 44 24 20 89 04 24 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_159_GCC {
	meta:
		tool = "C"
		name = "GCC or similar"
		pattern = "83EC0CC7042402000000FF15????????E8????????8B0D"
	strings:
		$1 = { 83 EC 0C C7 04 24 02 00 00 00 FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 0D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_160_GCC {
	meta:
		tool = "C"
		name = "MinGW GCC"
		version = "3.x"
		pattern = "5589E583EC08C70424??000000FF15????????E8????????????????????????55"
	strings:
		$1 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_161_HotSoupProcessor__HSP {
	meta:
		tool = "C"
		name = "HotSoupProcessor"
		version = "3.1"
		source = "Generated based on AVG tests"
		pattern = "6A606830084200E821430000BF940000008BC7E8FDF5FFFF8965E88BF4893E56FF15F00042008B4E10890D884542008B4604A3944542008B56088915984542008B760C81E6FF7F000089358C45420083F902740C81CE0080000089358C454200C1E00803"
	strings:
		$1 = { 6A 60 68 30 08 42 00 E8 21 43 00 00 BF 94 00 00 00 8B C7 E8 FD F5 FF FF 89 65 E8 8B F4 89 3E 56 FF 15 F0 00 42 00 8B 4E 10 89 0D 88 45 42 00 8B 46 04 A3 94 45 42 00 8B 56 08 89 15 98 45 42 00 8B 76 0C 81 E6 FF 7F 00 00 89 35 8C 45 42 00 83 F9 02 74 0C 81 CE 00 80 00 00 89 35 8C 45 42 00 C1 E0 08 03 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_162_HotSoupProcessor__HSP {
	meta:
		tool = "C"
		name = "HotSoupProcessor"
		version = "3.2"
		extra = "Generated based on AVG tests"
		pattern = "6A6068???84200E8????0000BF940000008BC7E8??F?FFFF8965E88BF4893E56FF15?0??42008B4E10890D????42008B4604A3????42008B56088915????42008B760C81E6FF7F00008935????420083F902740C81CE008000008935????4200C1E00803"
	strings:
		$1 = { 6A 60 68 ?? ?8 42 00 E8 ?? ?? 00 00 BF 94 00 00 00 8B C7 E8 ?? F? FF FF 89 65 E8 8B F4 89 3E 56 FF 15 ?0 ?? 42 00 8B 4E 10 89 0D ?? ?? 42 00 8B 46 04 A3 ?? ?? 42 00 8B 56 08 89 15 ?? ?? 42 00 8B 76 0C 81 E6 FF 7F 00 00 89 35 ?? ?? 42 00 83 F9 02 74 0C 81 CE 00 80 00 00 89 35 ?? ?? 42 00 C1 E0 08 03 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_163_Intel_XE {
	meta:
		tool = "C"
		name = "Intel XE"
		version = "13"
		pattern = "E8????0000E9A4FEFFFF"
	strings:
		$1 = { E8 ?? ?? 00 00 E9 A4 FE FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_164_LCC {
	meta:
		tool = "C"
		name = "LCC or similar"
		pattern = "5589E553"
	strings:
		$1 = { 55 89 E5 53 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_165_LCC {
	meta:
		tool = "C"
		name = "LCC or similar"
		pattern = "5589E555"
	strings:
		$1 = { 55 89 E5 55 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_166_LCC {
	meta:
		tool = "C"
		name = "LCC"
		version = "1.x"
		pattern = "64A1????????5589E56AFF68????????689A1040??50"
	strings:
		$1 = { 64 A1 ?? ?? ?? ?? 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 ?? 50 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_167_LCC {
	meta:
		tool = "C"
		name = "LCC"
		version = "DLL"
		pattern = "5589E5535657837D0C017505E817??????FF7510FF750CFF7508A1"
	strings:
		$1 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 ?? ?? ?? FF 75 10 FF 75 0C FF 75 08 A1 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_168_MASM_TASM {
	meta:
		tool = "C"
		name = "MASM/TASM"
		pattern = "6A00E8??0?0000A3????4000???????0?0????000000????0??????0?????0?0???????0??0????0?000"
	strings:
		$1 = { 6A 00 E8 ?? 0? 00 00 A3 ?? ?? 40 00 ?? ?? ?? ?0 ?0 ?? ?? 00 00 00 ?? ?? 0? ?? ?? ?0 ?? ?? ?0 ?0 ?? ?? ?? ?0 ?? 0? ?? ?0 ?0 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_169_MASM_TASM {
	meta:
		tool = "C"
		name = "MASM/TASM"
		pattern = "C2??00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00"
	strings:
		$1 = { C2 ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_170_MASM_TASM {
	meta:
		tool = "C"
		name = "MASM/TASM"
		pattern = "CCFF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00"
	strings:
		$1 = { CC FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_171_MASM_TASM {
	meta:
		tool = "C"
		name = "MASM/TASM"
		pattern = "FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00FF25??????00"
	strings:
		$1 = { FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_172_MASM32 {
	meta:
		tool = "C"
		name = "MASM32"
		pattern = "6A??680030400068??3040006A00E8070000006A00E806000000FF250820"
	strings:
		$1 = { 6A ?? 68 00 30 40 00 68 ?? 30 40 00 6A 00 E8 07 00 00 00 6A 00 E8 06 00 00 00 FF 25 08 20 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_173_Lahey_Fortran_90 {
	meta:
		tool = "C"
		name = "Lahey Fortran 90"
		version = "2001"
		pattern = "558BEC8B45??83E8??72??74??4874??4874??EB??68????????E8????????59E8"
	strings:
		$1 = { 55 8B EC 8B 45 ?? 83 E8 ?? 72 ?? 74 ?? 48 74 ?? 48 74 ?? EB ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_174_MetaWare_High_C___Phar_Lap_DOS_Extender_1983_89 {
	meta:
		tool = "C"
		name = "MetaWare High C"
		pattern = "B8????8ED8B8????CD21A3????3C037D??B409"
	strings:
		$1 = { B8 ?? ?? 8E D8 B8 ?? ?? CD 21 A3 ?? ?? 3C 03 7D ?? B4 09 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_175_MetaWare_High_C_Run_Time_Library___Phar_Lap_DOS_Extender_1983_89 {
	meta:
		tool = "C"
		name = "MetaWare High C"
		pattern = "B8????50B8????50CB"
	strings:
		$1 = { B8 ?? ?? 50 B8 ?? ?? 50 CB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_176_Metrowerks_CodeWarrior {
	meta:
		tool = "C"
		name = "Metrowerks CodeWarrior"
		version = "2.0 console"
		pattern = "5589E555B8FFFFFFFF505068????????64FF35000000006489250000000068????????E8????????????????????????E8????0000E8????0000E8"
	strings:
		$1 = { 55 89 E5 55 B8 FF FF FF FF 50 50 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_177_Metrowerks_CodeWarrior {
	meta:
		tool = "C"
		name = "Metrowerks CodeWarrior"
		version = "2.0 DLL"
		pattern = "5589E55356578B750C8B5D1083FE01740583FE0275125356FF7508E86EFFFFFF09C0750431C0EB215356FF7508E8????????89C709F6740583FE03750A5356FF7508E847FFFFFF89F88D65F45F5E5B5DC20C00C9"
	strings:
		$1 = { 55 89 E5 53 56 57 8B 75 0C 8B 5D 10 83 FE 01 74 05 83 FE 02 75 12 53 56 FF 75 08 E8 6E FF FF FF 09 C0 75 04 31 C0 EB 21 53 56 FF 75 08 E8 ?? ?? ?? ?? 89 C7 09 F6 74 05 83 FE 03 75 0A 53 56 FF 75 08 E8 47 FF FF FF 89 F8 8D 65 F4 5F 5E 5B 5D C2 0C 00 C9 }
	condition:
		for any of them : ( $ at pe.entry_point )
})x86_pe_compiler";
