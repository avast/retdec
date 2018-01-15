/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/compiler/compiler_10.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PeCompiler_10 =
R"x86_pe_compiler(rule rule_1__NET {
	meta:
		tool = "C"
		name = ".NET"
		version = "DLL"
		pattern = "00000000000000005F436F72446C6C4D61696E006D73636F7265652E646C6C0000??0000FF25"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 44 6C 6C 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 ?? 00 00 FF 25 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_2__NET {
	meta:
		tool = "C"
		name = ".NET"
		version = "EXE"
		pattern = "00000000000000005F436F724578654D61696E006D73636F7265652E646C6C0000000000FF25"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 00 00 00 FF 25 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_3_ASM {
	meta:
		tool = "C"
		name = "ASM"
		extra = "or similar"
		pattern = "6A00E8????????A3????????E8????????50E8"
	strings:
		$1 = { 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_4_ASM {
	meta:
		tool = "C"
		name = "ASM"
		extra = "or similar"
		pattern = "6A00E8????????A3????????E8????????6A0A506A00FF35????????E8????000050E8????????CC"
	strings:
		$1 = { 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 0A 50 6A 00 FF 35 ?? ?? ?? ?? E8 ?? ?? 00 00 50 E8 ?? ?? ?? ?? CC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_5_ASM {
	meta:
		tool = "C"
		name = "ASM"
		extra = "ASM-like"
		pattern = "6A00E8????????A3????????E8????????A3????????68"
	strings:
		$1 = { 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_AutoIt_3300_x86
{
	meta:
		name = "Aut2Exe"
		version = "3.3.0.0"
		language = "AutoIt"
		bytecode = true
		source = "Made by RetDec Team"
		pattern = "E8C4AF0000E979FEFFFF8BFF558BEC8BC18B4D08C70088DA47008B09836008008948045DC208008BFF558BEC538B5D08568BF1C70688DA47008B430889460885C08B430457743185C0742750E8EFD3FFFF8BF84757E810D3FFFF595989460485C07418FF"
	strings:
		$1 = { E8 C4 AF 00 00 E9 79 FE FF FF 8B FF 55 8B EC 8B C1 8B 4D 08 C7 00 88 DA 47 00 8B 09 83 60 08 00 89 48 04 5D C2 08 00 8B FF 55 8B EC 53 8B 5D 08 56 8B F1 C7 06 88 DA 47 00 8B 43 08 89 46 08 85 C0 8B 43 04 57 74 31 85 C0 74 27 50 E8 EF D3 FF FF 8B F8 47 57 E8 10 D3 FF FF 59 59 89 46 04 85 C0 74 18 FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_AutoIt_338x_x86 {
	meta:
		name = "Aut2Exe"
		version = "3.3.8.x"
		language = "AutoIt"
		bytecode = true
		source = "Made by RetDec Team"
		pattern = "E816900000E989FEFFFFCCCCCCCCCC558BEC57568B750C8B4D108B7D088BC18BD103C63BFE76083BF80F82A001000081F980000000721C833D24974A00007413575683E70F83E60F3BFE5E5F7505E9DD030000F7C7030000007514C1E90283E20383F908"
	strings:
		$1 = { E8 16 90 00 00 E9 89 FE FF FF CC CC CC CC CC 55 8B EC 57 56 8B 75 0C 8B 4D 10 8B 7D 08 8B C1 8B D1 03 C6 3B FE 76 08 3B F8 0F 82 A0 01 00 00 81 F9 80 00 00 00 72 1C 83 3D 24 97 4A 00 00 74 13 57 56 83 E7 0F 83 E6 0F 3B FE 5E 5F 75 05 E9 DD 03 00 00 F7 C7 03 00 00 00 75 14 C1 E9 02 83 E2 03 83 F9 08 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_AutoIt_33100_x86 {
	meta:
		name = "Aut2Exe"
		version = "3.3.10.0"
		language = "AutoIt"
		bytecode = true
		source = "Made by RetDec Team"
		pattern = "E88ACF0000E97FFEFFFFCCCC57568B7424108B4C24148B7C240C8BC18BD103C63BFE76083BF80F82680300000FBA2558114C00017307F3A4E91703000081F9800000000F82CE0100008BC733C6A90F000000750E0FBA2570B34B00010F82DA0400000FBA"
	strings:
		$1 = { E8 8A CF 00 00 E9 7F FE FF FF CC CC 57 56 8B 74 24 10 8B 4C 24 14 8B 7C 24 0C 8B C1 8B D1 03 C6 3B FE 76 08 3B F8 0F 82 68 03 00 00 0F BA 25 58 11 4C 00 01 73 07 F3 A4 E9 17 03 00 00 81 F9 80 00 00 00 0F 82 CE 01 00 00 8B C7 33 C6 A9 0F 00 00 00 75 0E 0F BA 25 70 B3 4B 00 01 0F 82 DA 04 00 00 0F BA }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_AutoIt_33102_x86 {
	meta:
		name = "Aut2Exe"
		version = "3.3.10.2"
		language = "AutoIt"
		bytecode = true
		source = "Made by RetDec Team"
		pattern = "E897CF0000E97FFEFFFFCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC57568B7424108B4C24148B7C240C8BC18BD103C63BFE76083BF80F82680300000FBA2558014C00017307F3A4E91703000081F9800000000F82CE0100008BC733C6A90F000000750E0FBA25"
	strings:
		$1 = { E8 97 CF 00 00 E9 7F FE FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 57 56 8B 74 24 10 8B 4C 24 14 8B 7C 24 0C 8B C1 8B D1 03 C6 3B FE 76 08 3B F8 0F 82 68 03 00 00 0F BA 25 58 01 4C 00 01 73 07 F3 A4 E9 17 03 00 00 81 F9 80 00 00 00 0F 82 CE 01 00 00 8B C7 33 C6 A9 0F 00 00 00 75 0E 0F BA 25 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_AutoIt_33140_x86 {
	meta:
		name = "Aut2Exe"
		version = "3.3.14.0"
		language = "AutoIt"
		bytecode = true
		source = "Made by RetDec Team"
		pattern = "E8B5D00000E97FFEFFFFCCCCCCCCCCCCCCCCCC57568B7424108B4C24148B7C240C8BC18BD103C63BFE76083BF80F82680300000FBA25FC314C00017307F3A4E91703000081F9800000000F82CE0100008BC733C6A90F000000750E0FBA2524E34B00010F"
	strings:
		$1 = { E8 B5 D0 00 00 E9 7F FE FF FF CC CC CC CC CC CC CC CC CC 57 56 8B 74 24 10 8B 4C 24 14 8B 7C 24 0C 8B C1 8B D1 03 C6 3B FE 76 08 3B F8 0F 82 68 03 00 00 0F BA 25 FC 31 4C 00 01 73 07 F3 A4 E9 17 03 00 00 81 F9 80 00 00 00 0F 82 CE 01 00 00 8B C7 33 C6 A9 0F 00 00 00 75 0E 0F BA 25 24 E3 4B 00 01 0F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_AutoIt_33142_x86 {
	meta:
		name = "Aut2Exe"
		version = "3.3.14.2"
		language = "AutoIt"
		bytecode = true
		source = "Made by RetDec Team"
		pattern = "E8B8D00000E97FFEFFFFCCCCCCCCCCCCCCCCCCCCCCCC57568B7424108B4C24148B7C240C8BC18BD103C63BFE76083BF80F82680300000FBA25FC314C00017307F3A4E91703000081F9800000000F82CE0100008BC733C6A90F000000750E0FBA2524E34B"
	strings:
		$1 = { E8 B8 D0 00 00 E9 7F FE FF FF CC CC CC CC CC CC CC CC CC CC CC CC 57 56 8B 74 24 10 8B 4C 24 14 8B 7C 24 0C 8B C1 8B D1 03 C6 3B FE 76 08 3B F8 0F 82 68 03 00 00 0F BA 25 FC 31 4C 00 01 73 07 F3 A4 E9 17 03 00 00 81 F9 80 00 00 00 0F 82 CE 01 00 00 8B C7 33 C6 A9 0F 00 00 00 75 0E 0F BA 25 24 E3 4B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_AutoIt_33xx_x64 {
	meta:
		name = "Aut2Exe"
		version = "3.3.x.x"
		language = "AutoIt"
		bytecode = true
		source = "Made by RetDec Team"
		pattern = "4883EC28E8????00004883C428E9??FEFFFFCCCC"
	strings:
		$1 = { 48 83 EC 28 E8 ?? ?? 00 00 48 83 C4 28 E9 ?? FE FF FF CC CC }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_PE_UNSPECIFIED
{
	meta:
		name = "Aut2Exe"
		version = "2.64"
		language = "AutoIt"
		bytecode = true
		source = "Made by RetDec Team"
		pattern = "6A606808FD4000E8733D0000BF940000008BC7E84FF6FFFF8965E88BF4893E56FF1558F140008B4E10890D6C3544008B4604A3783544008B560889157C3544008B760C81E6FF7F000089357035440083F902740C81CE00800000893570354400C1E00803"
	strings:
		$1 = { 6A 60 68 08 FD 40 00 E8 73 3D 00 00 BF 94 00 00 00 8B C7 E8 4F F6 FF FF 89 65 E8 8B F4 89 3E 56 FF 15 58 F1 40 00 8B 4E 10 89 0D 6C 35 44 00 8B 46 04 A3 78 35 44 00 8B 56 08 89 15 7C 35 44 00 8B 76 0C 81 E6 FF 7F 00 00 89 35 70 35 44 00 83 F9 02 74 0C 81 CE 00 80 00 00 89 35 70 35 44 00 C1 E0 08 03 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_gc_x64_1
{
	meta:
		tool = "C"
		name = "gc"
		language = "Go"
		pattern = "488D742408488B3C24488D0510000000FFE0????????????????????????????488D05?9C?FFFFFFE0??????????????51488B01488B7110488B490865488B3C2530000000C74768000000004881EC8000000083F9047E1183F9107E02CD034889E7FCF348A54889E6488B0E488B56084C8B46104C8B4E18"
		strings:
		$1 = { 48 8D 74 24 08 48 8B 3C 24 48 8D 05 10 00 00 00 FF E0 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 05 ?9 C? FF FF FF E0 ?? ?? ?? ?? ?? ?? ?? 51 48 8B 01 48 8B 71 10 48 8B 49 08 65 48 8B 3C 25 30 00 00 00 C7 47 68 00 00 00 00 48 81 EC 80 00 00 00 83 F9 04 7E 11 83 F9 10 7E 02 CD 03 48 89 E7 FC F3 48 A5 48 89 E6 48 8B 0E 48 8B 56 08 4C 8B 46 10 4C 8B 4E 18 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_gc_x64_2_mingwbuild
{
	meta:
		tool = "C"
		name = "gc"
		language = "Go"
		pattern = "4883EC28488B05?5????00C70000000000E8?A????00E895FCFFFF90904883C428C39090909090909090909090909090554889E55DC3662E0F1F840000000000554889E54883EC2048833D?0????00007430488D0DA7?A??00FF15??????004885C0742F"
		strings:
		$1 = { 48 83 EC 28 48 8B 05 ?5 ?? ?? 00 C7 00 00 00 00 00 E8 ?A ?? ?? 00 E8 95 FC FF FF 90 90 48 83 C4 28 C3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 55 48 89 E5 5D C3 66 2E 0F 1F 84 00 00 00 00 00 55 48 89 E5 48 83 EC 20 48 83 3D ?0 ?? ?? 00 00 74 30 48 8D 0D A7 ?A ?? 00 FF 15 ?? ?? ?? 00 48 85 C0 74 2F }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_gc_x86_1
{
	meta:
		tool = "C"
		name = "gc"
		language = "Go"
		pattern = "??????????240C8D5C241089442404895C2408C70424FFFFFFFFE901000000??E9?BD?FFFF??????????????????????8B5C240464C705340000000000000089E58B4B0489C8C1E00229C489E78B7308FCF3A5FF1389EC8B5C240489430C895310648B0534000000894314C3????????83EC18C70424F4FF"
	strings:
		$1 = { ?? ?? ?? ?? ?? 24 0C 8D 5C 24 10 89 44 24 04 89 5C 24 08 C7 04 24 FF FF FF FF E9 01 00 00 00 ?? E9 ?B D? FF FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B 5C 24 04 64 C7 05 34 00 00 00 00 00 00 00 89 E5 8B 4B 04 89 C8 C1 E0 02 29 C4 89 E7 8B 73 08 FC F3 A5 FF 13 89 EC 8B 5C 24 04 89 43 0C 89 53 10 64 8B 05 34 00 00 00 89 43 14 C3 ?? ?? ?? ?? 83 EC 18 C7 04 24 F4 FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_gc_x86_2_mingwbuild
{
	meta:
		tool = "C"
		name = "gc"
		language = "Go"
		pattern = "83EC0CC705??????0?00000000E8?E????0083C40CE9?6FCFFFF909090909090??????????????????????????????C7042400"
	strings:
		$1 = { 83 EC 0C C7 05 ?? ?? ?? 0? 00 00 00 00 E8 ?E ?? ?? 00 83 C4 0C E9 ?6 FC FF FF 90 90 90 90 90 90 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 04 24 00}
	condition:
		for any of them : ( $ at pe.entry_point )
})x86_pe_compiler";
