/*
 * YARA rules for x86 PE installer detection.
 * Copyright (c) 2017 Avast Software, licensed under the MIT license
 */

import "pe"

rule advanced_installer
{
	meta:
		tool = "I"
		name = "Advanced Installer"
		strength = "high"
	strings:
		$s00 = "ADVINSTSFX"
		$s01 = "Software\\Caphyon\\Advanced Installer\\"
		$s02 = "Detected working Internet connection." wide
		$s03 = "<< Advanced Installer (x86) Log >>" wide
		$s04 = "=====================End of Log=====================" wide
		$s05 = "REINSTALL=ALL REINSTALLMODE=vomus" wide
	condition:
		pe.number_of_sections == 5 and
		all of them
}

rule arc_sfx {
	meta:
		tool = "I"
		name = "ARC SFX"
		pattern = "8CC88CDB8ED88EC089??????2BC3A3????89??????BE????B9????BF????BA????FCAC32C28AD8"
	strings:
		$1 = { 8C C8 8C DB 8E D8 8E C0 89 ?? ?? ?? 2B C3 A3 ?? ?? 89 ?? ?? ?? BE ?? ?? B9 ?? ?? BF ?? ?? BA ?? ?? FC AC 32 C2 8A D8 }
	condition:
		$1 at pe.entry_point
}

private rule astrum_strings {
	strings:
		$1 = "Astrum Installer package #"
		$2 = "AstrumInstaller"
	condition:
		all of them
}

rule astrum_uv_01 {
	meta:
		tool = "I"
		name = "Astrum"
		pattern = "558BEC83EC0C535657BE28774700FF75088BCEE8B13700008BCEE87E0B00008BCEE86413000085C07D1533DB8BCE"
	strings:
		$fixed1 = { 55 8B EC 83 EC 0C 53 56 57 }
		$fixed2 = { E8 ?? ?? 00 00 8B CE E8 ?? ?? 00 00 8B CE E8 ?? ?? 00 00 85 C0 7D 15 33 DB 8B CE }
		$s1 = { BE 28 77 47 00 FF 75 08 8B CE }
		$s2 = { FF 15 ?? ?? ?? ?? FF 75 08 BE 18 88 47 00 8B CE }
	condition:
		all of ($fixed*) and
		1 of ($s*) and
		astrum_strings
}

rule astrum_uv_02 {
	meta:
		tool = "I"
		name = "Astrum"
		pattern = "6A4033C0598DBD????????F3AB66ABAA"
	strings:
		$1 = { 6A 40 33 C0 59 8D BD ?? ?? ?? ?? F3 AB 66 AB AA }
	condition:
		$1 and astrum_strings
}

rule create_install {
	meta:
		tool = "I"
		name = "CreateInstall"
	strings:
		$s01 = "Gentee Launcher"
	condition:
		pe.sections[pe.number_of_sections - 2].name == ".gentee" and
		pe.overlay.size != 0 and
		pe.resources[pe.number_of_resources-1].type == pe.RESOURCE_TYPE_MANIFEST and
		pe.resources[pe.number_of_resources-2].name_string == "S\x00E\x00T\x00U\x00P\x00_\x00I\x00C\x00O\x00N\x00" and   // "SETUP_ICON"
		pe.resources[pe.number_of_resources-3].name_string == "S\x00E\x00T\x00U\x00P\x00_\x00T\x00E\x00M\x00P\x00" and   // "SETUP_TEMP"
		all of them
}

rule fly_studio {
	meta:
		tool = "I"
		name = "FlyStudio"
	condition:
		pe.overlay.size > 16 and
		uint32(pe.overlay.offset) == 0x829ab7a5 and
		uint32(pe.overlay.offset + 4) == 0x04 and
		uint32(pe.overlay.offset + pe.overlay.size - 4) == 0x829ab7a5 and
		pe.overlay.offset == filesize - uint32(pe.overlay.offset + pe.overlay.size - 8) - 0x08
}

rule gentee_installer {
	meta:
		tool = "I"
		name = "GenteeInstaller"
	strings:
		$s01 = "Gentee installer"
	condition:
		pe.overlay.size > 16 and
		uint32(0x3F0) == pe.overlay.offset and
		(uint32(0x3F4) + uint32(0x3F8)) <= pe.overlay.size and
		(uint32(pe.overlay.offset) == uint32(0x3F8)) and
		$s01 at pe.sections[2].raw_data_offset
}

rule ghost_installer {
	meta:
		tool = "I"
		name = "GhostInstaller"
	strings:
		$s01 = "GIPENDMSCF"
	condition:
		pe.number_of_sections == 3 and
		pe.sections[0].name == "UPX0" and
		pe.sections[1].name == "UPX1" and
		pe.overlay.offset != 0 and
		pe.overlay.size != 0 and
		uint32(pe.overlay.offset) == 0x4643534D and
		pe.resources[4].type == pe.RESOURCE_TYPE_DIALOG and
		pe.resources[4].name_string == "D\x00L\x00G\x00_\x00I\x00N\x00P\x00U\x00T\x00Q\x00U\x00E\x00R\x00Y\x00S\x00T\x00R\x00" and
		pe.resources[5].type == pe.RESOURCE_TYPE_DIALOG and
  		pe.resources[5].name_string == "D\x00L\x00G\x00_\x00P\x00R\x00E\x00S\x00E\x00T\x00U\x00P\x00" and
		all of them
}

rule install_creator {
	meta:
		tool = "I"
		name = "InstallCreator"
	strings:
		$s01 = { 77 77 67 54 29 48 }
	condition:
		pe.number_of_sections == 3 and
		pe.sections[0].name == "UPX0" and
		pe.sections[1].name == "UPX1" and
		pe.overlay.offset != 0 and
		pe.overlay.size != 0 and
		$s01 at pe.overlay.offset
}

rule ms_setup_installer_8x
{
	meta:
		tool = "I"
		name = "Microsoft Setup"
		version = "8.x"
		source = "Made by RetDec Team"
		hash = "fb7363e3a2e114f57f34b377b984ecf3e4805398279f318d7cc394e1bfbbc561"
	strings:
		$s01 = "MsiInstallProduct returned '%d'"
		$s02 = "AssemblyCheck: Error creating assembly name object"
		$s03 = "Status of package '%s' after install is 'InstallNeeded'"
		$s04 = "Running external check, and writing to log file '%s'" wide
		$s05 = "Using MsiInstallProduct with package path '%s' and command line '%s'" wide
	condition:
		pe.number_of_sections == 3 and
		for any resource in pe.resources : (resource.name_string == "S\x00E\x00T\x00U\x00P\x00C\x00F\x00G\x00") and
		all of them
}

rule quick_batch_compiler_105 {
	meta:
		tool = "I"
		name = "Quick Batch File Compiler"
		version = "1.0.0.0 - 1.0.5.5"
	strings:
		$h01 = { 31 2E 32 34 00 55 50 58 21 0C 09  }  // UPX signature
		$h02 = { 2E 66 FE FF 04 10 40 00 03 07 42 6F 6F 6C 65 61 6E 01 00 04 15 FF DD F6 FF 05 46 61 6C 73 65 04 54 72 75 65 8D 0D 2C 11 01 07 49 6E 74 65 67 65 }  // The begin of the UPX section
		$s01 = "OnAskForKey"
		$s02 = "OFTWARE\\Borland\\Delphi\\RTL"
	condition:
		pe.overlay.offset >= 0xD000 and
		uint32(pe.overlay.offset + pe.overlay.size - 4) == pe.overlay.size and
		pe.number_of_sections == 3 and
		pe.sections[0].name == "UPX0" and
		pe.sections[1].name == "UPX1" and
		pe.timestamp == 0x2A425E19 and
		all of them
}

rule quick_batch_compiler_106 {
	meta:
		tool = "I"
		name = "Quick Batch File Compiler"
		version = "1.0.6.0+"
	strings:
		$h01 = { 55 8B EC B9 07 00 00 00 6A 00 6A 00 49 75 F9  }  // Entry point code
		$s01 = "SOFTWARE\\Borland\\Delphi\\RTL"
		$s02 = "Compressed file is corrupt"
		$s03 = "Quick Batch File Compiler"
	condition:
		pe.overlay.offset >= 0x23000 and
		uint32(pe.overlay.offset + pe.overlay.size - 4) == pe.overlay.size and
		pe.number_of_sections == 8 and
		pe.sections[0].name == "CODE" and
		pe.sections[1].name == "DATA" and
		pe.timestamp == 0x2A425E19 and
		$h01 at pe.entry_point and
		all of them
}

rule quick_batch_compiler_2xx {
	meta:
		tool = "I"
		name = "Quick Batch File Compiler"
		version = "2.0.0.0 - 2.1.7.0"
	strings:
		$h01 = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9  }  // Entry point code
		$h02 = { FF FF FF FF 10 00 00 00 46 69 6C 65 20 69 73 20 63 6F 72 72 75 70 74 2E 00 00 00 00 }                 // Delphi: "File is corrupt."
		$h03 = { FF FF FF FF 1A 00 00 00 43 6F 6D 70 72 65 73 73 65 64 20 66 69 6C 65 20 69 73 20 63 6F 72 72 75 70 }  // Delphi: "Compressed file is corrupt"
		$h04 = { FF FF FF FF 19 00 00 00 51 75 69 63 6B 20 42 61 74 63 68 20 46 69 6C 65 20 43 6F 6D 70 69 6C 65 72 }  // Delphi: "Quick Batch File Compiler"
		$s05 = "TMultiReadExclusiveWriteSynchronizer"
	condition:
		pe.overlay.offset >= 0x1F000 and
		uint32(pe.overlay.offset + pe.overlay.size - 4) == pe.overlay.size and
		pe.number_of_sections == 8 and
		pe.sections[0].name == "CODE" and
		pe.sections[1].name == "DATA" and
		pe.timestamp == 0x2A425E19 and
		$h01 at pe.entry_point and
		all of them
}

rule quick_batch_compiler_300 {
	meta:
		tool = "I"
		name = "Quick Batch File Compiler"
		version = "3.0.0.0 - 3.1.6.0"
	strings:
		$h01 = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9  }  // Entry point code
		$h02 = { FF FF FF FF 1A 00 00 00 43 6F 6D 70 72 65 73 73 65 64 20 66 69 6C 65 20 69 73 20 63 6F 72 72 75 70 }  // Delphi: "Compressed file is corrupt"
		$s03 = "TResourceStreamSV"
		$s04 = "PADDINGXXPADDING"
	condition:
		0x5000 <= filesize and filesize < 300KB and
		pe.number_of_sections == 8 and
		pe.sections[0].name == "CODE" and
		pe.sections[1].name == "DATA" and
		pe.timestamp == 0x2A425E19 and
		$h01 at pe.entry_point and
		@s04 > pe.sections[7].raw_data_offset and
		all of them
}

rule quick_batch_compiler_320 {
	meta:
		tool = "I"
		name = "Quick Batch File Compiler"
		version = "3.2.0.0"
	strings:
		$h01 = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9  }  // Entry point code
		$h02 = { FF FF FF FF 19 00 00 00 51 75 69 63 6B 20 42 61 74 63 68 20 46 69 6C 65 20 43 6F 6D 70 69 6C 65 72 00 00 00 }  // Delphi: "Quick Batch File Compiler"
		$h03 = { FF FF FF FF 0F 00 00 00 63 6F 6D 6D 61 6E 64 2E 63 6F 6D 20 2F 63 20 00 }                                      // Delphi: "command.com /c"
		$h04 = { 50 41 44 44 49 4E 47 58 58 50 41 44 44 49 4E 47 }  // "PADDINGXXPADDING"
		$h05 = { 63 6D 64 6C 6E 00 00 00 } // "cmdln\0\0\0"
	condition:
		0x5000 <= filesize and filesize < 300KB and
		pe.number_of_sections == 8 and
		pe.sections[0].name == "CODE" and
		pe.sections[1].name == "DATA" and
		pe.timestamp == 0x2A425E19 and
		$h01 at pe.entry_point and
		@h04 > pe.sections[7].raw_data_offset and
		all of them
}

rule quick_batch_compiler_321 {
	meta:
		tool = "I"
		name = "Quick Batch File Compiler"
		version = "3.2.1.0+"
	strings:
		$res_name01 = "RTFM" wide
		$res_name02 = "SCRIPT" wide
		$h01 = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9  }    // Entry point code
		$h02 = { FF FF FF FF 57 00 00 00 46 61 73 74 4D 4D 20 42 6F 72 6C 61 6E 64 20 45 64 69 74 69 6F 6E 20 A9 20 }  // Delphi: "FastMM Borland Edition (c) 2004"
		$h03 = { 50 41 44 44 49 4E 47 58 58 50 41 44 44 49 4E 47 }  // "PADDINGXXPADDING"
		$h04 = { 63 6D 64 6C 6E 00 00 00 } // "cmdln\0\0\0"
	condition:
		0x5000 <= filesize and filesize < 300KB and
		pe.number_of_sections == 9 and
		pe.sections[0].name == ".text" and
		pe.sections[1].name == ".itext" and
		$h01 at pe.entry_point and
		@h03 > pe.sections[7].raw_data_offset and
		any of ($res_name*) and
		all of ($h*)
}

rule quick_batch_compiler_4xx {
	meta:
		tool = "I"
		name = "Quick Batch File Compiler"
		version = "4.0.0.0+"
	strings:
		$h01 = { FF FF FF FF 3A 00 00 00 46 61 73 74 4D 4D 20 45 6D 62 61 72 63 61 64 65 72 6F 20 45 64 69 74 69 6F }  // Delphi: "FastMM Embarcadero Edition (c) 2004"
		$h02 = { FF FF FF FF 18 00 00 00 78 66 74 6A 73 72 6A 73 75 79 68 65 77 33 35 33 79 34 35 79 33 65 34 72 00 }  // Delphi: "xftjsrjsuyhew353y45y3e4r"
		$s03 = "In order to correctly identify malware while avoiding false positives, antivirus manufacturers shalldetect the presence of Quick Batch File Compiler label" wide
		$s04 = "PADDINGXXPADDING"
		$s05 = "QUICKBFC" wide
	condition:
		pe.number_of_sections >= 8 and
		pe.sections[0].name == ".text" and
		pe.timestamp != 0x2A425E19 and
		@s03 > pe.sections[7].raw_data_offset and
		all of them
}

rule quick_batch_compiler_5xx {
	meta:
		tool = "I"
		name = "Quick Batch File Compiler"
		version = "5.0.0.0+"
	strings:
		$s01 = "compiler.environment"
		$s02 = "In order to correctly identify malware while avoiding false positives, antivirus manufacturers shalldetect the presence of Quick Batch File Compiler label" wide
		$s03 = "Encrypted user script: Resource Name: SCRIPT, Resource Type: RC DATA" wide
		$s04 = "QUICKBFC" wide
	condition:
		pe.number_of_sections >= 8 and
		pe.sections[0].name == ".text" and
		pe.timestamp != 0x2A425E19 and
		@s03 > pe.sections[7].raw_data_offset and
		all of them
}

rule kgb_sfx {
	meta:
		tool = "I"
		name = "KGB SFX"
		pattern = "60BE00A046008DBE0070F9FF5783CDFFEB109090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73"
	strings:
		$1 = { 60 BE 00 A0 46 00 8D BE 00 70 F9 FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }
	condition:
		$1 at pe.entry_point
}

rule gsfx {
	meta:
		tool = "I"
		name = "GSFX"
		pattern = "47534658"
	strings:
		$1 = { 47 53 46 58 }
	condition:
		$1 at pe.entry_point
}

rule cipherwall_sfx_15_console {
	meta:
		tool = "I"
		name = "CipherWall SFX"
		version = "1.5"
		extra = "console version"
		pattern = "9061BE001042008DBE0000FEFFC787C02002000B6E5B9B5783CDFFEB0E909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73EF75098B1E83EEFC11DB73E431C983E803720DC1E0088A064683F0FF747489C501DB75078B1E83EEFC11DB11C901DB75078B1E83EEFC11DB11C975204101DB75078B1E83EEFC11DB11C901DB73EF75098B1E83EEFC11DB73E483C10281FD"
	strings:
		$1 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD }
	condition:
		$1 at pe.entry_point
}

rule cipherwall_sfx_15_gui {
	meta:
		tool = "I"
		name = "CipherWall SFX"
		version = "1.5"
		extra = "GUI version"
		pattern = "9061BE001042008DBE0000FEFFC787C0200200F989C76A5783CDFFEB0E909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB73EF75098B1E83EEFC11DB73E431C983E803720DC1E0088A064683F0FF747489C501DB75078B1E83EEFC11DB11C901DB75078B1E83EEFC11DB11C975204101DB75078B1E83EEFC11DB11C901DB73EF75098B1E83EEFC11DB73E483C10281FD"
	strings:
		$1 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD }
	condition:
		$1 at pe.entry_point
}

rule gp_install_50332 {
	meta:
		tool = "I"
		name = "GP-Install"
		version = "5.0.3.32"
		pattern = "558BEC33C951515151515151535657B8C41C4100E86B3EFFFF33C055687620410064FF30648920BAA047410033C0E8310AFFFF33D2A1A0"
	strings:
		$1 = { 55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 B8 C4 1C 41 00 E8 6B 3E FF FF 33 C0 55 68 76 20 41 00 64 FF 30 64 89 20 BA A0 47 41 00 33 C0 E8 31 0A FF FF 33 D2 A1 A0 }
	condition:
		$1 at pe.entry_point
}

rule createinstall {
	meta:
		tool = "I"
		name = "CreateInstall"
		pattern = "558BEC81EC200200005356576A00FF15186140006800704000894508FF151461400085C074276A00A10020400050FF153C6140008BF06A0656FF15386140006A0356FF1538614000E93603000068027F"
	strings:
		$1 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F }
	condition:
		$1 at pe.entry_point
}

rule createinstall_2000_35 {
	meta:
		tool = "I"
		name = "CreateInstall"
		version = "2003.3.5"
		pattern = "81EC0C0400005356575568605040006A016A00FF15D88040008BF0FF15D48040003DB7000000750F56FF15B88040006A02FF15A480400033DBE8F2FEFFFF68027F0000891D9474400053891D98744000"
	strings:
		$1 = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 }
	condition:
		$1 at pe.entry_point
}

rule exemplar_installer {
	meta:
		tool = "I"
		name = "Exemplar Installer"
		pattern = "558BEC83EC??535657FF15????????8B1D????????8BF085F675??6A??FFD38A068B3D????????3C??75??56FFD7"
	strings:
		$1 = { 55 8B EC 83 EC ?? 53 56 57 FF 15 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8B F0 85 F6 75 ?? 6A ?? FF D3 8A 06 8B 3D ?? ?? ?? ?? 3C ?? 75 ?? 56 FF D7 }
	condition:
		$1 at pe.entry_point
}

rule pyinstaller_27
{
	meta:
		tool = "I"
		name = "PyInstaller"
		version = "2.7"
		strength = "high"
	strings:
		$s00 = "Cannot GetProcAddress for PySys_SetObject"
		$s01 = "Error coping %s"
		$s02 = "Error loading Python DLL: %s (error code %d)"
		$s03 = "PYTHONHOME"
	condition:
		pe.number_of_resources > 0 and
		@s00 < pe.sections[2].raw_data_offset and
		all of them
}

private rule pyinstaller_3x_strings
{
	strings:
		$s00 = "Error loading Python DLL '%s'."
		$s01 = "Cannot open self %s or archive %s"
		$s02 = "Cannot open PyInstaller archive from executable (%s) or external archive (%s)"
		$s10 = /PyInstalle(m|r): FormatMessageW failed\./
		$s11 = /PyInstalle(m|r): pyi_win32_utils_to_utf8 failed\./
	condition:
		pe.number_of_sections > 0 and
		any of ($s0*) and
		all of ($s1*)
}

private rule pyinstaller_3x_overlay
{
	strings:
		$s01 = { 4D 45 49 0C 0B 0A 0B 0E }      // PyInstaller magic number
		$s02 = /PYZ\-\d\d\.pyz/
		$s03 = /python3\d{1,2}\.dll/
	condition:
		pe.overlay.offset > 0 and
		@s02 > pe.overlay.offset and
		@s03 > pe.overlay.offset and
		all of them
}

rule pyinstaller_3x
{
	meta:
		tool = "I"
		name = "PyInstaller"
		version = "3.x"
		strength = "high"
	condition:
		pyinstaller_3x_overlay and
		pyinstaller_3x_strings
}

rule pyinstaller_3x_empty
{
	meta:
		tool = "I"
		name = "PyInstaller (no data)"
		version = "3.x"
		strength = "high"
	condition:
		pe.overlay.size == 0 and
		pyinstaller_3x_strings
}

rule pyinstaller_3x_corrupt
{
	meta:
		tool = "I"
		name = "PyInstaller (corrupt)"
		version = "3.x"
		strength = "high"
	condition:
		pe.overlay.size > 0 and
		pyinstaller_3x_strings and
		not pyinstaller_3x_overlay
}

rule installanywhere_61 {
	meta:
		tool = "I"
		name = "InstallAnywhere"
		version = "6.1"
		pattern = "60BE00A042008DBE0070FDFF5783CDFFEB109090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB7507"
	strings:
		$1 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }
	condition:
		$1 at pe.entry_point
}

rule installshield_uv_01 {
	meta:
		tool = "I"
		name = "InstallShield"
		pattern = "45BC50FF15????4100F645E8015F74060FB745ECEB036A0A5850566A006A00FF"
		start = 96
	strings:
		$1 = { 45 BC 50 FF 15 ?? ?? 41 00 F6 45 E8 01 5F 74 06 0F B7 45 EC EB 03 6A 0A 58 50 56 6A 00 6A 00 FF }
	condition:
		$1 at pe.entry_point + 96
}

rule installshield_uv_02 {
	meta:
		tool = "I"
		name = "InstallShield"
		pattern = "558BEC81EC14??00005356576A00FF15????????68????????FF15????????85C07429"
	strings:
		$1 = { 55 8B EC 81 EC 14 ?? 00 00 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 29 }
	condition:
		$1 at pe.entry_point
}

rule installshield_uv_3 {
	meta:
		tool = "I"
		name = "InstallShield"
		pattern = "558BEC83EC4456FF15????41008BF085F675086AFFFF15????41008A06578B3D????41003C22751B56FFD78BF08A063C22740484C075F1803E22751556FFD78B"
	strings:
		$1 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? 41 00 8B F0 85 F6 75 08 6A FF FF 15 ?? ?? 41 00 8A 06 57 8B 3D ?? ?? 41 00 3C 22 75 1B 56 FF D7 8B F0 8A 06 3C 22 74 04 84 C0 75 F1 80 3E 22 75 15 56 FF D7 8B }
	condition:
		$1 at pe.entry_point
}

rule installshield_uv_05 {
	meta:
		tool = "I"
		name = "InstallShield"
		source = "Made by Retdec Team"
		pattern = "558BEC83EC4456FF15???141008BF085F675086AFFFF15???141008A06578B3D???241003C22751B56FFD78BF08A063C22740484C075F1803E22751556FFD78BF0EB0E3C207E0A56FFD78BF0803E207FF68A0684C074043C207EE18365E8008D45BC50FF"
	strings:
		$1 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?1 41 00 8B F0 85 F6 75 08 6A FF FF 15 ?? ?1 41 00 8A 06 57 8B 3D ?? ?2 41 00 3C 22 75 1B 56 FF D7 8B F0 8A 06 3C 22 74 04 84 C0 75 F1 80 3E 22 75 15 56 FF D7 8B F0 EB 0E 3C 20 7E 0A 56 FF D7 8B F0 80 3E 20 7F F6 8A 06 84 C0 74 04 3C 20 7E E1 83 65 E8 00 8D 45 BC 50 FF }
	condition:
		$1 at pe.entry_point
}

rule instyler_uv_01 {
	meta:
		tool = "I"
		name = "Instyler"
		pattern = "4953011A00"
	strings:
		$1 = { 49 53 01 1A 00 }
	condition:
		$1 at pe.entry_point
}

rule instyler_uv_02 {
	meta:
		tool = "I"
		name = "Instyler"
		pattern = "6979457869744944"
	strings:
		$1 = { 69 79 45 78 69 74 49 44 }
	condition:
		$1 at pe.entry_point
}

rule sentinel_110_ultrapro_dongle {
	meta:
		tool = "I"
		name = "Sentinel"
		version = "1.1.0 UltraPro Dongle"
		pattern = "A1????????85C00F85590600005556C705????????????????FF15????????0105????????FF15????????3305????????25FE??????0D01??????A3????????33C050C704??????????????????E8BD0F000083C40483F8647CE768????????FF15????????8B35????????68????????FFD668????????FFD668????????FFD668????????FFD668????????FFD6A1????????8B??????????668B4D0083C508??????????????668B75FA????????????66????????????8B55FC81E1FFFF000081F9"
	strings:
		$1 = { A1 ?? ?? ?? ?? 85 C0 0F 85 59 06 00 00 55 56 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 25 FE ?? ?? ?? 0D 01 ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 50 C7 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 BD 0F 00 00 83 C4 04 83 F8 64 7C E7 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 A1 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 66 8B 4D 00 83 C5 08 ?? ?? ?? ?? ?? ?? ?? 66 8B 75 FA ?? ?? ?? ?? ?? ?? 66 ?? ?? ?? ?? ?? ?? 8B 55 FC 81 E1 FF FF 00 00 81 F9 }
	condition:
		$1 at pe.entry_point
}

rule sentinel_54200_superpro_dongle {
	meta:
		tool = "I"
		name = "Sentinel"
		version = "5.42.0.0 SuperPro Dongle"
		pattern = "60E8000000005D81ED????????B910FF0000BB00000000E8????????68B920FF0000E8????????68B930FF0000E8????????68E8????????6827F0107FE8????????68BB02000000E8????????6807D4307FE8????????68BB01000000E8????????68501EDF80E8????????68B910120000BB00000000E8????????68B920120000E8????????68E8????????68072AA300E8????????68BB01000000E8????????6888B55BFFE8????????68B930120000BB00000000E8????????68"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 10 FF 00 00 BB 00 00 00 00 E8 ?? ?? ?? ?? 68 B9 20 FF 00 00 E8 ?? ?? ?? ?? 68 B9 30 FF 00 00 E8 ?? ?? ?? ?? 68 E8 ?? ?? ?? ?? 68 27 F0 10 7F E8 ?? ?? ?? ?? 68 BB 02 00 00 00 E8 ?? ?? ?? ?? 68 07 D4 30 7F E8 ?? ?? ?? ?? 68 BB 01 00 00 00 E8 ?? ?? ?? ?? 68 50 1E DF 80 E8 ?? ?? ?? ?? 68 B9 10 12 00 00 BB 00 00 00 00 E8 ?? ?? ?? ?? 68 B9 20 12 00 00 E8 ?? ?? ?? ?? 68 E8 ?? ?? ?? ?? 68 07 2A A3 00 E8 ?? ?? ?? ?? 68 BB 01 00 00 00 E8 ?? ?? ?? ?? 68 88 B5 5B FF E8 ?? ?? ?? ?? 68 B9 30 12 00 00 BB 00 00 00 00 E8 ?? ?? ?? ?? 68 }
	condition:
		$1 at pe.entry_point
}

rule sentinel_640_superpro_automatic_protection {
	meta:
		tool = "I"
		name = "Sentinel"
		version = "6.4.0 SuperPro Automatic Protection"
		pattern = "68????????6A016A00FF15????????A3????????FF15????????33C93DB7000000A1????????0F94C185C0890D????????0F85????????5556C705????????01000000FF15????????0105????????FF15????????3305????????25FEFFDF3F0D01002000A3????????33C050C70485????????00000000E8????????83C40483F8647C??68????????FF15????????8B35????????68????????FFD668????????FFD668"
	strings:
		$1 = { 68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1 ?? ?? ?? ?? 0F 94 C1 85 C0 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 25 FE FF DF 3F 0D 01 00 20 00 A3 ?? ?? ?? ?? 33 C0 50 C7 04 85 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 83 C4 04 83 F8 64 7C ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? FF D6 68 }
	condition:
		$1 at pe.entry_point
}

rule sentinel_641_superpro_automatic_protection {
	meta:
		tool = "I"
		name = "Sentinel"
		version = "6.4.1 SuperPro Automatic Protection"
		pattern = "A1????????558B??????85C074??85ED75??A1????????5055FF15????????8B0D????????5551FF15????????85C074??8B15????????52FF15????????6A006A0068????????E8????????B8010000005DC20C0068????????6A016A00FF15????????A3????????FF15????????33C93DB7000000A1????????0F94C185C0890D????????0F85????????56C705????????01000000FF15????????01??????????FF15"
	strings:
		$1 = { A1 ?? ?? ?? ?? 55 8B ?? ?? ?? 85 C0 74 ?? 85 ED 75 ?? A1 ?? ?? ?? ?? 50 55 FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 55 51 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 15 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 6A 00 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 01 00 00 00 5D C2 0C 00 68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1 ?? ?? ?? ?? 0F 94 C1 85 C0 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? FF 15 }
	condition:
		$1 at pe.entry_point
}

rule setup_factory_install_package {
	meta:
		tool = "I"
		name = "Setup Factory"
		version = "Installer Package"
	strings:
		$s1 = { E0 E1 E2 E3 E4 E5 E6 E7 }
		$s2 = { E0 E0 E1 E1 E2 E2 E3 E3 E4 E4 E5 E5 E6 E6 E7 E7 }
	condition:
		pe.overlay.size > 0x10 and
		($s1 at pe.overlay.offset or $s2 at pe.overlay.offset)
}

rule setup_factory_install_app {
	meta:
		tool = "I"
		name = "Setup Factory"
		version = "Setup Launcher"
	strings:
		$s1 = "PKWARE Data Compression Library for Win32"
		$s3 = "irsetup.dat"
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs"
		$s5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
	condition:
		(
			pe.version_info["CompanyName"] == "Indigo Rose Corporation" or
			pe.version_info["LegalTrademarks"] == "Setup Factory is a trademark of Indigo Rose Corporation"
		)
		and
		(
			pe.version_info["FileDescription"] contains "Setup Factory 4." or
			pe.version_info["ProductName"] contains "Setup Factory 5." or
			pe.version_info["ProductName"] contains "Setup Factory 6." or
			pe.version_info["ProductName"] contains "Setup Factory 8."
		)
		and
		(
			all of them
		)
}

rule setup_factory_install_app_upx {
	meta:
		tool = "I"
		name = "Setup Factory"
		version = "Setup Launcher 7.0"
	condition:
		pe.number_of_sections == 3 and
		pe.sections[0].name == "UPX0" and
		pe.version_info["Comments"] == "Created with Setup Factory 7.0" and
		pe.version_info["ProductName"] == "Setup Factory 7.0 Runtime"
}

rule setup2go {
	meta:
		tool = "I"
		name = "Setup2Go"
		pattern = "5B53455455505F494E464F5D0D0A566572"
	strings:
		$1 = { 5B 53 45 54 55 50 5F 49 4E 46 4F 5D 0D 0A 56 65 72 }
	condition:
		$1 at pe.entry_point
}

rule smart_install_maker_v4 {
	meta:
		tool = "I"
		name = "Smart Install Maker"
		version = "4.x"
	strings:
		$s01 = "Smart Install Maker" nocase
		$s02 = "SMART INSTALL MAKER" nocase
		$s03 = "c:\\delphi7\\Lib\\km\\KOL.pas"
		$s04 = "TLZMADecompressor"
		$s05 = "Can not create DIB section, error:"
	condition:
		pe.number_of_sections == 8 and
		pe.sections[0].name == "CODE" and           // Delphi
		pe.sections[1].name == "DATA" and
		pe.overlay.size != 0 and
		all of them
}

rule smart_install_maker_v5 {
	meta:
		tool = "I"
		name = "Smart Install Maker"
		version = "5.x"
	strings:
		$s01 = "Smart Install Maker" nocase
		$s02 = "SMART INSTALL MAKER" nocase
	condition:
		pe.number_of_sections == 8 and
		pe.sections[0].name == "CODE" and           // Delphi
		pe.sections[1].name == "DATA" and
		pe.overlay.size != 0 and
		$s01 at pe.overlay.offset and
		all of them
}

rule thinstall_uv {
	meta:
		tool = "I"
		name = "Thinstall"
		pattern = "FFFFFF8BC18B4C2404898829040000C7400C010000000FB64901D1E9894810C7401480000000C204008B442404C7410C"
		start = 16
	strings:
		$1 = { FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C }
	condition:
		$1 at pe.entry_point + 16
}

rule thinstall_19_2460 {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "1.9 - 2.460"
		pattern = "558BEC515356576A006A00FF15????????50E887FCFFFF5959A1????????8B40100305????????8945FC8B45FCFFE05F5E5BC9C3000000"
	strings:
		$1 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 ?? ?? ?? ?? 50 E8 87 FC FF FF 59 59 A1 ?? ?? ?? ?? 8B 40 10 03 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_2313_2403 {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.312 - 2.403"
		pattern = "6A00FF15????????E8D4F8FFFFE9E9ADFFFFFF8BC18B4C2404898829040000C7400C010000000FB64901D1E9894810C7401480000000C204008B442404C7410C010000008981290400000FB64001D1E8894110C741"
	strings:
		$1 = { 6A 00 FF 15 ?? ?? ?? ?? E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_24_25 {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.4 - 2.5"
		pattern = "558BECB8??????????????????50E800000000582D????????B9????????BA????????BE????????BF????????BD????????03E8"
	strings:
		$1 = { 55 8B EC B8 ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? BD ?? ?? ?? ?? 03 E8 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_2547_2628 {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.547 - 2.628"
		pattern = "E80000000058BB????00002BC35068????????68????000068????0000E8????FFFFE9??FFFFFF"
	strings:
		$1 = { E8 00 00 00 00 58 BB ?? ?? 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? 00 00 68 ?? ?? 00 00 E8 ?? ?? FF FF E9 ?? FF FF FF }
	condition:
		for any of them : ( $ in (pe.entry_point .. pe.entry_point + 12) )
}

rule thinstall_27xx {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.7xx"
		pattern = "9C60E80000000058BB????????2BC35068????????68????????68????????E8????????E9"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_3035_3043 {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "3.035 - 3.043"
		pattern = "9C60685374416C685468496EE80000000058BB371F00002BC35068????????68002800006804010000E8BAFEFFFFE990FFFFFFCCCCCCCCCCCCCC558BEC83C4F4FC5357568B75088B7D0CC745FC0800000033DBBA00"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_20x_embedded {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.0x embedded"
		pattern = "B8EFBEADDE506A00FF15????????E9ADFFFFFF8BC18B4C2404898829040000C7400C010000000FB64901D1E9894810C7401480000000C204008B442404C7410C010000008981290400000FB64001D1E8894110C7411480000000C20400558BEC53565733C033FF39450C8BF1760C8B4D08033C81403B450C72F48BCEE8430000008B461433D2F7F78B5E1033D28BF88BC3F7F7897E1889450C33C033C98B5508030C8240394D0C73F4488B14822BCA0FAFCF2BD90FAFFA897E14895E105F5E5B5DC20800"
	strings:
		$1 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_22xx_2308_embedded {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.2xx - 2.308 embedded"
		pattern = "B8EFBEADDE506A00FF15????????E9B9FFFFFF8BC18B4C2404898829040000C7400C010000000FB64901D1E9894810C7401480000000C204008B442404C7410C010000008981290400000FB64001D1E8894110C7411480000000C20400558BEC53565733C033FF39450C8BF1760C8B4D08033C81403B450C72F48BCEE8430000008B461433D2F7F78B5E1033D28BF88BC3F7F7897E1889450C33C033C98B5508030C8240394D0C73F4488B14822BCA0FAFCF2BD90FAFFA897E14895E105F5E5B5DC20800"
	strings:
		$1 = { B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 B9 FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_2545_embedded {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "2.545 embedded"
		pattern = "E8F2FFFFFF5068????????68401B0000E842FFFFFFE99DFFFFFF000000000000"
	strings:
		$1 = { E8 F2 FF FF FF 50 68 ?? ?? ?? ?? 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_3049_3080_vs {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "3.049 - 3.080 virtualization suite"
		pattern = "9C60685374416C685468496EE80000000058BB371F00002BC35068????????68002C00006804010000E8BAFEFFFFE990FFFFFFCCCCCCCCCCCCCC558BEC83C4F4FC5357568B75088B7D0CC745FC0800000033DBBA00"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 ?? ?? ?? ?? 68 00 2C 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_30xx_vs {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "3.0xx virtualization suite"
		pattern = "9C6068????????68????????E80000000058BB????????2BC35068????????68????????68????????E8BAFEFFFFE9????????CCCCCCCCCCCCCC558BEC83C4F4FC5357568B75088B7D0CC745FC0800000033DBBA"
	strings:
		$1 = { 9C 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 BA FE FF FF E9 ?? ?? ?? ?? CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA }
	condition:
		$1 at pe.entry_point
}

rule thinstall_3100_3332_vs {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "3.100 - 3.332 virtualization suite"
		pattern = "9C60685374416C685468496EE80000000058BB????????2BC35068????????68????????68????????E82CFFFFFFE990FFFFFFCCCC558BEC83C4F4FC5357568B75088B7D0CC745FC0800000033DBBA000000804333C0E819010000730E8B4DF8E8270100000245F7AAEBE9"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 2C FF FF FF E9 90 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 }
	condition:
		$1 at pe.entry_point
}

rule thinstall_3348_3350_vs {
	meta:
		tool = "I"
		name = "Thinstall"
		version = "3.348 - 3.350 virtualization suite"
		pattern = "9C60685374416C685468496EE80000000058BB591900002BC35068????????68????????68AC000000E82CFFFFFFE9??FFFFFFCCCCCCCCCC558BEC83C4F4FC5357568B75088B7D0CC745FC0800000033DBBA000000804333C0E819010000730E8B4DF8E8270100000245F7AAEBE9E8040100000F8296000000E8F9000000735BB904000000E8050100004874DE0F89C6000000E8DF000000731B55BD00010000E8DF0000008807474D75F5E8C700000072E95DEBA2B901000000E8D000000083C0078945F8C645F70083F8087489E8B10000008845F7E97CFFFFFFB907000000E8AA0000005033C9B102E8A00000008BC84141580BC074048BD8EB5E83F902746A41E8880000008945FCE948FFFFFFE88700000049E2098BC3E87D000000EB3A498BC1558B4DFC8BE833C0D3E5E85D0000000BC55D8BD8E85F0000003D0000010073143DFF370000730E3D7F020000730883F87F770441414141568BF72BF0F3A45EE9F0FEFFFF33C0EB058BC72B450C5E5F5BC9C2080003D275088B1683C604F913D2C3B908000000E801000000C333C0E8E1FFFFFF13C0E2F7C333C941E8D4FFFFFF13C9E8CDFFFFFF72F2C3000000000000"
	strings:
		$1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 59 19 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 AC 00 00 00 E8 2C FF FF FF E9 ?? FF FF FF CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 C3 B9 08 00 00 00 E8 01 00 00 00 C3 33 C0 E8 E1 FF FF FF 13 C0 E2 F7 C3 33 C9 41 E8 D4 FF FF FF 13 C9 E8 CD FF FF FF 72 F2 C3 00 00 00 00 00 00 }
	condition:
		$1 at pe.entry_point
}

rule viseman {
	meta:
		tool = "I"
		name = "Viseman Installer"
	condition:
		pe.overlay.offset != 0 and
		pe.overlay.size > 4 and
		uint32(pe.overlay.offset) == 0x56495345     // Reversed "VISE"
}

rule wise_installer_uv_01 {
	meta:
		tool = "I"
		name = "Wise Installer"
		pattern = "558BEC81EC????00005356576A??????????????FF15????4000"
	strings:
		$1 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? 40 00 }
	condition:
		$1 at pe.entry_point
}

rule wise_installer_uv_02 {
	meta:
		tool = "I"
		name = "Wise Installer"
		pattern = "81EC200F000056576A04FF150C61400033FF897C2440897C2424897C2420897C2428897C241CFF15A46040008A0880F92289442430752AEB0580F9227410408A"
	strings:
		$1 = { 81 EC 20 0F 00 00 56 57 6A 04 FF 15 0C 61 40 00 33 FF 89 7C 24 40 89 7C 24 24 89 7C 24 20 89 7C 24 28 89 7C 24 1C FF 15 A4 60 40 00 8A 08 80 F9 22 89 44 24 30 75 2A EB 05 80 F9 22 74 10 40 8A }
	condition:
		$1 at pe.entry_point
}

rule wise_installer_uv_03 {
	meta:
		tool = "I"
		name = "Wise Installer"
		pattern = "558BEC81ECBC0400005356576A04FF1564304000FF15503040008BF08975F48A063C220F85980000008A4601468975F433DB3AC3740D3C2274098A4601468975"
	strings:
		$1 = { 55 8B EC 81 EC BC 04 00 00 53 56 57 6A 04 FF 15 64 30 40 00 FF 15 50 30 40 00 8B F0 89 75 F4 8A 06 3C 22 0F 85 98 00 00 00 8A 46 01 46 89 75 F4 33 DB 3A C3 74 0D 3C 22 74 09 8A 46 01 46 89 75 }
	condition:
		$1 at pe.entry_point
}

rule wise_installer_uv_04 {
	meta:
		tool = "I"
		name = "Wise Installer"
	strings:
		$1 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 3? 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 3? 20 40 00 8B 3D ?? 20 40 00 53 53 6A }
		$2 = { 55 8b ec 81 ec 74 05 00 00 53 8d 85 98 fd ff ff 56 33 db 57 be 04 01 00 00 56 50 53 ff 15 b4 40 40 00 56 8d 85 98 fd ff ff 50 50 ff 15 8c 40 40 00 53 8d 8d 98 fd ff ff 53 6a 03 53 6a 01 68 00 }
		$3 = { 55 8b ec 81 ec 7c 05 00 00 53 56 57 be 04 01 00 00 56 8d 85 90 fd ff ff 33 db 50 53 89 5d f4 ff 15 38 20 40 00 56 8d 85 90 fd ff ff 50 50 ff 15 34 20 40 00 8b 3d 30 20 40 00 53 53 6a 03 53 6a }
	condition:
		$1 at pe.entry_point or
		$2 at pe.entry_point or
		$3 at pe.entry_point
}

rule wise_installer_uv_05 {
	meta:
		tool = "I"
		name = "Wise Installer"
	strings:
		$s01 = "WISE_SETUP_EXE_PATH=\"%s\""
		$s02 = "Wise Installation"
		$s03 = "WiseInitLangAlwaysPrompt"
		$s04 = "Initializing Wise Installation Wizard..."
	condition:
		pe.number_of_sections == 5 and
		pe.sections[3].name == ".WISE" and
		all of them
}

rule wise_installer_uv_06 {
	meta:
		tool = "I"
		name = "Wise Installer"
	strings:
		$h01 = { 64 a1 00 00 00 00 55 8b ec 6a ff 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 00 00 00 00 83 ec }
		$h02 = { 55 8b ec 6a ff 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec }
		$s01 = "GLBSInstall"
		$s02 = "System DLLs corrupt or missing."
		$s03 = "Could not locate installer DLL."
		$s04 = "WiseMain"
		$s05 = "Corrupt installation detected."
		$s06 = "The installation file may be corrupt."
	condition:
		pe.number_of_sections >= 4 and
		($h01 at pe.entry_point or $h02 at pe.entry_point) and
		4 of ($s*)
}

rule wise_installer_110 {
	meta:
		tool = "I"
		name = "Wise Installer"
		version = "1.10"
		pattern = "558BEC81EC400F00005356576A04FF15F4304000FF15743040008A088945E880F92275488A4801408945E833F684C9740E80F92274098A4801408945E8EBEE8038227504408945E880382075094080382074FA8945E88A0880F92F742B84C9741F80F93D741A8A480140EBF133F684C974D680F92074"
	strings:
		$1 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 E8 8A 08 80 F9 2F 74 2B 84 C9 74 1F 80 F9 3D 74 1A 8A 48 01 40 EB F1 33 F6 84 C9 74 D6 80 F9 20 74 }
	condition:
		$1 at pe.entry_point
}

rule nsis_1xx {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "1.xx"
		pattern = "83EC0C535657FF152071400005E8030000BE60FD410089442410B320FF15287040006800040000FF15287140005056FF1508714000803D60FD410022750880C302BE61FD41008A068B3DF071400084C0740F3AC3740B56FFD78BF08A0684C075F1803E00740556FFD78BF089742414803E20750756FFD78BF0EBF4803E2F75"
	strings:
		$1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 80 3E 20 75 07 56 FF D7 8B F0 EB F4 80 3E 2F 75 }
	condition:
		$1 at pe.entry_point
}

rule nsis_1xx_pimp {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "1.xx PiMP"
		pattern = "83EC5C53555657FF15??????00"
	strings:
		$1 = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_overlay_data {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
	strings:
		$s01 = { EF BE AD DE 6E 73 69 73 69 6E 73 74 61 6C 6C 00 }
		$s02 = { ED BE AD DE 4E 75 6C 6C 53 6F 66 74 49 6E 73 74 }
		$s03 = { 0? 00 00 00 EF BE AD DE 4E 75 6C 6C (53|73) 6F 66 74 49 6E 73 74 }
	condition:
		pe.number_of_sections > 3 and
		pe.overlay.size != 0 and
		(
			@s01 >= pe.overlay.offset or
			@s02 >= pe.overlay.offset or
			@s03 >= pe.overlay.offset
		)
}

rule nsis_13x_pimp {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "1.3x PIMP"
		pattern = "558BEC81EC????000056576A??BE????????598DBD"
	strings:
		$1 = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }
	condition:
		$1 at pe.entry_point
}

rule nsis_20rc2 {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.0rc2"
		pattern = "83EC1053555657C74424147092400033EDC644241320FF152C70400055FF1584724000BE00544300BF000400005657A3A8EC4200FF15C4704000E88DFFFFFF8B1D9070400085C0752168FB03000056FF155C714000"
	strings:
		$1 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_20 {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.0"
		pattern = "83EC0C53555657C74424107092400033DBC644241420FF152C70400053FF1584724000BE00544300BF000400005657A3A8EC4200FF15C4704000E88DFFFFFF8B2D9070400085C0752168FB03000056FF155C714000"
	strings:
		$1 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_20b2_20b3 {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.0b2, 2.0b3"
		pattern = "83EC0C53555657FF15??7040008B35??92400005E803000089442414B320FF152C704000BF0004000068??????0057FF15????400057FF15"
	strings:
		$1 = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 ?? ?? ?? 00 57 FF 15 ?? ?? 40 00 57 FF 15 }
	condition:
		$1 at pe.entry_point
}

rule nsis_20b4_01 {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.0b4"
		pattern = "83EC1053555657C7442414F091400033EDC644241320FF152C70400055FF1588724000BE00D44200BF000400005657A3606F4200FF15C4704000E89FFFFFFF8B1D9070400085C0752168FB03000056FF1560714000"
	strings:
		$1 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_20b4_02 {
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.0b4"
		pattern = "83EC14836424040053555657C644241320FF1530704000BE00207A00BD000400005655FF15C470400056E87D2B00008B1D8C7040006A0056FFD3BF809279005657E81526000085C0753868F89140005556FF156071400003C650E87829000056E8472B00006A0056FFD35657E8EA25000085C0750DC744241458914000E97202000057FF152471400068EC91400057E843"
	strings:
		$1 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 40 00 03 C6 50 E8 78 29 00 00 56 E8 47 2B 00 00 6A 00 56 FF D3 56 57 E8 EA 25 00 00 85 C0 75 0D C7 44 24 14 58 91 40 00 E9 72 02 00 00 57 FF 15 24 71 40 00 68 EC 91 40 00 57 E8 43 }
	condition:
		$1 at pe.entry_point
}

rule nsis_202_208
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.02 - 2.08"
		source = "Made by Retdec Team"
		pattern = "83EC2053555633DB57895C2418C7442410????4000C644241420FF153??0400053FF15???2400068????400068?0????00A3?0????00E8??2?0000BE00????00????0?0?00??57FF15????4000E8??FFFFFF8??????????0???0752168FB0?000056FF15"
	strings:
		$1 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? 40 00 C6 44 24 14 20 FF 15 ?? ?0 40 00 53 FF 15 ?? ?2 40 00 68 ?? ?? 40 00 68 ?0 ?? ?? 00 A3 ?0 ?? ?? 00 E8 ?? 2? 00 00 BE 00 ?? ?? 00 ?? ?? 0? 0? 00 ?? 57 FF 15 ?? ?? 40 00 E8 ?? FF FF FF 8? ?? ?? ?? ?? ?0 ?? ?0 75 21 68 FB 0? 00 00 56 FF 15 }
	condition:
		$1 at pe.entry_point
}

rule nsis_209_210
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.09 - 2.10"
		source = "Made by Retdec Team"
		pattern = "83EC2053555633F65789742418B?????400089742414C644241020FF1530?0400056FF158??2400068????400068?0??4?00A3?0??4?00E8??2?0000B?00??4?00BF00??00005?57FF15????4000E879FFFFFF85C0752468FB??00005?FF15????400068"
	strings:
		$1 = { 83 EC 20 53 55 56 33 F6 57 89 74 24 18 B? ?? ?? 40 00 89 74 24 14 C6 44 24 10 20 FF 15 30 ?0 40 00 56 FF 15 8? ?2 40 00 68 ?? ?? 40 00 68 ?0 ?? 4? 00 A3 ?0 ?? 4? 00 E8 ?? 2? 00 00 B? 00 ?? 4? 00 BF 00 ?? 00 00 5? 57 FF 15 ?? ?? 40 00 E8 79 FF FF FF 85 C0 75 24 68 FB ?? 00 00 5? FF 15 ?? ?? 40 00 68 }
	condition:
		$1 at pe.entry_point
}

rule nsis_211_212
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.11 - 2.12"
		source = "Made by Retdec Team"
		pattern = "81EC8001000053555633F65789742418B?????400089742410C644241420FF1530?0400056FF15???24000????????00????????????????????505668????4?00FF15???1400068????400068?0??4?00E8??2?0000B?00??4?00??????0?00??57FF15"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 F6 57 89 74 24 18 B? ?? ?? 40 00 89 74 24 10 C6 44 24 14 20 FF 15 30 ?0 40 00 56 FF 15 ?? ?2 40 00 ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 56 68 ?? ?? 4? 00 FF 15 ?? ?1 40 00 68 ?? ?? 40 00 68 ?0 ?? 4? 00 E8 ?? 2? 00 00 B? 00 ?? 4? 00 ?? ?? ?? 0? 00 ?? 57 FF 15 }
	condition:
		$1 at pe.entry_point
}

rule nsis_213_223
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.13 - 2.23"
		source = "Made by Retdec Team"
		pattern = "81EC7C01000053555633F65789742418BD??9?4000C644241020FF153070400056FF1570724000A3?0??4200568D4424306860010000505668????4?00FF155871400068??92400068?0??4200E8??280000BB00?44?00536800040000FF15B?704000E8"
	strings:
		$1 = { 81 EC 7C 01 00 00 53 55 56 33 F6 57 89 74 24 18 B? ?0 ?? 40 00 C6 44 24 10 20 FF 15 30 ?0 40 00 56 FF 15 7? ?2 40 00 A3 ?0 ?? 4? 00 56 8D 44 24 30 68 60 01 00 00 50 56 68 ?? ?? 4? 00 FF 15 58 ?1 40 00 68 ?? ?? 40 00 68 ?0 ?? 4? 00 E8 ?? 2? 00 00 B? 00 ?? 4? 00 5? 68 00 ?? 00 00 FF 15 B? ?0 40 00 E8 }
	condition:
		$1 at pe.entry_point
}

rule nsis_224
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.24"
		source = "Made by Retdec Team"
		pattern = "81EC8001000053555633DB57895C2418C7442414?09?400033F6C644241020FF153070400053FF1574724000A3?0??4200538D4424346860010000505368????4?00FF155C71400068??92400068?0??4200E8??280000FF15B?704000BF00?04?005057"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 14 ?0 9? 40 00 33 F6 C6 44 24 10 20 FF 15 30 70 40 00 53 FF 15 74 72 40 00 A3 ?0 ?? 42 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 ?? ?? 4? 00 FF 15 5C 71 40 00 68 ?? 92 40 00 68 ?0 ?? 42 00 E8 ?? 28 00 00 FF 15 B? 70 40 00 BF 00 ?0 4? 00 50 57 }
	condition:
		$1 at pe.entry_point
}

rule nsis_225
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.25"
		source = "Made by Retdec Team"
		pattern = "558BEC81EC80010000535633DB57895DF4C745F8????4000895DFCC645EC20FF153070400053FF157?724000?3??????00???????0?????????0??????505368??????00FF155?71400068????400068?0????00E8??2?0000FF15B?704000?????0"
	strings:
		$1 = { 55 8B EC 81 EC 80 01 00 00 53 56 33 DB 57 89 5D F4 C7 45 F8 ?? ?? 40 00 89 5D FC C6 45 EC 20 FF 15 30 70 40 00 53 FF 15 7? 72 40 00 ?3 ?? ?? ?? 00 ?? ?? ?? ?0 ?? ?? ?? ?? ?0 ?? ?? ?? 50 53 68 ?? ?? ?? 00 FF 15 5? 71 40 00 68 ?? ?? 40 00 68 ?0 ?? ?? 00 E8 ?? 2? 00 00 FF 15 B? 70 40 00 ?? ?? ?0 }
	condition:
		$1 at pe.entry_point
}

rule nsis_226_228
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.26 - 2.28"
		source = "Made by Retdec Team"
		pattern = "81EC8001000053555633DB57895C2418C7442410??91400033F6C644241420FF153070400053FF1578724000A3?4??4200538D4424346860010000505368????4?00FF155471400068??9?400068?0??4200E8??270000FF15B?704000BF00?04?005057"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? 91 40 00 33 F6 C6 44 24 14 20 FF 15 30 70 40 00 53 FF 15 78 72 40 00 A3 ?4 ?? ?? 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 ?? ?? ?? 00 FF 15 54 71 40 00 68 ?? 9? 40 00 68 ?0 ?? ?? 00 E8 ?? 27 00 00 FF 15 B? 70 40 00 BF 00 ?0 ?? 00 50 57 }
	condition:
		$1 at pe.entry_point
}

rule nsis_229
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.29"
		source = "Made by Retdec Team"
		pattern = "81EC8001000053555633DB57895C2418C7442410??91400033F6C644241420FF15307040006801800000FF15B?70400053FF15787240006A08A3?4??4200E8??2A0000A3?4??4200538D4424346860010000505368????4?00FF155471400068??9?4000"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? 91 40 00 33 F6 C6 44 24 14 20 FF 15 30 70 40 00 68 01 80 00 00 FF 15 B? 70 40 00 53 FF 15 78 72 40 00 6A 08 A3 ?4 ?? 42 00 E8 ?? 2A 00 00 A3 ?4 ?? 42 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 ?? ?? 4? 00 FF 15 54 71 40 00 68 ?? 9? 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_230
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.30"
		source = "Made by Retdec Team"
		pattern = "81EC8001000053555633DB57895C2418C7442410??91400033F6C644241420FF15307040006801800000FF15B?70400053FF157C7240006A08A3?4????00E8??2A0000A3?4????00538D4424346860010000505368??????00FF155871400068??9?4000"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? 91 40 00 33 F6 C6 44 24 14 20 FF 15 30 70 40 00 68 01 80 00 00 FF 15 B? 70 40 00 53 FF 15 7C 72 40 00 6A 08 A3 ?4 ?? ?? 00 E8 ?? 2A 00 00 A3 ?4 ?? ?? 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 ?? ?? ?? 00 FF 15 58 71 40 00 68 ?? 9? 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_231_246
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.31 - 2.46"
		source = "Made by Retdec Team"
		pattern = "81EC8001000053555633DB57895C2418C7442410??91400033F6C644241420FF15307040006801800000FF15B?70400053FF157C7240006A08A3?8????00E8??2?0000A3?4????00538D4424346860010000505368??????00FF155871400068??914000"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? 40 00 33 F6 C6 44 24 14 20 FF 15 30 ?0 40 00 68 01 80 00 00 FF 15 B? ?0 40 00 53 FF 15 ?? ?2 40 00 6A 08 A3 ?8 ?? ?? 00 E8 ?? 2? 00 00 A3 ?4 ?? ?? 00 53 8D 44 24 34 68 60 01 00 00 50 53 68 ?? ?? ?? 00 FF 15 58 ?1 40 00 68 ?? ?? 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_247_248
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.47 - 2.48"
		source = "Made by Retdec Team"
		pattern = "81EC8001000053555633DB57895C2418C7442410??91400033F6C644241420FF15347040006801800000FF15B?70400053FF157072400053A3?8????00E8??2D00003BC3740768000C0000FFD06A0DE8??2D00006A0BE8??2D0000A3?4????00538D4424"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? 91 40 00 33 F6 C6 44 24 14 20 FF 15 34 70 40 00 68 01 80 00 00 FF 15 B? 70 40 00 53 FF 15 70 72 40 00 53 A3 ?8 ?? ?? 00 E8 ?? 2D 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 6A 0D E8 ?? 2D 00 00 6A 0B E8 ?? 2D 00 00 A3 ?4 ?? ?? 00 53 8D 44 24 }
	condition:
		$1 at pe.entry_point
}

rule nsis_249
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.49"
		source = "Made by Retdec Team"
		pattern = "81EC8001000053555633DB57895C2418C7442410????400033F6C644241420FF15347040006801800000FF15B?70400053FF1570724000A3?8??4?00FF15B?70400066????0?741153E8??2?00003BC3740768000C0000FFD06A0DE8??2?00006A0BE8"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? 40 00 33 F6 C6 44 24 14 20 FF 15 34 70 40 00 68 01 80 00 00 FF 15 B? 70 40 00 53 FF 15 70 72 40 00 A3 ?8 ?? 4? 00 FF 15 B? 70 40 00 66 ?? ?? 0? 74 11 53 E8 ?? 2? 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 6A 0D E8 ?? 2? 00 00 6A 0B E8 }
	condition:
		$1 at pe.entry_point
}

rule nsis_250
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.50"
		source = "Made by Retdec Team"
		pattern = "81EC800100005355565733DB6801800000895C241CC7442414??91400033F6C644241820FF15B?704000FF15B?704000663D0600741153E8??2D00003BC3740768000C0000FFD068??914000E8??2D000068??914000E8??2D000068??914000E8??2D00"
	strings:
		$1 = { 81 EC 80 01 00 00 53 55 56 57 33 DB 68 01 80 00 00 89 5C 24 1C C7 44 24 14 ?? 91 40 00 33 F6 C6 44 24 18 20 FF 15 B? 70 40 00 FF 15 B? 70 40 00 66 3D 06 00 74 11 53 E8 ?? 2D 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 68 ?? 91 40 00 E8 ?? 2D 00 00 68 ?? 91 40 00 E8 ?? 2D 00 00 68 ?? 91 40 00 E8 ?? 2D 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_251
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "2.51"
		source = "Made by Retdec Team"
		pattern = "81EC840100005355565733DB6801800000895C2420C7442414????4000895C241CC644241820FF15B??04000FF15???04000663D0600741153E8????00003BC3740768000C0000FFD0?????????0?????????000????????????00"
	strings:
		$1 = { 81 EC 84 01 00 00 53 55 56 57 33 DB 68 01 80 00 00 89 5C 24 20 C7 44 24 14 ?? ?? 40 00 89 5C 24 1C C6 44 24 18 20 FF 15 B? ?0 40 00 FF 15 ?? ?0 40 00 66 3D 06 00 74 11 53 E8 ?? ?? 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 ?? ?? ?? ?? ?0 ?? ?? ?? ?? ?0 00 ?? ?? ?? ?? ?? ?? 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_300_301
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "3.00 - 3.01"
		source = "Made by Retdec Team"
		pattern = "81EC8401000053565733DB6801800000895C2418C7442410???14000895C2420C644241420FF15????4000FF15A??04000663D0600741153E8??2F00003BC3740768000C0000FFD0BE98?2400056E8??2?000056FF15A??040008D740601381E75EB556A"
	strings:
		$1 = { 81 EC 84 01 00 00 53 56 57 33 DB 68 01 80 00 00 89 5C 24 18 C7 44 24 10 ?? ?1 40 00 89 5C 24 20 C6 44 24 14 20 FF 15 ?? ?? 40 00 FF 15 A? ?0 40 00 66 3D 06 00 74 11 53 E8 ?? 2F 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 BE 98 ?2 40 00 56 E8 ?? 2? 00 00 56 FF 15 A? ?0 40 00 8D 74 06 01 38 1E 75 EB 55 6A }
	condition:
		$1 at pe.entry_point
}

rule nsis_300_301_unicode
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "3.00 - 3.01"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "81ECD40200005356576A205F33DB6801800000895C2414C7442410?0?24000895C241CFF15B??04000FF15???04000663D0600741153E8??3100003BC3740768000C0000FFD0BEB8?2400056E8??30000056FF155C?140008D740601803E0075EA556A09"
	strings:
		$1 = { 81 EC D4 02 00 00 53 56 57 6A 20 5F 33 DB 68 01 80 00 00 89 5C 24 14 C7 44 24 10 ?0 ?2 40 00 89 5C 24 1C FF 15 B? ?0 40 00 FF 15 ?? ?0 40 00 66 3D 06 00 74 11 53 E8 ?? 31 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 BE B8 ?2 40 00 56 E8 ?? 30 00 00 56 FF 15 5C ?1 40 00 8D 74 06 01 80 3E 00 75 EA 55 6A 09 }
	condition:
		$1 at pe.entry_point
}

rule nsis_302
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "3.02"
		source = "Made by Retdec Team"
		pattern = "81EC8401000053565733DB6801800000895C2418C7442410???14000895C2420C644241420FF15A??04000FF15???0400025FFFFFFBF663D0600A3?C????00741153E8??3000003BC3740768000C0000FFD0BE98?2400056E8??30000056FF15???04000"
	strings:
		$1 = { 81 EC 84 01 00 00 53 56 57 33 DB 68 01 80 00 00 89 5C 24 18 C7 44 24 10 ?? ?1 40 00 89 5C 24 20 C6 44 24 14 20 FF 15 A? ?0 40 00 FF 15 ?? ?0 40 00 25 FF FF FF BF 66 3D 06 00 A3 ?C ?? ?? 00 74 11 53 E8 ?? 30 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 BE 98 ?2 40 00 56 E8 ?? 30 00 00 56 FF 15 ?? ?0 40 00 }
	condition:
		$1 at pe.entry_point
}

rule nsis_302_unicode
{
	meta:
		tool = "I"
		name = "Nullsoft Install System"
		version = "3.02"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "81ECD40200005356576A205F33DB6801800000895C2414C7442410?0A24000895C241CFF15A?804000FF15A?80400025FFFFFFBF663D0600A3?C????00741153E8??3200003BC3740768000C0000FFD0BEB082400056E8??32000056FF15508140008D74"
	strings:
		$1 = { 81 EC D4 02 00 00 53 56 57 6A 20 5F 33 DB 68 01 80 00 00 89 5C 24 14 C7 44 24 10 ?0 A2 40 00 89 5C 24 1C FF 15 A? 80 40 00 FF 15 A? 80 40 00 25 FF FF FF BF 66 3D 06 00 A3 ?C ?? ?? 00 74 11 53 E8 ?? 32 00 00 3B C3 74 07 68 00 0C 00 00 FF D0 BE B0 82 40 00 56 E8 ?? 32 00 00 56 FF 15 50 81 40 00 8D 74 }
	condition:
		$1 at pe.entry_point
}

rule inno_uv {
	meta:
		tool = "I"
		name = "Inno Setup"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4??53565733C08945F08945??8945??E8????FFFFE8????FFFFE8????FFFFE8????FFFFE8????FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_10x {
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "1.0.x"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E8A77FFFFFE8FA92FFFFE8F1B3FFFF33C0"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_12x {
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "1.2.x"
		pattern = "558BEC83C4C053565733C08945F08945EC8945C0E85B73FFFFE8D687FFFFE8C5A9FFFFE8E0"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 E0 }
	condition:
		$1 at pe.entry_point
}

rule inno_13x
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "1.3.x"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 43 73 FF FF E8 F2 87 FF FF E8 E1 A9 FF FF E8 A4 F6 FF FF E8 23 FC FF FF BE ?? FE 40 00 33 C0 55 68 65 C2 40 00 64 FF 30 64 89 20 33 D2 55 68 24 C2 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 CC F3 FF FF 8B 55 F0 B8 ?? ?? 40 00 E8 03 74 FF }
		$2 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 C3 71 FF FF E8 72 86 FF FF E8 89 A8 FF FF E8 4C F5 FF FF E8 CB FA FF FF BE 78 FE 40 00 33 C0 55 68 51 C4 40 00 64 FF 30 64 89 20 33 D2 55 68 10 C4 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 74 F2 FF FF 8B 55 F0 B8 DC FB 40 00 E8 83 72 FF }
		$3 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 43 73 FF FF E8 F2 87 FF FF E8 E1 A9 FF FF E8 A4 F6 FF FF E8 23 FC FF FF BE 74 FE 40 00 33 C0 55 68 65 C2 40 00 64 FF 30 64 89 20 33 D2 55 68 24 C2 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 CC F3 FF FF 8B 55 F0 B8 D8 FB 40 00 E8 03 74 FF }
	condition:
		$1 at pe.entry_point or
		$2 at pe.entry_point or
		$3 at pe.entry_point
}

rule inno_overlay
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "1.3.x overlay"
		source = "Made by Retdec Team"
	strings:
		$1 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 ?? 89 45 }
	condition:
		$1 at pe.entry_point and
		pe.overlay.offset != 0 and
		pe.overlay.size > 0x10 and
		uint32(pe.overlay.offset) == 0x6B736469 and
		uint32(pe.overlay.offset+0x04) == 0x1A323361 and
		uint32(pe.overlay.offset+0x08) < filesize and
		uint32(pe.overlay.offset+0x0C) == 0x1A626C7A
}

rule inno_2xx
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "2.0.x"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E87371FFFFE8DA85FFFFE881A7FFFFE8C8A7FFFFE8B7A8FFFFE836F5FFFFE8F1FAFFFFBE04FF400033C05568E9C4400064FF3064892033D25568A8C4400064FF326489228D55F033C0E87AF2FFFF8B55"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8 A7 FF FF E8 B7 A8 FF FF E8 36 F5 FF FF E8 F1 FA FF FF BE 04 FF 40 00 33 C0 55 68 E9 C4 40 00 64 FF 30 64 89 20 33 D2 55 68 A8 C4 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 7A F2 FF FF 8B 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_300b
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "3.0.0b"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E89371FFFFE8FA85FFFFE899A7FFFFE8E0A7FFFFE8CFA8FFFFE8F6FAFFFFBE1CFF400033C05568C4C4400064FF3064892033D2556883C4400064FF326489228D55F033C0E897F2FFFF8B55F0B880FC40"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 93 71 FF FF E8 FA 85 FF FF E8 99 A7 FF FF E8 E0 A7 FF FF E8 CF A8 FF FF E8 F6 FA FF FF BE 1C FF 40 00 33 C0 55 68 C4 C4 40 00 64 FF 30 64 89 20 33 D2 55 68 83 C4 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 97 F2 FF FF 8B 55 F0 B8 80 FC 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_301b
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "3.0.1b"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E82F71FFFFE89685FFFFE835A7FFFFE87CA7FFFFE86BA8FFFFE8F6FAFFFFBE20FF400033C0556828C5400064FF3064892033D25568E7C4400064FF326489228D55F033C0E897F2FFFF8B55F0B884FC40"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 2F 71 FF FF E8 96 85 FF FF E8 35 A7 FF FF E8 7C A7 FF FF E8 6B A8 FF FF E8 F6 FA FF FF BE 20 FF 40 00 33 C0 55 68 28 C5 40 00 64 FF 30 64 89 20 33 D2 55 68 E7 C4 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 97 F2 FF FF 8B 55 F0 B8 84 FC 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_302b
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "3.0.2b"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E82F71FFFFE89685FFFFE835A7FFFFE87CA7FFFFE86BA8FFFFE8F6FAFFFFBE24FF400033C0556828C5400064FF3064892033D25568E7C4400064FF326489228D55F033C0E897F2FFFF8B55F0B888FC40"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 2F 71 FF FF E8 96 85 FF FF E8 35 A7 FF FF E8 7C A7 FF FF E8 6B A8 FF FF E8 F6 FA FF FF BE 24 FF 40 00 33 C0 55 68 28 C5 40 00 64 FF 30 64 89 20 33 D2 55 68 E7 C4 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 97 F2 FF FF 8B 55 F0 B8 88 FC 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_303b
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "3.0.3b"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E8B370FFFFE81A85FFFFE825A7FFFFE86CA7FFFFE85BA8FFFFE8E6FAFFFFBE20FF400033C05568C8C5400064FF3064892033D2556858C5400064FF326489228D55F033C0E887F2FFFF8B55F0B884FC40"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C A7 FF FF E8 5B A8 FF FF E8 E6 FA FF FF BE 20 FF 40 00 33 C0 55 68 C8 C5 40 00 64 FF 30 64 89 20 33 D2 55 68 58 C5 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 87 F2 FF FF 8B 55 F0 B8 84 FC 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_304b_307
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "3.0.4b - 3.0.7"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E8B370FFFFE81A85FFFFE825A7FFFFE86CA7FFFFE85BA8FFFFE8E6FAFFFFBE24FF400033C05568C8C5400064FF3064892033D2556858C5400064FF326489228D55F033C0E887F2FFFF8B55F0B888FC40"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C A7 FF FF E8 5B A8 FF FF E8 E6 FA FF FF BE 24 FF 40 00 33 C0 55 68 C8 C5 40 00 64 FF 30 64 89 20 33 D2 55 68 58 C5 40 00 64 FF 32 64 89 22 8D 55 F0 33 C0 E8 87 F2 FF FF 8B 55 F0 B8 88 FC 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_400
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.0.0"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E82F6BFFFFE81280FFFFE885A2FFFFE8CCA2FFFFE8BBA3FFFFE82EF6FFFFBE34FF400033C0556815CC400064FF3064892033D25568A5CB400064FF32648922A114F04000E8E7FEFFFFE8C6F9FFFF8D55"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 2F 6B FF FF E8 12 80 FF FF E8 85 A2 FF FF E8 CC A2 FF FF E8 BB A3 FF FF E8 2E F6 FF FF BE 34 FF 40 00 33 C0 55 68 15 CC 40 00 64 FF 30 64 89 20 33 D2 55 68 A5 CB 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 C6 F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_401_402
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.0.1 - 4.0.2"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E8136BFFFFE8F67FFFFFE871A2FFFFE8B8A2FFFFE8A7A3FFFFE812F6FFFFBE2800410033C0556834CC400064FF3064892033D25568C4CB400064FF32648922A114F04000E8E7FEFFFFE8AAF9FFFF8D55"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 13 6B FF FF E8 F6 7F FF FF E8 71 A2 FF FF E8 B8 A2 FF FF E8 A7 A3 FF FF E8 12 F6 FF FF BE 28 00 41 00 33 C0 55 68 34 CC 40 00 64 FF 30 64 89 20 33 D2 55 68 C4 CB 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 AA F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_403_408
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.0.3 - 4.0.8"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E8CF6AFFFFE8B27FFFFFE82DA2FFFFE874A2FFFFE863A3FFFFE812F6FFFFBE2800410033C05568DFCC400064FF3064892033D255686FCC400064FF32648922A114F04000E8E7FEFFFFE8AAF9FFFF8D55"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 CF 6A FF FF E8 B2 7F FF FF E8 2D A2 FF FF E8 74 A2 FF FF E8 63 A3 FF FF E8 12 F6 FF FF BE 28 00 41 00 33 C0 55 68 DF CC 40 00 64 FF 30 64 89 20 33 D2 55 68 6F CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 AA F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_409
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.0.9"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E89B6AFFFFE87E7FFFFFE8F9A1FFFFE840A2FFFFE82FA3FFFFE812F6FFFFBE2800410033C0556813CD400064FF3064892033D25568A3CC400064FF32648922A114F04000E8E7FEFFFFE8AAF9FFFF8D55"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 9B 6A FF FF E8 7E 7F FF FF E8 F9 A1 FF FF E8 40 A2 FF FF E8 2F A3 FF FF E8 12 F6 FF FF BE 28 00 41 00 33 C0 55 68 13 CD 40 00 64 FF 30 64 89 20 33 D2 55 68 A3 CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 AA F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_4010
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.0.10"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E8936AFFFFE8767FFFFFE8F1A1FFFFE838A2FFFFE827A3FFFFE80AF6FFFFBE2800410033C0556832CD400064FF3064892033D25568C2CC400064FF32648922A114F04000E8E7FEFFFFE8A2F9FFFF8D55"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 93 6A FF FF E8 76 7F FF FF E8 F1 A1 FF FF E8 38 A2 FF FF E8 27 A3 FF FF E8 0A F6 FF FF BE 28 00 41 00 33 C0 55 68 32 CD 40 00 64 FF 30 64 89 20 33 D2 55 68 C2 CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 A2 F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_4011
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.0.11"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E85F6AFFFFE8427FFFFFE8BDA1FFFFE804A2FFFFE8F3A2FFFFE80EF6FFFFBE2800410033C0556866CD400064FF3064892033D25568F6CC400064FF32648922A114F04000E8E7FEFFFFE8A6F9FFFF8D55"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 5F 6A FF FF E8 42 7F FF FF E8 BD A1 FF FF E8 04 A2 FF FF E8 F3 A2 FF FF E8 0E F6 FF FF BE 28 00 41 00 33 C0 55 68 66 CD 40 00 64 FF 30 64 89 20 33 D2 55 68 F6 CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 A6 F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_410
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.1.0"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E8576AFFFFE83A7FFFFFE8B5A1FFFFE8FCA1FFFFE8EBA2FFFFE806F6FFFFBE2C00410033C055686FCD400064FF3064892033D25568FFCC400064FF32648922A114F04000E8E7FEFFFFE89EF9FFFF8D55"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 57 6A FF FF E8 3A 7F FF FF E8 B5 A1 FF FF E8 FC A1 FF FF E8 EB A2 FF FF E8 06 F6 FF FF BE 2C 00 41 00 33 C0 55 68 6F CD 40 00 64 FF 30 64 89 20 33 D2 55 68 FF CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 9E F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_411
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.1.1"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E8576AFFFFE83A7FFFFFE8B5A1FFFFE8FCA1FFFFE8EBA2FFFFE806F6FFFFBE3800410033C055686FCD400064FF3064892033D25568FFCC400064FF32648922A114F04000E8E7FEFFFFE89EF9FFFF8D55"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 57 6A FF FF E8 3A 7F FF FF E8 B5 A1 FF FF E8 FC A1 FF FF E8 EB A2 FF FF E8 06 F6 FF FF BE 38 00 41 00 33 C0 55 68 6F CD 40 00 64 FF 30 64 89 20 33 D2 55 68 FF CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 9E F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_412_413
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.1.2 - 4.1.3"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E8576AFFFFE83A7FFFFFE8B5A1FFFFE8FCA1FFFFE8EBA2FFFFE806F6FFFFBE4400410033C055686FCD400064FF3064892033D25568FFCC400064FF32648922A114F04000E8E7FEFFFFE89EF9FFFF8D55"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 57 6A FF FF E8 3A 7F FF FF E8 B5 A1 FF FF E8 FC A1 FF FF E8 EB A2 FF FF E8 06 F6 FF FF BE 44 00 41 00 33 C0 55 68 6F CD 40 00 64 FF 30 64 89 20 33 D2 55 68 FF CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 9E F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_414
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.1.4"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E8576AFFFFE83A7FFFFFE8B5A1FFFFE8FCA1FFFFE8EBA2FFFFE806F6FFFFBE4C00410033C055686FCD400064FF3064892033D25568FFCC400064FF32648922A114F04000E8E7FEFFFFE89EF9FFFF8D55"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 57 6A FF FF E8 3A 7F FF FF E8 B5 A1 FF FF E8 FC A1 FF FF E8 EB A2 FF FF E8 06 F6 FF FF BE 4C 00 41 00 33 C0 55 68 6F CD 40 00 64 FF 30 64 89 20 33 D2 55 68 FF CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 9E F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_415
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.1.5"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E8576AFFFFE83A7FFFFFE8B5A1FFFFE8FCA1FFFFE8EBA2FFFFE806F6FFFFBE5000410033C055686FCD400064FF3064892033D25568FFCC400064FF32648922A114F04000E8E7FEFFFFE89EF9FFFF8D55"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 57 6A FF FF E8 3A 7F FF FF E8 B5 A1 FF FF E8 FC A1 FF FF E8 EB A2 FF FF E8 06 F6 FF FF BE 50 00 41 00 33 C0 55 68 6F CD 40 00 64 FF 30 64 89 20 33 D2 55 68 FF CC 40 00 64 FF 32 64 89 22 A1 14 F0 40 00 E8 E7 FE FF FF E8 9E F9 FF FF 8D 55 }
	condition:
		$1 at pe.entry_point
}

rule inno_416_417
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.1.6 - 4.1.7"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E8639FFFFFE846B4FFFFE8C1D6FFFFE808D7FFFFE80BF6FFFFBE2CC0400033C055688E98400064FF3064892033D255681E98400064FF32648922A114B04000E8ECFEFFFFE8A3F9FFFF8D55F033C0E8ED"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 63 9F FF FF E8 46 B4 FF FF E8 C1 D6 FF FF E8 08 D7 FF FF E8 0B F6 FF FF BE 2C C0 40 00 33 C0 55 68 8E 98 40 00 64 FF 30 64 89 20 33 D2 55 68 1E 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 A3 F9 FF FF 8D 55 F0 33 C0 E8 ED }
	condition:
		$1 at pe.entry_point
}

rule inno_418
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.1.8"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C053565733C08945F08945C48945C0E8639FFFFFE846B4FFFFE8C1D6FFFFE808D7FFFFE80BF6FFFFBE34C0400033C055688E98400064FF3064892033D255681E98400064FF32648922A114B04000E8ECFEFFFFE8A3F9FFFF8D55F033C0E8ED"
	strings:
		$1 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 63 9F FF FF E8 46 B4 FF FF E8 C1 D6 FF FF E8 08 D7 FF FF E8 0B F6 FF FF BE 34 C0 40 00 33 C0 55 68 8E 98 40 00 64 FF 30 64 89 20 33 D2 55 68 1E 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 A3 F9 FF FF 8D 55 F0 33 C0 E8 ED }
	condition:
		$1 at pe.entry_point
}

rule inno_420
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.2.0"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E8A79EFFFFE8D2B0FFFFE829D3FFFFE870D3FFFFE80BF6FFFFBEB0BD400033C05568CD98400064FF3064892033D255685D98400064FF32648922A114B04000E8ECFEFFFFE8A3F9FFFF8D55F033C0E881"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 A7 9E FF FF E8 D2 B0 FF FF E8 29 D3 FF FF E8 70 D3 FF FF E8 0B F6 FF FF BE B0 BD 40 00 33 C0 55 68 CD 98 40 00 64 FF 30 64 89 20 33 D2 55 68 5D 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 A3 F9 FF FF 8D 55 F0 33 C0 E8 81 }
	condition:
		$1 at pe.entry_point
}

rule inno_421
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.2.1"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E89B9EFFFFE8C6B0FFFFE81DD3FFFFE864D3FFFFE8FFF5FFFFBEB4BD400033C05568D998400064FF3064892033D255686998400064FF32648922A114B04000E8ECFEFFFFE897F9FFFF8D55F033C0E875"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 9B 9E FF FF E8 C6 B0 FF FF E8 1D D3 FF FF E8 64 D3 FF FF E8 FF F5 FF FF BE B4 BD 40 00 33 C0 55 68 D9 98 40 00 64 FF 30 64 89 20 33 D2 55 68 69 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 97 F9 FF FF 8D 55 F0 33 C0 E8 75 }
	condition:
		$1 at pe.entry_point
}

rule inno_422_423
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.2.2 - 4.2.3"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E8A39EFFFFE8CEB0FFFFE825D3FFFFE86CD3FFFFE807F6FFFFBEBCBD400033C05568D098400064FF3064892033D255686098400064FF32648922A114B04000E8ECFEFFFFE89FF9FFFF8D55F033C0E87D"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 A3 9E FF FF E8 CE B0 FF FF E8 25 D3 FF FF E8 6C D3 FF FF E8 07 F6 FF FF BE BC BD 40 00 33 C0 55 68 D0 98 40 00 64 FF 30 64 89 20 33 D2 55 68 60 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 7D }
	condition:
		$1 at pe.entry_point
}

rule inno_424_426
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.2.4 -4.2.6"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E8979EFFFFE8C2B0FFFFE821D3FFFFE868D3FFFFE807F6FFFFBECCBD400033C05568DC98400064FF3064892033D255686C98400064FF32648922A114B04000E8ECFEFFFFE89FF9FFFF8D55F033C0E879"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 97 9E FF FF E8 C2 B0 FF FF E8 21 D3 FF FF E8 68 D3 FF FF E8 07 F6 FF FF BE CC BD 40 00 33 C0 55 68 DC 98 40 00 64 FF 30 64 89 20 33 D2 55 68 6C 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 79 }
	condition:
		$1 at pe.entry_point
}

rule inno_427
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "4.2.7"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E85F9EFFFFE88AB0FFFFE8E9D2FFFFE830D3FFFFE807F6FFFFBECCBD400033C055681499400064FF3064892033D25568A498400064FF32648922A114B04000E8ECFEFFFFE89FF9FFFF8D55F033C0E841"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 5F 9E FF FF E8 8A B0 FF FF E8 E9 D2 FF FF E8 30 D3 FF FF E8 07 F6 FF FF BE CC BD 40 00 33 C0 55 68 14 99 40 00 64 FF 30 64 89 20 33 D2 55 68 A4 98 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 41 }
	condition:
		$1 at pe.entry_point
}

rule inno_500
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.0.0"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E8279EFFFFE852B0FFFFE8B9D2FFFFE800D3FFFFE807F6FFFFBEC8BD400033C055687299400064FF3064892033D255680299400064FF32648922A114B04000E8ECFEFFFFE89FF9FFFF8D55F033C0E811"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 27 9E FF FF E8 52 B0 FF FF E8 B9 D2 FF FF E8 00 D3 FF FF E8 07 F6 FF FF BE C8 BD 40 00 33 C0 55 68 72 99 40 00 64 FF 30 64 89 20 33 D2 55 68 02 99 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 11 }
	condition:
		$1 at pe.entry_point
}

rule inno_501_502
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.0.1 - 5.0.2"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E8579DFFFFE88EAFFFFFE8D9D1FFFFE820D2FFFFE8FBF5FFFFBEC8BD400033C05568219A400064FF3064892033D25568D299400064FF32648922A114B04000E8ECFEFFFFE89FF9FFFF8D55F033C0E88D"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 57 9D FF FF E8 8E AF FF FF E8 D9 D1 FF FF E8 20 D2 FF FF E8 FB F5 FF FF BE C8 BD 40 00 33 C0 55 68 21 9A 40 00 64 FF 30 64 89 20 33 D2 55 68 D2 99 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 8D }
	condition:
		$1 at pe.entry_point
}

rule inno_503
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.0.3"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E89F9DFFFFE8D6AFFFFFE819D2FFFFE860D2FFFFE8FBF5FFFFBEC8BD400033C05568D999400064FF3064892033D255688A99400064FF32648922A114B04000E8ECFEFFFFE89FF9FFFF8D55F033C0E88D"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 9F 9D FF FF E8 D6 AF FF FF E8 19 D2 FF FF E8 60 D2 FF FF E8 FB F5 FF FF BE C8 BD 40 00 33 C0 55 68 D9 99 40 00 64 FF 30 64 89 20 33 D2 55 68 8A 99 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 8D }
	condition:
		$1 at pe.entry_point
}

rule inno_504
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.0.4"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E84B9DFFFFE882AFFFFFE8C5D1FFFFE80CD2FFFFE8FBF5FFFFBEC4BD400033C055682D9A400064FF3064892033D25568DE99400064FF32648922A114B04000E8ECFEFFFFE89FF9FFFF8D55F033C0E839"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 4B 9D FF FF E8 82 AF FF FF E8 C5 D1 FF FF E8 0C D2 FF FF E8 FB F5 FF FF BE C4 BD 40 00 33 C0 55 68 2D 9A 40 00 64 FF 30 64 89 20 33 D2 55 68 DE 99 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 39 }
	condition:
		$1 at pe.entry_point
}

rule inno_505_506
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.0.5 - 5.0.6"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E8BB9CFFFFE8F2AEFFFFE835D1FFFFE87CD1FFFFE8FBF5FFFFBEC4BD400033C05568BD9A400064FF3064892033D255686E9A400064FF32648922A114B04000E8ECFEFFFFE89FF9FFFF8D55F033C0E815"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 BB 9C FF FF E8 F2 AE FF FF E8 35 D1 FF FF E8 7C D1 FF FF E8 FB F5 FF FF BE C4 BD 40 00 33 C0 55 68 BD 9A 40 00 64 FF 30 64 89 20 33 D2 55 68 6E 9A 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 15 }
	condition:
		$1 at pe.entry_point
}

rule inno_507
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.0.7"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4B853565733C08945F08945BC8945B8E89F9CFFFFE8D6AEFFFFE819D1FFFFE860D1FFFFE8DFF5FFFFBEC4BD400033C05568E39A400064FF3064892033D25568949A400064FF32648922A114B04000E8ECFEFFFFE89FF9FFFF8D55F033C0E8F9"
	strings:
		$1 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 9F 9C FF FF E8 D6 AE FF FF E8 19 D1 FF FF E8 60 D1 FF FF E8 DF F5 FF FF BE C4 BD 40 00 33 C0 55 68 E3 9A 40 00 64 FF 30 64 89 20 33 D2 55 68 94 9A 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EC FE FF FF E8 9F F9 FF FF 8D 55 F0 33 C0 E8 F9 }
	condition:
		$1 at pe.entry_point
}

rule inno_508
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.0.8"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4D453565733C08945F08945E4E8E29BFFFFE88DAEFFFFE880D0FFFFE8C7D0FFFFE8DAF5FFFFBEC4BD400033C05568C09B400064FF3064892033D25568769B400064FF32648922A114B04000E8EFFEFFFFE8AEFAFFFF8D55F033C0E840D5FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 E4 E8 E2 9B FF FF E8 8D AE FF FF E8 80 D0 FF FF E8 C7 D0 FF FF E8 DA F5 FF FF BE C4 BD 40 00 33 C0 55 68 C0 9B 40 00 64 FF 30 64 89 20 33 D2 55 68 76 9B 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EF FE FF FF E8 AE FA FF FF 8D 55 F0 33 C0 E8 40 D5 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_510
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.1.0"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4D453565733C08945F08945E4E82E9BFFFFE8D9ADFFFFE8CCCFFFFFE813D0FFFFE852F5FFFFE831F9FFFFBEDCBD400033C05568799C400064FF3064892033D255682F9C400064FF32648922A114B04000E8EAFEFFFFE8A9FAFFFF8D55F033C0"
	strings:
		$1 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 E4 E8 2E 9B FF FF E8 D9 AD FF FF E8 CC CF FF FF E8 13 D0 FF FF E8 52 F5 FF FF E8 31 F9 FF FF BE DC BD 40 00 33 C0 55 68 79 9C 40 00 64 FF 30 64 89 20 33 D2 55 68 2F 9C 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EA FE FF FF E8 A9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_511
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.1.1"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4D453565733C08945F08945E4E84A9AFFFFE8F5ACFFFFE8E8CEFFFFE82FCFFFFFE86EF4FFFFE85DF5FFFFBEE0BD400033C05568619D400064FF3064892033D25568179D400064FF32648922A114B04000E8EAFEFFFFE8A9FAFFFF8D55F033C0"
	strings:
		$1 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 E4 E8 4A 9A FF FF E8 F5 AC FF FF E8 E8 CE FF FF E8 2F CF FF FF E8 6E F4 FF FF E8 5D F5 FF FF BE E0 BD 40 00 33 C0 55 68 61 9D 40 00 64 FF 30 64 89 20 33 D2 55 68 17 9D 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EA FE FF FF E8 A9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_512
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.1.2"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4D453565733C08945F08945E4E83A9AFFFFE8E5ACFFFFE8D8CEFFFFE81FCFFFFFE86EF4FFFFE85DF5FFFFBEE0BD400033C05568719D400064FF3064892033D25568279D400064FF32648922A114B04000E8EAFEFFFFE8A9FAFFFF8D55F033C0"
	strings:
		$1 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 E4 E8 3A 9A FF FF E8 E5 AC FF FF E8 D8 CE FF FF E8 1F CF FF FF E8 6E F4 FF FF E8 5D F5 FF FF BE E0 BD 40 00 33 C0 55 68 71 9D 40 00 64 FF 30 64 89 20 33 D2 55 68 27 9D 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EA FE FF FF E8 A9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_513
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.1.3 - 5.1.4"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4D453565733C08945F08945E4E8A698FFFFE851ABFFFFE854CDFFFFE89BCDFFFFE892F3FFFFE8F9F4FFFFBEE0BD400033C05568059F400064FF3064892033D25568BB9E400064FF32648922A114B04000E8EAFEFFFFE8A9FAFFFF8D55F033C0"
	strings:
		$1 = { 55 8B EC 83 C4 D4 53 56 57 33 C0 89 45 F0 89 45 E4 E8 A6 98 FF FF E8 51 AB FF FF E8 54 CD FF FF E8 9B CD FF FF E8 92 F3 FF FF E8 F9 F4 FF FF BE E0 BD 40 00 33 C0 55 68 05 9F 40 00 64 FF 30 64 89 20 33 D2 55 68 BB 9E 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 EA FE FF FF E8 A9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_516
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.1.5 - 5.1.6"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4CC53565733C08945F08945DCE8D698FFFFE8DDAAFFFFE800CDFFFFE847CDFFFFE83EF3FFFFE8A5F4FFFF33C055689A9E400064FF3064892033D25568509E400064FF32648922A114B04000E89BFEFFFFE85AFAFFFF8D55F033C0E8C0D1FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 D6 98 FF FF E8 DD AA FF FF E8 00 CD FF FF E8 47 CD FF FF E8 3E F3 FF FF E8 A5 F4 FF FF 33 C0 55 68 9A 9E 40 00 64 FF 30 64 89 20 33 D2 55 68 50 9E 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 9B FE FF FF E8 5A FA FF FF 8D 55 F0 33 C0 E8 C0 D1 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_517
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.1.7"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4CC53565733C08945F08945DCE80A98FFFFE811AAFFFFE83CCCFFFFE883CCFFFFE80AF3FFFFE871F4FFFF33C05568669F400064FF3064892033D255681C9F400064FF32648922A114B04000E89BFEFFFFE826FAFFFF8D55F033C0E8FCD0FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 0A 98 FF FF E8 11 AA FF FF E8 3C CC FF FF E8 83 CC FF FF E8 0A F3 FF FF E8 71 F4 FF FF 33 C0 55 68 66 9F 40 00 64 FF 30 64 89 20 33 D2 55 68 1C 9F 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 9B FE FF FF E8 26 FA FF FF 8D 55 F0 33 C0 E8 FC D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_518_519_5112
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.1.8 - 5.1.9, 5.1.12"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4CC53565733C08945F08945DCE8EE97FFFFE8F5A9FFFFE820CCFFFFE867CCFFFFE80AF3FFFFE871F4FFFF33C05568829F400064FF3064892033D25568389F400064FF32648922A114B04000E89BFEFFFFE826FAFFFF8D55F033C0E8E0D0FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 EE 97 FF FF E8 F5 A9 FF FF E8 20 CC FF FF E8 67 CC FF FF E8 0A F3 FF FF E8 71 F4 FF FF 33 C0 55 68 82 9F 40 00 64 FF 30 64 89 20 33 D2 55 68 38 9F 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 9B FE FF FF E8 26 FA FF FF 8D 55 F0 33 C0 E8 E0 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_5110_5111
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.1.10 - 5.1.11"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4CC53565733C08945F08945DCE8AA97FFFFE8B1A9FFFFE8DCCBFFFFE863CCFFFFE80AF3FFFFE871F4FFFF33C05568C69F400064FF3064892033D255687C9F400064FF32648922A114C04000E89BFEFFFFE826FAFFFF8D55F033C0E8E0D0FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 AA 97 FF FF E8 B1 A9 FF FF E8 DC CB FF FF E8 63 CC FF FF E8 0A F3 FF FF E8 71 F4 FF FF 33 C0 55 68 C6 9F 40 00 64 FF 30 64 89 20 33 D2 55 68 7C 9F 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 26 FA FF FF 8D 55 F0 33 C0 E8 E0 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_5113_5114
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.1.13 - 5.1.14"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4CC53565733C08945F08945DCE8FA97FFFFE801AAFFFFE82CCCFFFFE873CCFFFFE80AF3FFFFE871F4FFFF33C05568769F400064FF3064892033D255682C9F400064FF32648922A114B04000E89BFEFFFFE826FAFFFF8D55F033C0E8E0D0FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 CC 53 56 57 33 C0 89 45 F0 89 45 DC E8 FA 97 FF FF E8 01 AA FF FF E8 2C CC FF FF E8 73 CC FF FF E8 0A F3 FF FF E8 71 F4 FF FF 33 C0 55 68 76 9F 40 00 64 FF 30 64 89 20 33 D2 55 68 2C 9F 40 00 64 FF 32 64 89 22 A1 14 B0 40 00 E8 9B FE FF FF E8 26 FA FF FF 8D 55 F0 33 C0 E8 E0 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_520_521 {
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.2.0 - 5.2.1"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C453565733C08945F08945DCE83A97FFFFE841A9FFFFE86CCBFFFFE8B3CBFFFFE812F3FFFFE879F4FFFF33C0556832A0400064FF3064892033D25568FB9F400064FF32648922A114C04000E89BFEFFFFE806FAFFFF8D55F033C0E8B0D0FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 3A 97 FF FF E8 41 A9 FF FF E8 6C CB FF FF E8 B3 CB FF FF E8 12 F3 FF FF E8 79 F4 FF FF 33 C0 55 68 32 A0 40 00 64 FF 30 64 89 20 33 D2 55 68 FB 9F 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 06 FA FF FF 8D 55 F0 33 C0 E8 B0 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_522
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.2.2"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C453565733C08945F08945DCE87296FFFFE879A8FFFFE8A4CAFFFFE8EBCAFFFFE812F3FFFFE879F4FFFF33C0556802A1400064FF3064892033D25568CBA0400064FF32648922A114C04000E89BFEFFFFE806FAFFFF8D55F033C0E8B0D0FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 72 96 FF FF E8 79 A8 FF FF E8 A4 CA FF FF E8 EB CA FF FF E8 12 F3 FF FF E8 79 F4 FF FF 33 C0 55 68 02 A1 40 00 64 FF 30 64 89 20 33 D2 55 68 CB A0 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 06 FA FF FF 8D 55 F0 33 C0 E8 B0 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_523
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.2.3"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C453565733C08945F08945DCE86E96FFFFE875A8FFFFE8A0CAFFFFE8E7CAFFFFE80EF3FFFFE875F4FFFF33C055680BA1400064FF3064892033D25568D4A0400064FF32648922A114C04000E89BFEFFFFE802FAFFFF8D55F033C0E8ACD0FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 6E 96 FF FF E8 75 A8 FF FF E8 A0 CA FF FF E8 E7 CA FF FF E8 0E F3 FF FF E8 75 F4 FF FF 33 C0 55 68 0B A1 40 00 64 FF 30 64 89 20 33 D2 55 68 D4 A0 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 02 FA FF FF 8D 55 F0 33 C0 E8 AC D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_530b_538
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.3.0b - 5.3.8"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C453565733C08945F08945DCE8A295FFFFE8A9A7FFFFE8D4C9FFFFE81BCAFFFFE80EF3FFFFE875F4FFFF33C05568DBA1400064FF3064892033D25568A4A1400064FF32648922A114C04000E89BFEFFFFE802FAFFFF8D55F033C0E804D0FFFF"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 A2 95 FF FF E8 A9 A7 FF FF E8 D4 C9 FF FF E8 1B CA FF FF E8 0E F3 FF FF E8 75 F4 FF FF 33 C0 55 68 DB A1 40 00 64 FF 30 64 89 20 33 D2 55 68 A4 A1 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 02 FA FF FF 8D 55 F0 33 C0 E8 04 D0 FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_539_5311
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.3.9 - 5.3.11"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C453565733C08945F08945DCE86695FFFFE86DA7FFFFE898C9FFFFE8DFC9FFFFE80EF3FFFFE875F4FFFF33C0556817A2400064FF3064892033D25568E0A1400064FF32648922A114C04000E89BFEFFFFE802FAFFFF8D55F033C0E8C8CFFFFF"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 66 95 FF FF E8 6D A7 FF FF E8 98 C9 FF FF E8 DF C9 FF FF E8 0E F3 FF FF E8 75 F4 FF FF 33 C0 55 68 17 A2 40 00 64 FF 30 64 89 20 33 D2 55 68 E0 A1 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 9B FE FF FF E8 02 FA FF FF 8D 55 F0 33 C0 E8 C8 CF FF FF }
	condition:
		$1 at pe.entry_point
}

rule inno_5311
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.3.11"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C453565733C08945F08945DCE8AE94FFFFE8B5A6FFFFE844A9FFFFE853C9FFFFE89AC9FFFFE8C9F2FFFFE830F4FFFF33C05568D4A2400064FF3064892033D255689DA2400064FF32648922A114C04000E896FEFFFFE8C9FAFFFF8D55F033C0"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 AE 94 FF FF E8 B5 A6 FF FF E8 44 A9 FF FF E8 53 C9 FF FF E8 9A C9 FF FF E8 C9 F2 FF FF E8 30 F4 FF FF 33 C0 55 68 D4 A2 40 00 64 FF 30 64 89 20 33 D2 55 68 9D A2 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 96 FE FF FF E8 C9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_540_551
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.4.0 - 5.5.1"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C453565733C08945F08945DCE88694FFFFE88DA6FFFFE81CA9FFFFE853C9FFFFE89AC9FFFFE8C9F2FFFFE830F4FFFF33C05568FCA2400064FF3064892033D25568C5A2400064FF32648922A114C04000E896FEFFFFE8C9FAFFFF8D55F033C0"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 86 94 FF FF E8 8D A6 FF FF E8 1C A9 FF FF E8 53 C9 FF FF E8 9A C9 FF FF E8 C9 F2 FF FF E8 30 F4 FF FF 33 C0 55 68 FC A2 40 00 64 FF 30 64 89 20 33 D2 55 68 C5 A2 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 96 FE FF FF E8 C9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_552
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.5.2"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C453565733C08945F08945DCE88694FFFFE88DA6FFFFE81CA9FFFFE8BFA9FFFFE85EC9FFFFE8C9F2FFFFE830F4FFFF33C05568FCA2400064FF3064892033D25568C5A2400064FF32648922A114C04000E896FEFFFFE8C9FAFFFF8D55F033C0"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 86 94 FF FF E8 8D A6 FF FF E8 1C A9 FF FF E8 BF A9 FF FF E8 5E C9 FF FF E8 C9 F2 FF FF E8 30 F4 FF FF 33 C0 55 68 FC A2 40 00 64 FF 30 64 89 20 33 D2 55 68 C5 A2 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 96 FE FF FF E8 C9 FA FF FF 8D 55 F0 33 C0 }
	condition:
		$1 at pe.entry_point
}

rule inno_553_558
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.5.3 - 5.5.8"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C453565733C08945F08945DCE8CE8AFFFFE8D59CFFFFE8649FFFFFE807A0FFFFE8A6BFFFFFE811E9FFFFE878EAFFFF33C05568C9AC400064FF3064892033D2556892AC400064FF32648922A114C04000E826F5FFFFE811F1FFFF803D34B240"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 CE 8A FF FF E8 D5 9C FF FF E8 64 9F FF FF E8 07 A0 FF FF E8 A6 BF FF FF E8 11 E9 FF FF E8 78 EA FF FF 33 C0 55 68 C9 AC 40 00 64 FF 30 64 89 20 33 D2 55 68 92 AC 40 00 64 FF 32 64 89 22 A1 14 C0 40 00 E8 26 F5 FF FF E8 11 F1 FF FF 80 3D 34 B2 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_559
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.5.9"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4C453565733C08945F08945DCE82E86FFFFE83598FFFFE89C9BFFFFE8B79FFFFFE856BFFFFFE8EDE8FFFFE854EAFFFF33C0556869B1400064FF3064892033D2556832B1400064FF32648922A114D04000E826F5FFFFE811F1FFFF803D34C240"
	strings:
		$1 = { 55 8B EC 83 C4 C4 53 56 57 33 C0 89 45 F0 89 45 DC E8 2E 86 FF FF E8 35 98 FF FF E8 9C 9B FF FF E8 B7 9F FF FF E8 56 BF FF FF E8 ED E8 FF FF E8 54 EA FF FF 33 C0 55 68 69 B1 40 00 64 FF 30 64 89 20 33 D2 55 68 32 B1 40 00 64 FF 32 64 89 22 A1 14 D0 40 00 E8 26 F5 FF FF E8 11 F1 FF FF 80 3D 34 C2 40 }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_530b_535
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.3.0b - 5.3.5"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB8A4524100E8F002FFFF33C05568896A410064FF3064892033D25568456A410064FF32648922A118AB4100E8F6ECFFFFE801E8FFFF8D55EC33C0E88386FF"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 A4 52 41 00 E8 F0 02 FF FF 33 C0 55 68 89 6A 41 00 64 FF 30 64 89 20 33 D2 55 68 45 6A 41 00 64 FF 32 64 89 22 A1 18 AB 41 00 E8 F6 EC FF FF E8 01 E8 FF FF 8D 55 EC 33 C0 E8 83 86 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_536_537
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.3.6 - 5.3.7"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB8E8544100E87004FFFF33C05568916A410064FF3064892033D255684D6A410064FF32648922A148AB4100E83AEFFFFFE845EAFFFF8D55EC33C0E8FB87FF"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 E8 54 41 00 E8 70 04 FF FF 33 C0 55 68 91 6A 41 00 64 FF 30 64 89 20 33 D2 55 68 4D 6A 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 3A EF FF FF E8 45 EA FF FF 8D 55 EC 33 C0 E8 FB 87 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_538
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.3.8"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB8F0544100E87004FFFF33C05568916A410064FF3064892033D255684D6A410064FF32648922A148AB4100E842EFFFFFE84DEAFFFF8D55EC33C0E8FB87FF"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 E8 54 41 00 E8 70 04 FF FF 33 C0 55 68 91 6A 41 00 64 FF 30 64 89 20 33 D2 55 68 4D 6A 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 3A EF FF FF E8 45 EA FF FF 8D 55 EC 33 C0 E8 FB 87 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_539_5310
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.3.9 - 5.3.10"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB854554100E87004FFFF33C05568916A410064FF3064892033D255684D6A410064FF32648922A148AB4100E8A6EFFFFFE8B1EAFFFF8D55EC33C0E8FB87FF"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 54 55 41 00 E8 70 04 FF FF 33 C0 55 68 91 6A 41 00 64 FF 30 64 89 20 33 D2 55 68 4D 6A 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 A6 EF FF FF E8 B1 EA FF FF 8D 55 EC 33 C0 E8 FB 87 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_5311
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.3.11"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB818564100E8E403FFFF33C055681D6B410064FF3064892033D25568D96A410064FF32648922A148AB4100E8DEEFFFFFE885EBFFFF8D55EC33C0E89F87FF"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 18 56 41 00 E8 E4 03 FF FF 33 C0 55 68 1D 6B 41 00 64 FF 30 64 89 20 33 D2 55 68 D9 6A 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 DE EF FF FF E8 85 EB FF FF 8D 55 EC 33 C0 E8 9F 87 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_540_543
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.4.0 - 5.4.3"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB8B0524100E8AC03FFFF33C05568456B410064FF3064892033D25568016B410064FF32648922A148AB4100E84EECFFFFE8F5E7FFFF8D55EC33C0E87F84FF"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 B0 52 41 00 E8 AC 03 FF FF 33 C0 55 68 45 6B 41 00 64 FF 30 64 89 20 33 D2 55 68 01 6B 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 4E EC FF FF E8 F5 E7 FF FF 8D 55 EC 33 C0 E8 7F 84 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_550_551
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.5.0 - 5.5.1"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB8B8524100E8AC03FFFF33C05568456B410064FF3064892033D25568016B410064FF32648922A148AB4100E856ECFFFFE8FDE7FFFF8D55EC33C0E87F84FF"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 B8 52 41 00 E8 AC 03 FF FF 33 C0 55 68 45 6B 41 00 64 FF 30 64 89 20 33 D2 55 68 01 6B 41 00 64 FF 32 64 89 22 A1 48 AB 41 00 E8 56 EC FF FF E8 FD E7 FF FF 8D 55 EC 33 C0 E8 7F 84 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_552
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.5.2"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB864ED4000E8E871FFFF33C0556889FA400064FF3064892033D2556845FA400064FF32648922A1483B4100E8BEF7FFFFE865F3FFFF8D55EC33C0E8F7C3FF"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 64 ED 40 00 E8 E8 71 FF FF 33 C0 55 68 89 FA 40 00 64 FF 30 64 89 20 33 D2 55 68 45 FA 40 00 64 FF 32 64 89 22 A1 48 3B 41 00 E8 BE F7 FF FF E8 65 F3 FF FF 8D 55 EC 33 C0 E8 F7 C3 FF }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_553_555
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.5.3 - 5.5.5"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB82C004100E8E851FFFF33C055689E1A410064FF3064892033D255685A1A410064FF32648922A1485B4100E816D8FFFFE865D3FFFF803DDC2A410000740C"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 2C 00 41 00 E8 E8 51 FF FF 33 C0 55 68 9E 1A 41 00 64 FF 30 64 89 20 33 D2 55 68 5A 1A 41 00 64 FF 32 64 89 22 A1 48 5B 41 00 E8 16 D8 FF FF E8 65 D3 FF FF 80 3D DC 2A 41 00 00 74 0C }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_556_558
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.5.6 - 5.5.8"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB834004100E8E851FFFF33C055689E1A410064FF3064892033D255685A1A410064FF32648922A1485B4100E81ED8FFFFE86DD3FFFF803DDC2A410000740C"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 34 00 41 00 E8 E8 51 FF FF 33 C0 55 68 9E 1A 41 00 64 FF 30 64 89 20 33 D2 55 68 5A 1A 41 00 64 FF 32 64 89 22 A1 48 5B 41 00 E8 1E D8 FF FF E8 6D D3 FF FF 80 3D DC 2A 41 00 00 74 0C }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_559
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "5.5.9"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB844014100E8C84DFFFF33C05568BE1E410064FF3064892033D255687A1E410064FF32648922A1485B4100E80ED5FFFFE85DD0FFFF803DDC2A410000740C"
	strings:
		$1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 45 D8 89 45 EC B8 44 01 41 00 E8 C8 4D FF FF 33 C0 55 68 BE 1E 41 00 64 FF 30 64 89 20 33 D2 55 68 7A 1E 41 00 64 FF 32 64 89 22 A1 48 5B 41 00 E8 0E D5 FF FF E8 5D D0 FF FF 80 3D DC 2A 41 00 00 74 0C }
	condition:
		$1 at pe.entry_point
}

rule inno_unicode_600
{
	meta:
		tool = "I"
		name = "Inno Setup"
		version = "6.0.0"
		extra = "unicode version"
		source = "Made by Retdec Team"
		pattern = "558BEC83C4A453565733C08945C48945C08945A48945D08945C88945CC8945D48945D88945ECB8D8104B00E8B072F5FF33C05568DE654B0064FF3064892033D2"
	strings:
		$s01 = { 55 8b ec 83 c4 a4 53 56 57 33 c0 89 45 c4 89 45 c0 89 45 a4 89 45 d0 89 45 c8 89 45 cc 89 45 d4 89 45 d8 89 45 ec b8 d8 10 4b 00 e8 b0 72 f5 ff 33 c0 55 68 de 65 4b 00 64 ff 30 64 89 20 33 d2 }
		$s10 = "Inno Setup Setup Data (6.0.0) (u)"
		$s11 = "Inno Setup Messages (6.0.0) (u)"
	condition:
		$s01 at pe.entry_point and
		all of ($s1*)
}

rule sevenzip_sfx_3xx_01
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "3.xx"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF6808EA410068207A410064A100000000506489250000000083EC585356578965E8FF156CE1410033D28AD489154C6542008BC881E1FF000000890D48654200C1E10803CA890D44654200C1E810A3406542006A01E8DB1D00005985C075086A"
	strings:
		$1 = { 55 8B EC 6A FF 68 08 EA 41 00 68 20 7A 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 6C E1 41 00 33 D2 8A D4 89 15 4C 65 42 00 8B C8 81 E1 FF 00 00 00 89 0D 48 65 42 00 C1 E1 08 03 CA 89 0D 44 65 42 00 C1 E8 10 A3 40 65 42 00 6A 01 E8 DB 1D 00 00 59 85 C0 75 08 6A }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_3xx_02
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "3.xx"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF6870864100687C25410064A100000000506489250000000083EC585356578965E8FF157081410033D28AD4891560F441008BC881E1FF000000890D5CF44100C1E10803CA890D58F44100C1E810A354F441006A01E8ED1D00005985C075086A"
	strings:
		$1 = { 55 8B EC 6A FF 68 70 86 41 00 68 7C 25 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 70 81 41 00 33 D2 8A D4 89 15 60 F4 41 00 8B C8 81 E1 FF 00 00 00 89 0D 5C F4 41 00 C1 E1 08 03 CA 89 0D 58 F4 41 00 C1 E8 10 A3 54 F4 41 00 6A 01 E8 ED 1D 00 00 59 85 C0 75 08 6A }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_3xx_03
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "3.xx"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF680836410068340C410064A100000000506489250000000083EC685356578965E833DB895DFC6A02FF15F830410059830DDC794100FF830DE0794100FFFF15FC3041008B0DD47941008908FF15003141008B0DD07941008908A1043141008B"
	strings:
		$1 = { 55 8B EC 6A FF 68 08 36 41 00 68 34 0C 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 F8 30 41 00 59 83 0D DC 79 41 00 FF 83 0D E0 79 41 00 FF FF 15 FC 30 41 00 8B 0D D4 79 41 00 89 08 FF 15 00 31 41 00 8B 0D D0 79 41 00 89 08 A1 04 31 41 00 8B }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_42x
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "4.2x"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF68202D420068?CC3410064A100000000506489250000000083EC585356578965E8FF158421420033D28AD4891590B942008BC881E1FF000000890D8CB94200C1E10803CA890D88B94200C1E810A384B942006A01E8BD1C00005985C075086A"
	strings:
		$1 = { 55 8B EC 6A FF 68 20 2D 42 00 68 ?C C3 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 84 21 42 00 33 D2 8A D4 89 15 90 B9 42 00 8B C8 81 E1 FF 00 00 00 89 0D 8C B9 42 00 C1 E1 08 03 CA 89 0D 88 B9 42 00 C1 E8 10 A3 84 B9 42 00 6A 01 E8 BD 1C 00 00 59 85 C0 75 08 6A }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_43x_9xx
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "4.3x - 9.xx"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF68????4?0068????4?0064A100000000506489250000000083EC685356578965E833DB895DFC6A02FF15????4?0059830D????4200FF830D????4200FFFF15????4?008B0D????42008908FF15????4?008B0D????42008908A1????4?008B"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? 4? 00 68 ?? ?? 4? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 ?? ?? 4? 00 59 83 0D ?? ?? 42 00 FF 83 0D ?? ?? 42 00 FF FF 15 ?? ?? 4? 00 8B 0D ?? ?? 42 00 89 08 FF 15 ?? ?? 4? 00 8B 0D ?? ?? 42 00 89 08 A1 ?? ?? 4? 00 8B }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_15xx_16xx
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "15.xx - 16.xx"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF68????420068?44?420064A100000000506489250000000083EC685356578965E833DB895DFC6A02FF15???1420059830D74?54300FF830D78?54300FFFF15???142008B0D44?54?008908FF153??142008B0D40?54?008908A1???142008B"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? 42 00 68 ?4 4? 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 ?? ?1 42 00 59 83 0D 74 ?5 43 00 FF 83 0D 78 ?5 43 00 FF FF 15 ?? ?1 42 00 8B 0D 44 ?5 4? 00 89 08 FF 15 3? ?1 42 00 8B 0D 40 ?5 4? 00 89 08 A1 ?? ?1 42 00 8B }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_17xx
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "17.xx"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF68509B420068?44E420064A100000000506489250000000083EC685356578965E833DB895DFC6A02FF153C81420059830D34354300FF830D38354300FFFF15388142008B0D141543008908FF15348142008B0D101543008908A1308142008B"
	strings:
		$1 = { 55 8B EC 6A FF 68 50 9B 42 00 68 ?4 4E 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 E8 33 DB 89 5D FC 6A 02 FF 15 3C 81 42 00 59 83 0D 34 35 43 00 FF 83 0D 38 35 43 00 FF FF 15 38 81 42 00 8B 0D 14 15 43 00 89 08 FF 15 34 81 42 00 8B 0D 10 15 43 00 89 08 A1 30 81 42 00 8B }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_313_console
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "3.13"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF6878F8410068607C410064A100000000506489250000000083EC105356578965E8FF1510F1410033D28AD489152C7E42008BC881E1FF000000890D287E4200C1E10803CA890D247E4200C1E810A3207E42006A01E8FD1300005985C075086A"
	strings:
		$1 = { 55 8B EC 6A FF 68 78 F8 41 00 68 60 7C 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 10 53 56 57 89 65 E8 FF 15 10 F1 41 00 33 D2 8A D4 89 15 2C 7E 42 00 8B C8 81 E1 FF 00 00 00 89 0D 28 7E 42 00 C1 E1 08 03 CA 89 0D 24 7E 42 00 C1 E8 10 A3 20 7E 42 00 6A 01 E8 FD 13 00 00 59 85 C0 75 08 6A }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_42x_console
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "4.2x"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF68202C420068?0CD410064A100000000506489250000000083EC105356578965E8FF150021420033D28AD489158CBF42008BC881E1FF000000890D88BF4200C1E10803CA890D84BF4200C1E810A380BF42006A01E89F1C00005985C075086A"
	strings:
		$1 = { 55 8B EC 6A FF 68 20 2C 42 00 68 ?0 CD 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 10 53 56 57 89 65 E8 FF 15 00 21 42 00 33 D2 8A D4 89 15 8C BF 42 00 8B C8 81 E1 FF 00 00 00 89 0D 88 BF 42 00 C1 E1 08 03 CA 89 0D 84 BF 42 00 C1 E8 10 A3 80 BF 42 00 6A 01 E8 9F 1C 00 00 59 85 C0 75 08 6A }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_43x_16xx_console
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "4.3x - 16.xx"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF68????4?0068????4?0064A100000000506489250000000083EC205356578965E88365FC006A01FF15???04?0059830D????4200FF830D????4200FFFF15???04?008B0D????42008908FF15???04?008B0D????42008908A1???04?008B00"
	strings:
		$1 = { 55 8B EC 6A FF 68 ?? ?? 4? 00 68 ?? ?? 4? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 20 53 56 57 89 65 E8 83 65 FC 00 6A 01 FF 15 ?? ?0 4? 00 59 83 0D ?? ?? 42 00 FF 83 0D ?? ?? 42 00 FF FF 15 ?? ?0 4? 00 8B 0D ?? ?? 42 00 89 08 FF 15 ?? ?0 4? 00 8B 0D ?? ?? 42 00 89 08 A1 ?? ?0 4? 00 8B 00 }
	condition:
		$1 at pe.entry_point
}

rule sevenzip_sfx_17xx_console
{
	meta:
		tool = "I"
		name = "7-Zip SFX"
		version = "17.xx"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC6AFF68C076420068?C2?420064A100000000506489250000000083EC205356578965E88365FC006A01FF15DC50420059830D34064300FF830D38064300FFFF15E05042008B0DFCE542008908FF15E45042008B0DF8E542008908A1E85042008B00"
	strings:
		$1 = { 55 8B EC 6A FF 68 C0 76 42 00 68 ?C 2? 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 20 53 56 57 89 65 E8 83 65 FC 00 6A 01 FF 15 DC 50 42 00 59 83 0D 34 06 43 00 FF 83 0D 38 06 43 00 FF FF 15 E0 50 42 00 8B 0D FC E5 42 00 89 08 FF 15 E4 50 42 00 8B 0D F8 E5 42 00 89 08 A1 E8 50 42 00 8B 00 }
	condition:
		$1 at pe.entry_point
}

rule winxzip_sfx_uv_01 {
	meta:
		tool = "I"
		name = "WinZip SFX"
		pattern = "FF15??????00B12238087402B120408038007410"
	strings:
		$1 = { FF 15 ?? ?? ?? 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 }
	condition:
		$1 at pe.entry_point
}

rule winxzip_sfx_uv_02 {
	meta:
		tool = "I"
		name = "WinZip SFX"
		pattern = "53FF15??????00B3223818740380C3FE8A48014033D23ACA740A3ACB74068A480140EBF23810"
	strings:
		$1 = { 53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 }
	condition:
		$1 at pe.entry_point
}

rule winxzip_sfx_uv_03
{
	meta:
		tool = "I"
		name = "WinZip SFX"
		source = "Made by Retdec Team"
		pattern = "53FF1560704000B3223818740380C3FE408A0833D23ACA74103ACB7407408A083ACA75F5381074014052505252FF156470400050E801FCFFFF50FF15847040005B558BEC51A19C9?4000830D08A?4000FF5633F63935449?400089358C9?4000893568"
	strings:
		$1 = { 53 FF 15 60 70 40 00 B3 22 38 18 74 03 80 C3 FE 40 8A 08 33 D2 3A CA 74 10 3A CB 74 07 40 8A 08 3A CA 75 F5 38 10 74 01 40 52 50 52 52 FF 15 64 70 40 00 50 E8 01 FC FF FF 50 FF 15 84 70 40 00 5B 55 8B EC 51 A1 9C 9? 40 00 83 0D 08 A? 40 00 FF 56 33 F6 39 35 44 9? 40 00 89 35 8C 9? 40 00 89 35 68 }
	condition:
		$1 at pe.entry_point
}

rule winzip_sfx_22_personal {
	meta:
		tool = "I"
		name = "WinZip SFX"
		version = "2.2"
		extra = "personal edition"
		pattern = "53FF1558704000B3223818740380C3FE4033D28A083ACA74103ACB7407408A083ACA75F5381074014052505252FF155C70400050E815FBFFFF50FF158C7040005B"
	strings:
		$1 = { 53 FF 15 58 70 40 00 B3 22 38 18 74 03 80 C3 FE 40 33 D2 8A 08 3A CA 74 10 3A CB 74 07 40 8A 08 3A CA 75 F5 38 10 74 01 40 52 50 52 52 FF 15 5C 70 40 00 50 E8 15 FB FF FF 50 FF 15 8C 70 40 00 5B }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_01
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		pattern = "83F8087C0833D28915????40008B0D????4000C1E108C681????4000006800010000A1????4000C1E00881C0????400050FF7508FF35"
	strings:
		$1 = { 83 F8 08 7C 08 33 D2 89 15 ?? ?? 40 00 8B 0D ?? ?? 40 00 C1 E1 08 C6 81 ?? ?? 40 00 00 68 00 01 00 00 A1 ?? ?? 40 00 C1 E0 08 81 C0 ?? ?? 40 00 50 FF 75 08 FF 35 }
	condition:
		for any of them : ( $ in (pe.entry_point + 20 .. pe.entry_point + 24) )
}

rule winrar_sfx_uv_02
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		pattern = "E8????????33C050505050E8????????C356578B7C240C8BF18BCF893EE8"
	strings:
		$1 = { E8 ?? ?? ?? ?? 33 C0 50 50 50 50 E8 ?? ?? ?? ?? C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_03
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		pattern = "E8??????0050E8??????000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468??????006A006A008BC68BCFE8"
	strings:
		$1 = { E8 ?? ?? ?? 00 50 E8 ?? ?? ?? 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 ?? ?? ?? 00 6A 00 6A 00 8B C6 8B CF E8 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_04
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		pattern = "E8??????0050E8??????000000000090558BEC81C4F4F3FFFF"
	strings:
		$1 = { E8 ?? ?? ?? 00 50 E8 ?? ?? ?? 00 00 00 00 00 90 55 8B EC 81 C4 F4 F3 FF FF }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_05
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		pattern = "E8??????0050E8??????00000000009081C4F4F3FFFF"
	strings:
		$1 = { E8 ?? ?? ?? 00 50 E8 ?? ?? ?? 00 00 00 00 00 90 81 C4 F4 F3 FF FF }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_06
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		pattern = "E8??????00C300000000909052508B442410F724248BC88B442404F764240C03C88B0424F764240C03D15959C208005553565733"
	strings:
		$1 = { E8 ?? ?? ?? 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_uv_07
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		pattern = "E9????000000000000909090558BEC5356578B7D108B5D0C8B75088BD3FF751468DD????006A006A008BC68BCFE8????000081EB1001000074054B7414EB57FF"
	strings:
		$1 = { E9 ?? ?? 00 00 00 00 00 00 90 90 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 DD ?? ?? 00 6A 00 6A 00 8B C6 8B CF E8 ?? ?? 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF }
	condition:
		$1 at pe.entry_point
}

rule winrar_uv_08 {
	meta:
		tool = "I"
		name = "WinRAR SFX"
		pattern = "E9????000000000000909090????????????00??00??????????FF"
	strings:
		$1 = { E9 ?? ?? 00 00 00 00 00 00 90 90 90 ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? FF }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_35x
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.5x"
		source = "Made by Retdec Team"
		pattern = "E89B27000050E8A72201000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E54041006A006A008BC68BCFE82643000081EB1001000074054B7414EB57FF75146A6656E8F8240100B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 9B 27 00 00 50 E8 A7 22 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 40 41 00 6A 00 6A 00 8B C6 8B CF E8 26 43 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 F8 24 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_361
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.61"
		source = "Made by Retdec Team"
		pattern = "E89F28000050E8832A01000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E54041006A006A008BC68BCFE82A44000081EB1001000074054B7414EB57FF75146A6656E8DA2C0100B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 9F 28 00 00 50 E8 83 2A 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 40 41 00 6A 00 6A 00 8B C6 8B CF E8 2A 44 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 DA 2C 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_362
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.62"
		source = "Made by Retdec Team"
		pattern = "E88F28000050E8CB2901000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E54041006A006A008BC68BCFE80A44000081EB1001000074054B7414EB57FF75146A6656E8222C0100B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 8F 28 00 00 50 E8 CB 29 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 40 41 00 6A 00 6A 00 8B C6 8B CF E8 0A 44 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 22 2C 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_370
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.70"
		source = "Made by Retdec Team"
		pattern = "E82F2B000050E83F3101000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E15041006A006A008BC68BCFE85247000081EB1001000074054B7414EB57FF75146A6656E89E330100B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 2F 2B 00 00 50 E8 3F 31 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E1 50 41 00 6A 00 6A 00 8B C6 8B CF E8 52 47 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 9E 33 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_371
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.71"
		source = "Made by Retdec Team"
		pattern = "E8F32A000050E83B3301000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E15041006A006A008BC68BCFE8A247000081EB1001000074054B7414EB57FF75146A6656E89A350100B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 F3 2A 00 00 50 E8 3B 33 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E1 50 41 00 6A 00 6A 00 8B C6 8B CF E8 A2 47 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 9A 35 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_380
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.80"
		source = "Made by Retdec Team"
		pattern = "E86F2B000050E8733601000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E55041006A006A008BC68BCFE87A48000081EB1001000074054B7414EB57FF75146A6656E8DE380100B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 6F 2B 00 00 50 E8 73 36 01 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 50 41 00 6A 00 6A 00 8B C6 8B CF E8 7A 48 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 DE 38 01 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_390
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.90"
		source = "Made by Retdec Team"
		pattern = "E8E3FEFFFF33C050505050E8542B0000C356578B7C240C8BF18BCF893EE8E2A7FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E8C1ACFFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 54 2B 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 E2 A7 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 C1 AC FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_391
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.91"
		source = "Made by Retdec Team"
		pattern = "E8E3FEFFFF33C050505050E8BE2B0000C356578B7C240C8BF18BCF893EE8E2A7FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E8C1ACFFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 BE 2B 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 E2 A7 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 C1 AC FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_392
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.92"
		source = "Made by Retdec Team"
		pattern = "E8E3FEFFFF33C050505050E8BE2B0000C356578B7C240C8BF18BCF893EE8F6A7FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E8D5ACFFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 BE 2B 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 F6 A7 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 D5 AC FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_393
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.93"
		source = "Made by Retdec Team"
		pattern = "E8E3FEFFFF33C050505050E8BE2B0000C356578B7C240C8BF18BCF893EE8D0A7FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E8AFACFFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 BE 2B 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 D0 A7 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 AF AC FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_400
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.00"
		source = "Made by Retdec Team"
		pattern = "E8E3FEFFFF33C050505050E87F2D0000C356578B7C240C8BF18BCF893EE81EA1FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E847A6FFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 7F 2D 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 1E A1 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 47 A6 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_401
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.01"
		source = "Made by Retdec Team"
		pattern = "E8E3FEFFFF33C050505050E8D52D0000C356578B7C240C8BF18BCF893EE8F3A0FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E81CA6FFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 D5 2D 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 F3 A0 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 1C A6 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_410
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.10"
		source = "Made by Retdec Team"
		pattern = "E8E3FEFFFF33C050505050E8F22D0000C356578B7C240C8BF18BCF893EE8B0A1FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E8D9A6FFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 F2 2D 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 B0 A1 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 D9 A6 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_411
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.11"
		source = "Made by Retdec Team"
		pattern = "E8E3FEFFFF33C050505050E8F22D0000C356578B7C240C8BF18BCF893EE8EE9FFFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E817A5FFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 F2 2D 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 EE 9F FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 17 A5 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_420
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.20"
		source = "Made by Retdec Team"
		pattern = "E8E3FEFFFF33C050505050E89F300000C356578B7C240C8BF18BCF893EE88FABFFFF89460889560C8B87240C00008946105F8BC65EC204008BC18B088B50103B91240C0000750D6A00FF700CFF7008E80EB1FFFFC3568BF18B0685C0740750FF15C44041"
	strings:
		$1 = { E8 E3 FE FF FF 33 C0 50 50 50 50 E8 9F 30 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 8F AB FF FF 89 46 08 89 56 0C 8B 87 24 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 24 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 0E B1 FF FF C3 56 8B F1 8B 06 85 C0 74 07 50 FF 15 C4 40 41 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_50x
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.0x"
		source = "Made by Retdec Team"
		pattern = "E8F0570000E978FEFFFF8BFF558BEC568D4508508BF1E805FDFFFFC706?48142008BC65E5DC20400C701?4814200E9BAFDFFFF8BFF558BEC568BF1C706?4814200E8A7FDFFFFF6450801740756E8??C9FFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 F0 57 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 05 FD FF FF C7 06 ?4 81 42 00 8B C6 5E 5D C2 04 00 C7 01 ?4 81 42 00 E9 BA FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 ?4 81 42 00 E8 A7 FD FF FF F6 45 08 01 74 07 56 E8 ?? C9 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_510
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.10"
		source = "Made by Retdec Team"
		pattern = "E85D640000E978FEFFFF8BFF558BEC568D4508508BF1E87AFCFFFFC706F0B142008BC65E5DC20400C701F0B14200E92FFDFFFF8BFF558BEC568BF1C706F0B14200E81CFDFFFFF6450801740756E886C9FFFF598BC65E5DC204008BFF558BEC56578B7D08"
		strings:
		$1 = { E8 5D 64 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 7A FC FF FF C7 06 F0 B1 42 00 8B C6 5E 5D C2 04 00 C7 01 F0 B1 42 00 E9 2F FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 F0 B1 42 00 E8 1C FD FF FF F6 45 08 01 74 07 56 E8 86 C9 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_511
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.11"
		source = "Made by Retdec Team"
		pattern = "E85C640000E978FEFFFF8BFF558BEC568D4508508BF1E87AFCFFFFC70620B242008BC65E5DC20400C70120B24200E92FFDFFFF8BFF558BEC568BF1C70620B24200E81CFDFFFFF6450801740756E886C9FFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 5C 64 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 7A FC FF FF C7 06 20 B2 42 00 8B C6 5E 5D C2 04 00 C7 01 20 B2 42 00 E9 2F FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 20 B2 42 00 E8 1C FD FF FF F6 45 08 01 74 07 56 E8 86 C9 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_520
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.20"
		source = "Made by Retdec Team"
		pattern = "E885630000E978FEFFFF8BFF558BEC568D4508508BF1E882FCFFFFC70620B242008BC65E5DC20400C70120B24200E937FDFFFF8BFF558BEC568BF1C70620B24200E824FDFFFFF6450801740756E84ECAFFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 85 63 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 82 FC FF FF C7 06 20 B2 42 00 8B C6 5E 5D C2 04 00 C7 01 20 B2 42 00 E9 37 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 20 B2 42 00 E8 24 FD FF FF F6 45 08 01 74 07 56 E8 4E CA FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_521
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.21"
		source = "Made by Retdec Team"
		pattern = "E885630000E978FEFFFF8BFF558BEC568D4508508BF1E882FCFFFFC70620B242008BC65E5DC20400C70120B24200E937FDFFFF8BFF558BEC568BF1C70620B24200E824FDFFFFF6450801740756E852CAFFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 85 63 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 82 FC FF FF C7 06 20 B2 42 00 8B C6 5E 5D C2 04 00 C7 01 20 B2 42 00 E9 37 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 20 B2 42 00 E8 24 FD FF FF F6 45 08 01 74 07 56 E8 52 CA FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_530
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.30"
		source = "Made by Retdec Team"
		pattern = "E886630000E978FEFFFF8BFF558BEC568D4508508BF1E882FCFFFFC706F0B242008BC65E5DC20400C701F0B24200E937FDFFFF8BFF558BEC568BF1C706F0B24200E824FDFFFFF6450801740756E88ACAFFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 86 63 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 82 FC FF FF C7 06 F0 B2 42 00 8B C6 5E 5D C2 04 00 C7 01 F0 B2 42 00 E9 37 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 F0 B2 42 00 E8 24 FD FF FF F6 45 08 01 74 07 56 E8 8A CA FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_531
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.31"
		source = "Made by Retdec Team"
		pattern = "E8DF650000E978FEFFFF8BFF558BEC568D4508508BF1E882FCFFFFC70694C842008BC65E5DC20400C70194C84200E937FDFFFF8BFF558BEC568BF1C70694C84200E824FDFFFFF6450801740756E86ACAFFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 DF 65 00 00 E9 78 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 82 FC FF FF C7 06 94 C8 42 00 8B C6 5E 5D C2 04 00 C7 01 94 C8 42 00 E9 37 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 94 C8 42 00 E8 24 FD FF FF F6 45 08 01 74 07 56 E8 6A CA FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_540
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.40"
		source = "Made by Retdec Team"
		pattern = "E899040000E980FEFFFF3B0DB8914300F27502F2C3F2E90F060000836104008BC183610800C7410460FF4200C701FC084300C3558BEC56FF75088BF1E84438FFFFC706080943008BC65E5DC20400836104008BC183610800C7410410094300C701080943"
	strings:
		$1 = { E8 99 04 00 00 E9 80 FE FF FF 3B 0D B8 91 43 00 F2 75 02 F2 C3 F2 E9 0F 06 00 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 60 FF 42 00 C7 01 FC 08 43 00 C3 55 8B EC 56 FF 75 08 8B F1 E8 44 38 FF FF C7 06 08 09 43 00 8B C6 5E 5D C2 04 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 10 09 43 00 C7 01 08 09 43 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_550
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.50"
		source = "Made by Retdec Team"
		pattern = "E88A040000E98EFEFFFF3B0DB8A14300F27502F2C3F2E9FF050000836104008BC183610800C74104600F4300C70104194300C3558BEC56FF75088BF1E81C3AFFFFC706101943008BC65E5DC20400836104008BC183610800C7410418194300C701101943"
	strings:
		$1 = { E8 8A 04 00 00 E9 8E FE FF FF 3B 0D B8 A1 43 00 F2 75 02 F2 C3 F2 E9 FF 05 00 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 60 0F 43 00 C7 01 04 19 43 00 C3 55 8B EC 56 FF 75 08 8B F1 E8 1C 3A FF FF C7 06 10 19 43 00 8B C6 5E 5D C2 04 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 18 19 43 00 C7 01 10 19 43 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_350
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.50"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E8B724000050E8E79D00000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E5C040006A006A008BC68BCFE84240000081EB1001000074054B7414EB57FF75146A6656E83CA00000B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 B7 24 00 00 50 E8 E7 9D 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 42 40 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 3C A0 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_351
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.51"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E8B724000050E8FB9D00000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E5C040006A006A008BC68BCFE84240000081EB1001000074054B7414EB57FF75146A6656E850A00000B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 B7 24 00 00 50 E8 FB 9D 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 42 40 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 50 A0 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.61"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E8B725000050E8479F00000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E5C040006A006A008BC68BCFE84241000081EB1001000074054B7414EB57FF75146A6656E89CA10000B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 B7 25 00 00 50 E8 47 9F 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 42 41 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 9C A1 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_362
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.62"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E8A725000050E80B9F00000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E5C040006A006A008BC68BCFE82241000081EB1001000074054B7414EB57FF75146A6656E860A10000B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 A7 25 00 00 50 E8 0B 9F 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 22 41 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 60 A1 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_370
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.70"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E8DB27000050E8B7A200000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E1C040006A006A008BC68BCFE8FE43000081EB1001000074054B7414EB57FF75146A6656E80CA50000B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 DB 27 00 00 50 E8 B7 A2 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E1 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 FE 43 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 0C A5 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_371
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.71"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E88B27000050E84FA400000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E1C040006A006A008BC68BCFE83A44000081EB1001000074054B7414EB57FF75146A6656E8A4A60000B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 8B 27 00 00 50 E8 4F A4 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E1 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 3A 44 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 A4 A6 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_380
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.80"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E8FB27000050E863A600000000000090558BEC5356578B7D108B5D0C8B75088BD3FF751468E5C040006A006A008BC68BCFE80645000081EB1001000074054B7414EB57FF75146A6656E8C0A80000B801000000EB476681E7FFFF66FFCF740766FFCF7423"
	strings:
		$1 = { E8 FB 27 00 00 50 E8 63 A6 00 00 00 00 00 00 90 55 8B EC 53 56 57 8B 7D 10 8B 5D 0C 8B 75 08 8B D3 FF 75 14 68 E5 C0 40 00 6A 00 6A 00 8B C6 8B CF E8 06 45 00 00 81 EB 10 01 00 00 74 05 4B 74 14 EB 57 FF 75 14 6A 66 56 E8 C0 A8 00 00 B8 01 00 00 00 EB 47 66 81 E7 FF FF 66 FF CF 74 07 66 FF CF 74 23 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_391
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.91"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E81EFFFFFF33C050505050E8BF2A0000C356578B7C240C8BF18BCF893EE8139EFFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E87AA2FFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 BF 2A 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 13 9E FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 7A A2 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_392
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.92"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E81EFFFFFF33C050505050E8BF2A0000C356578B7C240C8BF18BCF893EE8229EFFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E889A2FFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 BF 2A 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 22 9E FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 89 A2 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_393
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.93"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E81EFFFFFF33C050505050E8BF2A0000C356578B7C240C8BF18BCF893EE8FC9DFFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E863A2FFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 BF 2A 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 FC 9D FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 63 A2 FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_400
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.00"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E81EFFFFFF33C050505050E8EA2B0000C356578B7C240C8BF18BCF893EE8AB98FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E8559DFFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 EA 2B 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 AB 98 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 55 9D FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_401
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.01"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E81EFFFFFF33C050505050E8402C0000C356578B7C240C8BF18BCF893EE87898FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E8229DFFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 40 2C 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 78 98 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 22 9D FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_411
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.11"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E81EFFFFFF33C050505050E85D2C0000C356578B7C240C8BF18BCF893EE8DB96FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E8D89AFFFFC3558BEC83EC1C5633F6565656568D45"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 5D 2C 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 DB 96 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 D8 9A FF FF C3 55 8B EC 83 EC 1C 56 33 F6 56 56 56 56 8D 45 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_420
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.20"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E81EFFFFFF33C050505050E8A42E0000C356578B7C240C8BF18BCF893EE87DA2FFFF89460889560C8B87240C00008946105F8BC65EC204008BC18B088B50103B91240C0000750D6A00FF700CFF7008E88FA7FFFFC3568BF18B0685C0740750FF1564F140"
	strings:
		$1 = { E8 1E FF FF FF 33 C0 50 50 50 50 E8 A4 2E 00 00 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 7D A2 FF FF 89 46 08 89 56 0C 8B 87 24 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 24 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 8F A7 FF FF C3 56 8B F1 8B 06 85 C0 74 07 50 FF 15 64 F1 40 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_501
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.01"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E89C580000E978FEFFFF558BEC83EC04897DFC8B7D088B4D0CC1E907660FEFC0EB088DA4240000000090660F7F07660F7F4710660F7F4720660F7F4730660F7F4740660F7F4750660F7F4760660F7F47708DBF800000004975D08B7DFC8BE55DC3558BEC"
	strings:
		$1 = { E8 9C 58 00 00 E9 78 FE FF FF 55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3 55 8B EC }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_510
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.1x"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E811650000E978FEFFFF558BEC83EC04897DFC8B7D088B4D0CC1E907660FEFC0EB088DA4240000000090660F7F07660F7F4710660F7F4720660F7F4730660F7F4740660F7F4750660F7F4760660F7F47708DBF800000004975D08B7DFC8BE55DC3558BEC"
	strings:
		$1 = { E8 11 65 00 00 E9 78 FE FF FF 55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3 55 8B EC }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_52x
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.2x"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E82D640000E978FEFFFF558BEC83EC04897DFC8B7D088B4D0CC1E907660FEFC0EB088DA4240000000090660F7F07660F7F4710660F7F4720660F7F4730660F7F4740660F7F4750660F7F4760660F7F47708DBF800000004975D08B7DFC8BE55DC3558BEC"
	strings:
		$1 = { E8 2D 64 00 00 E9 78 FE FF FF 55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3 55 8B EC }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_530
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.30"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E82E640000E978FEFFFF558BEC83EC04897DFC8B7D088B4D0CC1E907660FEFC0EB088DA4240000000090660F7F07660F7F4710660F7F4720660F7F4730660F7F4740660F7F4750660F7F4760660F7F47708DBF800000004975D08B7DFC8BE55DC3558BEC"
	strings:
		$1 = { E8 2E 64 00 00 E9 78 FE FF FF 55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3 55 8B EC }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_531
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.31"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E887660000E978FEFFFF558BEC83EC04897DFC8B7D088B4D0CC1E907660FEFC0EB088DA4240000000090660F7F07660F7F4710660F7F4720660F7F4730660F7F4740660F7F4750660F7F4760660F7F47708DBF800000004975D08B7DFC8BE55DC3558BEC"
	strings:
		$1 = { E8 87 66 00 00 E9 78 FE FF FF 55 8B EC 83 EC 04 89 7D FC 8B 7D 08 8B 4D 0C C1 E9 07 66 0F EF C0 EB 08 8D A4 24 00 00 00 00 90 66 0F 7F 07 66 0F 7F 47 10 66 0F 7F 47 20 66 0F 7F 47 30 66 0F 7F 47 40 66 0F 7F 47 50 66 0F 7F 47 60 66 0F 7F 47 70 8D BF 80 00 00 00 49 75 D0 8B 7D FC 8B E5 5D C3 55 8B EC }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_540
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.40"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E809050000E980FEFFFF3B0DA8B04200F27502F2C3F2E97E060000E9894C0000558BEC8325607945000083EC2C5333DB43091DACB042006A0AE8BD1B010085C00F84740100008365EC0033C0830DACB042000233C95657891D607945008D7DD4530FA28B"
	strings:
		$1 = { E8 09 05 00 00 E9 80 FE FF FF 3B 0D A8 B0 42 00 F2 75 02 F2 C3 F2 E9 7E 06 00 00 E9 89 4C 00 00 55 8B EC 83 25 60 79 45 00 00 83 EC 2C 53 33 DB 43 09 1D AC B0 42 00 6A 0A E8 BD 1B 01 00 85 C0 0F 84 74 01 00 00 83 65 EC 00 33 C0 83 0D AC B0 42 00 02 33 C9 56 57 89 1D 60 79 45 00 8D 7D D4 53 0F A2 8B }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_zip_550
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.50"
		extra = "with ZIP payload"
		source = "Made by Retdec Team"
		pattern = "E8E6040000E98EFEFFFF3B0DA8D04200F27502F2C3F2E95B060000E9E7490000558BEC832588CE45000083EC285333DB43091DACD042006A0AE84B19010085C00F846D0100008365F00033C0830DACD042000233C95657891D88CE45008D7DD8530FA28B"
	strings:
		$1 = { E8 E6 04 00 00 E9 8E FE FF FF 3B 0D A8 D0 42 00 F2 75 02 F2 C3 F2 E9 5B 06 00 00 E9 E7 49 00 00 55 8B EC 83 25 88 CE 45 00 00 83 EC 28 53 33 DB 43 09 1D AC D0 42 00 6A 0A E8 4B 19 01 00 85 C0 0F 84 6D 01 00 00 83 65 F0 00 33 C0 83 0D AC D0 42 00 02 33 C9 56 57 89 1D 88 CE 45 00 8D 7D D8 53 0F A2 8B }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_35x
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.5x"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E833FC0000C300000000909052508B442410F724248BC88B442404F764240C03C88B0424F764240C03D15959C208005553565733FF8B5C24148B4C24180BC97514909090900BD2747C909090900BDB7474909090900BD2790E90909090F7DAF7D883DA00"
	strings:
		$1 = { E8 33 FC 00 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 FF 8B 5C 24 14 8B 4C 24 18 0B C9 75 14 90 90 90 90 0B D2 74 7C 90 90 90 90 0B DB 74 74 90 90 90 90 0B D2 79 0E 90 90 90 90 F7 DA F7 D8 83 DA 00 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_36x
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.6x"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E863030100C300000000909052508B442410F724248BC88B442404F764240C03C88B0424F764240C03D15959C208005553565733FF8B5C24148B4C24180BC97514909090900BD2747C909090900BDB7474909090900BD2790E90909090F7DAF7D883DA00"
	strings:
		$1 = { E8 63 03 01 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 FF 8B 5C 24 14 8B 4C 24 18 0B C9 75 14 90 90 90 90 0B D2 74 7C 90 90 90 90 0B DB 74 74 90 90 90 90 0B D2 79 0E 90 90 90 90 F7 DA F7 D8 83 DA 00 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_370
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.70"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E8EB060100C300000000909052508B442410F724248BC88B442404F764240C03C88B0424F764240C03D15959C208005553565733FF8B5C24148B4C24180BC97514909090900BD2747C909090900BDB7474909090900BD2790E90909090F7DAF7D883DA00"
	strings:
		$1 = { E8 EB 06 01 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 FF 8B 5C 24 14 8B 4C 24 18 0B C9 75 14 90 90 90 90 0B D2 74 7C 90 90 90 90 0B DB 74 74 90 90 90 90 0B D2 79 0E 90 90 90 90 F7 DA F7 D8 83 DA 00 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_371
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.71"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E853090100C300000000909052508B442410F724248BC88B442404F764240C03C88B0424F764240C03D15959C208005553565733FF8B5C24148B4C24180BC97514909090900BD2747C909090900BDB7474909090900BD2790E90909090F7DAF7D883DA00"
	strings:
		$1 = { E8 53 09 01 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 FF 8B 5C 24 14 8B 4C 24 18 0B C9 75 14 90 90 90 90 0B D2 74 7C 90 90 90 90 0B DB 74 74 90 90 90 90 0B D2 79 0E 90 90 90 90 F7 DA F7 D8 83 DA 00 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_380
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.80"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E8AB0B0100C300000000909052508B442410F724248BC88B442404F764240C03C88B0424F764240C03D15959C208005553565733FF8B5C24148B4C24180BC97514909090900BD2747C909090900BDB7474909090900BD2790E90909090F7DAF7D883DA00"
	strings:
		$1 = { E8 AB 0B 01 00 C3 00 00 00 00 90 90 52 50 8B 44 24 10 F7 24 24 8B C8 8B 44 24 04 F7 64 24 0C 03 C8 8B 04 24 F7 64 24 0C 03 D1 59 59 C2 08 00 55 53 56 57 33 FF 8B 5C 24 14 8B 4C 24 18 0B C9 75 14 90 90 90 90 0B D2 74 7C 90 90 90 90 0B DB 74 74 90 90 90 90 0B D2 79 0E 90 90 90 90 F7 DA F7 D8 83 DA 00 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_391
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.91"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC51C745FCD9F24000E82FFFFFFF8D45FC506A01E8AED4FFFF5959C9C356578B7C240C8BF18BCF893EE895ADFFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E87EB2FFFFC355"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC D9 F2 40 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 AE D4 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 95 AD FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 7E B2 FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_392
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.92"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC51C745FCD9F24000E82FFFFFFF8D45FC506A01E8AED4FFFF5959C9C356578B7C240C8BF18BCF893EE8A4ADFFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E88DB2FFFFC355"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC D9 F2 40 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 AE D4 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 A4 AD FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 8D B2 FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_393
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "3.93"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC51C745FCD9F24000E82FFFFFFF8D45FC506A01E8AED4FFFF5959C9C356578B7C240C8BF18BCF893EE87EADFFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E867B2FFFFC355"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC D9 F2 40 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 AE D4 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 7E AD FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 67 B2 FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_400
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.00"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC51C745FC41034100E82FFFFFFF8D45FC506A01E840D1FFFF5959C9C356578B7C240C8BF18BCF893EE8C5A6FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E8F8ABFFFFC355"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC 41 03 41 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 40 D1 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 C5 A6 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 F8 AB FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_401
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.01"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC51C745FC41034100E82FFFFFFF8D45FC506A01E83ED1FFFF5959C9C356578B7C240C8BF18BCF893EE8C3A6FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E8F6ABFFFFC355"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC 41 03 41 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 3E D1 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 C3 A6 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 F6 AB FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_411
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.11"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC51C745FC41034100E82FFFFFFF8D45FC506A01E88CD0FFFF5959C9C356578B7C240C8BF18BCF893EE89BA5FFFF89460889560C8B871C0C00008946105F8BC65EC204008BC18B088B50103B911C0C0000750D6A00FF700CFF7008E8CEAAFFFFC355"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC 41 03 41 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 8C D0 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 9B A5 FF FF 89 46 08 89 56 0C 8B 87 1C 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 1C 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 CE AA FF FF C3 55 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_420
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "4.20"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "558BEC51C745FC55134100E82FFFFFFF8D45FC506A01E88AD0FFFF5959C9C356578B7C240C8BF18BCF893EE82AA4FFFF89460889560C8B87240C00008946105F8BC65EC204008BC18B088B50103B91240C0000750D6A00FF700CFF7008E8B3A9FFFFC356"
	strings:
		$1 = { 55 8B EC 51 C7 45 FC 55 13 41 00 E8 2F FF FF FF 8D 45 FC 50 6A 01 E8 8A D0 FF FF 59 59 C9 C3 56 57 8B 7C 24 0C 8B F1 8B CF 89 3E E8 2A A4 FF FF 89 46 08 89 56 0C 8B 87 24 0C 00 00 89 46 10 5F 8B C6 5E C2 04 00 8B C1 8B 08 8B 50 10 3B 91 24 0C 00 00 75 0D 6A 00 FF 70 0C FF 70 08 E8 B3 A9 FF FF C3 56 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_501
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.01"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E8AE610000E9A4FEFFFF8BFF558BEC568D4508508BF1E831FDFFFFC706A45F42008BC65E5DC20400C701A45F4200E9E6FDFFFF8BFF558BEC568BF1C706A45F4200E8D3FDFFFFF6450801740756E815C1FFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 AE 61 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 31 FD FF FF C7 06 A4 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 A4 5F 42 00 E9 E6 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 A4 5F 42 00 E8 D3 FD FF FF F6 45 08 01 74 07 56 E8 15 C1 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_510
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.10"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E88F620000E9A4FEFFFF8BFF558BEC568D4508508BF1E829FDFFFFC706B45F42008BC65E5DC20400C701B45F4200E9DEFDFFFF8BFF558BEC568BF1C706B45F4200E8CBFDFFFFF6450801740756E851C1FFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 8F 62 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 29 FD FF FF C7 06 B4 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 B4 5F 42 00 E9 DE FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 B4 5F 42 00 E8 CB FD FF FF F6 45 08 01 74 07 56 E8 51 C1 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_511
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.11"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E88F620000E9A4FEFFFF8BFF558BEC568D4508508BF1E829FDFFFFC706C45F42008BC65E5DC20400C701C45F4200E9DEFDFFFF8BFF558BEC568BF1C706C45F4200E8CBFDFFFFF6450801740756E84DC1FFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 8F 62 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 29 FD FF FF C7 06 C4 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 C4 5F 42 00 E9 DE FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 C4 5F 42 00 E8 CB FD FF FF F6 45 08 01 74 07 56 E8 4D C1 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_520
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.20"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E8B1610000E9A4FEFFFF8BFF558BEC568D4508508BF1E831FDFFFFC706C45F42008BC65E5DC20400C701C45F4200E9E6FDFFFF8BFF558BEC568BF1C706C45F4200E8D3FDFFFFF6450801740756E81DC2FFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 B1 61 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 31 FD FF FF C7 06 C4 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 C4 5F 42 00 E9 E6 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 C4 5F 42 00 E8 D3 FD FF FF F6 45 08 01 74 07 56 E8 1D C2 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_521
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.21"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E8B1610000E9A4FEFFFF8BFF558BEC568D4508508BF1E831FDFFFFC706C45F42008BC65E5DC20400C701C45F4200E9E6FDFFFF8BFF558BEC568BF1C706C45F4200E8D3FDFFFFF6450801740756E819C2FFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 B1 61 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 31 FD FF FF C7 06 C4 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 C4 5F 42 00 E9 E6 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 C4 5F 42 00 E8 D3 FD FF FF F6 45 08 01 74 07 56 E8 19 C2 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_530
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.30"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E8B1610000E9A4FEFFFF8BFF558BEC568D4508508BF1E831FDFFFFC706885F42008BC65E5DC20400C701885F4200E9E6FDFFFF8BFF558BEC568BF1C706885F4200E8D3FDFFFFF6450801740756E821C2FFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 B1 61 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 31 FD FF FF C7 06 88 5F 42 00 8B C6 5E 5D C2 04 00 C7 01 88 5F 42 00 E9 E6 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 88 5F 42 00 E8 D3 FD FF FF F6 45 08 01 74 07 56 E8 21 C2 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_531
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.31"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E80B640000E9A4FEFFFF8BFF558BEC568D4508508BF1E831FDFFFFC706346642008BC65E5DC20400C70134664200E9E6FDFFFF8BFF558BEC568BF1C70634664200E8D3FDFFFFF6450801740756E8FDC1FFFF598BC65E5DC204008BFF558BEC56578B7D08"
	strings:
		$1 = { E8 0B 64 00 00 E9 A4 FE FF FF 8B FF 55 8B EC 56 8D 45 08 50 8B F1 E8 31 FD FF FF C7 06 34 66 42 00 8B C6 5E 5D C2 04 00 C7 01 34 66 42 00 E9 E6 FD FF FF 8B FF 55 8B EC 56 8B F1 C7 06 34 66 42 00 E8 D3 FD FF FF F6 45 08 01 74 07 56 E8 FD C1 FF FF 59 8B C6 5E 5D C2 04 00 8B FF 55 8B EC 56 57 8B 7D 08 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_540
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.40"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E8B0040000E97AFEFFFF3B0DA4714300F27502F2C3F2E925060000836104008BC183610800C7410474F54200C70194F64200C3558BEC56FF75088BF1E83F81FFFFC706A0F642008BC65E5DC20400836104008BC183610800C74104A8F64200C701A0F642"
	strings:
		$1 = { E8 B0 04 00 00 E9 7A FE FF FF 3B 0D A4 71 43 00 F2 75 02 F2 C3 F2 E9 25 06 00 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 74 F5 42 00 C7 01 94 F6 42 00 C3 55 8B EC 56 FF 75 08 8B F1 E8 3F 81 FF FF C7 06 A0 F6 42 00 8B C6 5E 5D C2 04 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 A8 F6 42 00 C7 01 A0 F6 42 }
	condition:
		$1 at pe.entry_point
}

rule winrar_sfx_console_550
{
	meta:
		tool = "I"
		name = "WinRAR SFX"
		version = "5.50"
		extra = "console version"
		source = "Made by Retdec Team"
		pattern = "E894040000E987FEFFFF3B0DA4714300F27502F2C3F2E90A060000836104008BC183610800C7410474F54200C7019CF64200C3558BEC56FF75088BF1E8D882FFFFC706A8F642008BC65E5DC20400836104008BC183610800C74104B0F64200C701A8F642"
	strings:
		$1 = { E8 94 04 00 00 E9 87 FE FF FF 3B 0D A4 71 43 00 F2 75 02 F2 C3 F2 E9 0A 06 00 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 74 F5 42 00 C7 01 9C F6 42 00 C3 55 8B EC 56 FF 75 08 8B F1 E8 D8 82 FF FF C7 06 A8 F6 42 00 8B C6 5E 5D C2 04 00 83 61 04 00 8B C1 83 61 08 00 C7 41 04 B0 F6 42 00 C7 01 A8 F6 42 }
	condition:
		$1 at pe.entry_point
}

rule wix_toolset_3x
{
	meta:
		tool = "I"
		name = "WiX Toolset"
		version = "3.x"
		source = "Made by RetDec Team"
	strings:
		$s01 = ".wixburn"
		$s02 = "Failed to find Burn section"
		$s03 = "Failed to read section info, data to short: %u"
		$h04 = {00 43 F1 00 02 00 00 00}	// Wix section header + version
	condition:
		for any section in pe.sections : ((section.name == ".wixburn") and ($h04 at section.raw_data_offset)) and
		all of them
}

rule xt_app_launcher
{
	meta:
		tool = "I"
		name = "Xenocode Application Launcher"
		source = "Made by RetDec Team"
	strings:
		$h00 = { 8b 4f 3c 03 cf 0f b7 51 14 56 8d 74 0a 18 0f b7 51 06 33 c0 85 d2 76 16 8d 4e 10 8b 31 85 f6 74 07 8b 41 04 03 c6 03 c7 83 c1 28 4a 75 ed 2b c7 5e c3 }
		$h01 = { 55 8b ec 51 8b 4f 3c 03 cf 0f b7 51 14 53 0f b7 59 06 33 c0 8d 54 0a 18 89 45 fc 3b d8 76 29 83 c2 14 56 8b 72 fc 85 f6 74 12 8b 0a 8d 04 0e 83 e1 11 }
	condition:
		pe.number_of_sections == 6 and
		pe.sections[2].name == ".xcpad" and
		pe.overlay.size != 0 and
		any of them
}

rule inno_610
{
         meta:
                tool = "I"
                name = "Inno Setup"
                version = "6.1.0"
                author = "Thomas Roccia"
                pattern = "entry-point: 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 "
         strings:
                $s1 = { 55 8B EC 83 C4 A4 53 56 57 33 C0 89 45 C4 89 45 C0 89 45 A4 89 45 D0 89 45 C8 89 45 CC 89 45 D4 89 }
                $s2 = "Inno Setup Setup Data (6.1.0) (u)" fullword wide ascii
                $s3 =  "Inno Setup Messages (6.0.0) (u)" fullword wide ascii
         condition:
                $s1 at pe.entry_point and
                all of ($s*)
}
