/*
 * YARA rules for ARM Mach-O packer detection.
 * Copyright (c) 2017 Avast Software, licensed under the MIT license
 */

import "macho"

rule upx_391_lzma
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [LZMA]"
		pattern = "04D04DE2FFDF2DE9B90200EB00C0DDE50E005CE37902001A0C482DE900B0D0E506CCA0E3ABB1A0E11CCBA0E10DB0A0E1"
	strings:
		$1 = { 04 D0 4D E2 FF DF 2D E9 B9 02 00 EB 00 C0 DD E5 0E 00 5C E3 79 02 00 1A 0C 48 2D E9 00 B0 D0 E5 06 CC A0 E3 AB B1 A0 E1 1C CB A0 E1 0D B0 A0 E1 }
	condition:
		$1 at macho.entry_point or $1 at macho.ep_for_arch(macho.CPU_TYPE_ARM)
}

rule upx_391_nrv2b
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2B]"
		pattern = "04D04DE2FFDF2DE9790000EB001081E03E402DE90050E0E30241A0E31F0000EA"
	strings:
		$1 = { 04 D0 4D E2 FF DF 2D E9 79 00 00 EB 00 10 81 E0 3E 40 2D E9 00 50 E0 E3 02 41 A0 E3 1F 00 00 EA }
	condition:
		$1 at macho.entry_point or $1 at macho.ep_for_arch(macho.CPU_TYPE_ARM)
}

rule upx_391_nrv2d
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2D]"
		pattern = "04D04DE2FFDF2DE9880000EBFC402DE9007081E00050E0E30241A0E3160000EA"
	strings:
		$1 = { 04 D0 4D E2 FF DF 2D E9 88 00 00 EB FC 40 2D E9 00 70 81 E0 00 50 E0 E3 02 41 A0 E3 16 00 00 EA }
	condition:
		$1 at macho.entry_point or $1 at macho.ep_for_arch(macho.CPU_TYPE_ARM)
}

rule upx_391_nrv2e
{
	meta:
		tool = "P"
		name = "UPX"
		version = "3.91 [NRV2E]"
		pattern = "04D04DE2FFDF2DE98D0000EBFC402DE9007081E00050E0E30241A0E3160000EA"
	strings:
		$1 = { 04 D0 4D E2 FF DF 2D E9 8D 00 00 EB FC 40 2D E9 00 70 81 E0 00 50 E0 E3 02 41 A0 E3 16 00 00 EA }
	condition:
		$1 at macho.entry_point or $1 at macho.ep_for_arch(macho.CPU_TYPE_ARM)
}
