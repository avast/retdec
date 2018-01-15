/**
 * @file src/cpdetect/signatures/yara/database/x86/pe/packer/packer_57.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *x86PePacker_57 =
R"x86_pe_packer(
rule rule_1551_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.0"
		pattern = "55FF96????????09C07407890383C304EB??FF96????????8BAE????????8DBE00F0FFFFBB0010000050546A045357FFD58D87????000080207F8060287F585054505357FFD558618D4424806A0039C475FA83EC80E9"
	strings:
		$1 = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 ?? ?? 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1552_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.90 [LZMA]"
		extra = "Delphi stub"
		pattern = "60BE????????8DBE????????C787????????????????5783CDFF89E58D9C24????????31C05039DC75FB46465368????????5783C3045368????????5683C304"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1553_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.90 [LZMA]"
		pattern = "60BE????????8DBE????????5783CDFF89E58D9C24????????31C05039DC75FB46465368????????5783C3045368????????5683C3045350C703????????9090"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1554_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.90 [LZMA]"
		pattern = "60BE????????8DBE????????5783CDFFEB109090909090908A064688074701DB75078B1E83EEFC11DB72EDB80100000001DB75078B1E83EEFC11DB11C001DB"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1555_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.91"
		pattern = "680004F50FE80200000050C35589E581EC0C020000C785F4FDFFFF48757920C785F8FDFFFF76616D2166C785FCFDFFFF2121"
	strings:
		$1 = { 68 00 04 F5 0F E8 02 00 00 00 50 C3 55 89 E5 81 EC 0C 02 00 00 C7 85 F4 FD FF FF 48 75 79 20 C7 85 F8 FD FF FF 76 61 6D 21 66 C7 85 FC FD FF FF 21 21 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1556_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.91"
		pattern = "E8100000006AFF6A006823010000E80A00000050C3C8000004C958EBE85589E581ECF4030000C7850CFCFFFF31323334"
	strings:
		$1 = { E8 10 00 00 00 6A FF 6A 00 68 23 01 00 00 E8 0A 00 00 00 50 C3 C8 00 00 04 C9 58 EB E8 55 89 E5 81 EC F4 03 00 00 C7 85 0C FC FF FF 31 32 33 34 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1557_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "2.93 - 3.00 [LZMA]"
		pattern = "60BE????????8DBE????????5789E58D9C24????????31C05039DC75FB46465368????????5783C3045368????????5683C3045350C703030002009090909090"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1558_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.0"
		pattern = "5557565383EC7C8B942490000000C744247400000000C6442473008BAC249C0000008D420489442478B8010000000FB64A0289C3D3E389D949894C246C0FB64A01D3E048894424688B8424A80000000FB632"
	strings:
		$1 = { 55 57 56 53 83 EC 7C 8B 94 24 90 00 00 00 C7 44 24 74 00 00 00 00 C6 44 24 73 00 8B AC 24 9C 00 00 00 8D 42 04 89 44 24 78 B8 01 00 00 00 0F B6 4A 02 89 C3 D3 E3 89 D9 49 89 4C 24 6C 0F B6 4A 01 D3 E0 48 89 44 24 68 8B 84 24 A8 00 00 00 0F B6 32 }
	condition:
		for any of them : ( $ in (pe.entry_point + 48 .. pe.entry_point + 80) )
}
rule rule_1559_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.0"
		pattern = "E8????????5883D80589C383C3308B433905000040008B4B3D89C689C78CD88EC0B400AC30E088C4AAE2F88B430850C3"
	strings:
		$1 = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 83 C3 30 8B 43 39 05 00 00 40 00 8B 4B 3D 89 C6 89 C7 8C D8 8E C0 B4 00 AC 30 E0 88 C4 AA E2 F8 8B 43 08 50 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1560_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "0.1x modified"
		pattern = "50BE????????8DBE????????5783CD"
	strings:
		$1 = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1561_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified stub"
		pattern = "01DB078B1E83EEFC11DBEDB80100000001DB078B1E83EEFC11DB11C001DB730B"
	strings:
		$1 = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1562_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified stub"
		pattern = "60BE????????8DBE????????5783CDFFFCB28031DBA4B302E86D00000073F631C9E864000000731C31C0E85B0000007323B30241B010E84F00000010C073F7753FAAEBD4E84D00000029D97510E842000000EB28ACD1E8744D11C9EB1C9148C1E008ACE82C0000003D007D0000730A80FC05730683F87F770241419589E8B3015689FE29C6F3A45EEB8E00D275058A164610D2C331C941E8EEFFFFFF11C9E8E7FFFFFF72F2C331"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1563_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified stub"
		pattern = "60BE????????8DBE????????5783CDFFFCB280E8000000005B83C366A4FFD373FB31C9FFD3731431C0FFD3731D41B010FFD310C073FA753CAAEBE2E84A00000049E210E840000000EB28ACD1E8744511C9EB1C9148C1E008ACE82A0000003D007D0000730A80FC05730683F87F770241419589E85689FE29C6F3A45EEB9F00D275058A164610D2C331C941FFD311C9FFD372F8C331C031DB31C95E89F7B9????????8A07472CE8"
	strings:
		$1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2A 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 56 89 FE 29 C6 F3 A4 5E EB 9F 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 FF D3 11 C9 FF D3 72 F8 C3 31 C0 31 DB 31 C9 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1564_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified stub"
		pattern = "79070FB707475047B95748F2AE55FF9684??000009C07407890383C304EBD8FF9688??000061E9??????FF"
	strings:
		$1 = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 ?? ?? ?? FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1565_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified"
		pattern = "558BEC83C4F860C645FF00C745F8000000008B7D088B750C8B55108B5D1C33C9EB2C8BC103C33B452077735156"
	strings:
		$1 = { 55 8B EC 83 C4 F8 60 C6 45 FF 00 C7 45 F8 00 00 00 00 8B 7D 08 8B 75 0C 8B 55 10 8B 5D 1C 33 C9 EB 2C 8B C1 03 C3 3B 45 20 77 73 51 56 }
	condition:
		for any of them : ( $ in (pe.entry_point .. pe.entry_point + 192) )
}
rule rule_1566_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified"
		pattern = "807C2408010F85??01000060BE00????108DBE00????FF5783CDFFEB0F9090908A0634554688074701DB750950B020E8??0000005872E9B80100000050B001E8"
	strings:
		$1 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 BE 00 ?? ?? 10 8D BE 00 ?? ?? FF 57 83 CD FF EB 0F 90 90 90 8A 06 34 55 46 88 07 47 01 DB 75 09 50 B0 20 E8 ?? 00 00 00 58 72 E9 B8 01 00 00 00 50 B0 01 E8 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1567_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "modified"
		pattern = "E800000000558B6C2404816C2404????0000E8????00008BC8E8??0100002BC13D000100000F83??0000008B5C240881E300F0FFFF81ED05104000803B4D7513"
	strings:
		$1 = { E8 00 00 00 00 55 8B 6C 24 04 81 6C 24 04 ?? ?? 00 00 E8 ?? ?? 00 00 8B C8 E8 ?? 01 00 00 2B C1 3D 00 01 00 00 0F 83 ?? 00 00 00 8B 5C 24 08 81 E3 00 F0 FF FF 81 ED 05 10 40 00 80 3B 4D 75 13 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1568_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "1.0x Protector"
		pattern = "EB??????????8A064688074701DB75078B1E83EEFC11DB"
	strings:
		$1 = { EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1569_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "1.0 Inliner"
		pattern = "9C60E8000000005DB8B38540002DAC8540002BE88DB5D5FEFFFF8B0683F80074118DB5E1FEFFFF8B0683F8010F84F1010000C706010000008BD58B85B1FEFFFF2BD08995B1FEFFFF0195C9FEFFFF8DB5E5FEFFFF01168B368BFD606A40680010000068001000006A00FF9505FFFFFF85C00F84060300008985C5FEFFFFE8000000005BB93189400081E92E86400003D95053E83D0200006103BDA9FEFFFF8BDF833F00750A83C7"
	strings:
		$1 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 05 FF FF FF 85 C0 0F 84 06 03 00 00 89 85 C5 FE FF FF E8 00 00 00 00 5B B9 31 89 40 00 81 E9 2E 86 40 00 03 D9 50 53 E8 3D 02 00 00 61 03 BD A9 FE FF FF 8B DF 83 3F 00 75 0A 83 C7 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1570_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "UPX$HiT 0.0.1"
		pattern = "94BC??????00B9??00000080340C??E2FA94FFE061"
	strings:
		$1 = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }
	condition:
		$1
}
rule rule_1571_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "UPX$HiT 0.0.1"
		pattern = "E2FA94FFE06100000000000000"
	strings:
		$1 = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }
	condition:
		$1
}
rule rule_1572_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "UPX$HiT 0.0.1"
		pattern = "E8????????5E83C6??AD89C7AD89C1AD300747E2??ADFFE0C3"
	strings:
		$1 = { E8 ?? ?? ?? ?? 5E 83 C6 ?? AD 89 C7 AD 89 C1 AD 30 07 47 E2 ?? AD FF E0 C3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1573_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "UPX$HiT 0.06"
		pattern = "B8????4300B915000000803408??E2FAE9D6FFFFFF"
	strings:
		$1 = { B8 ?? ?? 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1574_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "3.06 Scrambler"
		pattern = "E8000000005983C10751C3C3BE????????83EC04893424B9800000008136????????50B80400000050033424585883E903E2E9EBD6"
	strings:
		$1 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE ?? ?? ?? ?? 83 EC 04 89 34 24 B9 80 00 00 00 81 36 ?? ?? ?? ?? 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1575_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "1.x Scrambler RC"
		pattern = "9061BE????????8DBE????????5783CDFF"
	strings:
		$1 = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1576_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "UPXcrypter"
		pattern = "BF??????0081FF??????007410812F??00000083C704BB05????00FFE3BE??????00FFE600000000"
	strings:
		$1 = { BF ?? ?? ?? 00 81 FF ?? ?? ?? 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 ?? ?? 00 FF E3 BE ?? ?? ?? 00 FF E6 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1577_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "UpxLock 1.0 - 1.2"
		pattern = "60E8000000005D81ED4812400060E82B03000061"
	strings:
		$1 = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1578_UPX {
	meta:
		tool = "P"
		name = "UPX"
		version = "DOS EXE"
		pattern = "B9????BE????BFC0FFFD"
	strings:
		$1 = { B9 ?? ?? BE ?? ?? BF C0 FF FD }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1579_UPXFreak {
	meta:
		tool = "P"
		name = "UPXFreak"
		version = "0.1"
		extra = "for Borland Delphi"
		pattern = "BE????????83C601FFE6000000??????0003000000????????001000000000????????0000??F6??00B24F4500??F9??00EF4F4500??F6??008CD14200??56??00??????00??????00??????00??24??00??????00"
	strings:
		$1 = { BE ?? ?? ?? ?? 83 C6 01 FF E6 00 00 00 ?? ?? ?? 00 03 00 00 00 ?? ?? ?? ?? 00 10 00 00 00 00 ?? ?? ?? ?? 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 24 ?? 00 ?? ?? ?? 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1580_USERNAME {
	meta:
		tool = "P"
		name = "USERNAME"
		version = "3.00"
		pattern = "FB2E????????2E????????2E????????2E????????8CC82BC18BC82E????????2E????????33C08ED8060E07FC33F6"
	strings:
		$1 = { FB 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 8C C8 2B C1 8B C8 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? 33 C0 8E D8 06 0E 07 FC 33 F6 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1581_USSR {
	meta:
		tool = "P"
		name = "USSR"
		version = "0.31"
		pattern = "000000000000000000000000400000C02E5553535200000000100000????????00100000????????000000000000000000000000400000C0000000000000000000000000000000000000000000000000"
	strings:
		$1 = { 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 2E 55 53 53 52 00 00 00 00 10 00 00 ?? ?? ?? ?? 00 10 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1582_USSR {
	meta:
		tool = "P"
		name = "USSR"
		version = "0.31"
		pattern = "E8000000005D83C51255C32083B8ED2037EFC6B979379E8CC930C9E301C3BE32??????B0??30068A064681FE00??????7CF3"
	strings:
		$1 = { E8 00 00 00 00 5D 83 C5 12 55 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 8C C9 30 C9 E3 01 C3 BE 32 ?? ?? ?? B0 ?? 30 06 8A 06 46 81 FE 00 ?? ?? ?? 7C F3 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1583_VBOX {
	meta:
		tool = "P"
		name = "VBOX"
		version = "4.2 MTE"
		pattern = "8CE00BC58CE00BC403C5740074008BC5"
	strings:
		$1 = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1584_VBOX {
	meta:
		tool = "P"
		name = "VBOX"
		version = "4.3 - 4.6"
		pattern = "????????9003C433C433C52BC533C58BC5????2BC548????0BC086E08CE0????8CE086E003C440"
	strings:
		$1 = { ?? ?? ?? ?? 90 03 C4 33 C4 33 C5 2B C5 33 C5 8B C5 ?? ?? 2B C5 48 ?? ?? 0B C0 86 E0 8C E0 ?? ?? 8C E0 86 E0 03 C4 40 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1585_VBOX {
	meta:
		tool = "P"
		name = "VBOX"
		version = "4.3 - 4.6"
		pattern = "8BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC58BC5"
	strings:
		$1 = { 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 }
	condition:
		for any of them : ( $ at pe.entry_point )
}
rule rule_1586_Vcasm_Protector {
	meta:
		tool = "P"
		name = "Vcasm Protector"
		version = "1.0e"
		pattern = "EB0A5B5650726F746563745D"
	strings:
		$1 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D }
	condition:
		for any of them : ( $ at pe.entry_point )
}
)x86_pe_packer";
