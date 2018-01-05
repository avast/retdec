/**
 * @file src/cpdetect/signatures/yara/database/arm/macho/compiler.cpp
 * @brief Database of signatures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

const char *armMachOCompiler =
R"arm_macho_packer(
rule XCode_SDK_arm_1
{
	meta:
		tool = "C"
		name = "XCode"
		extra = "with WatchOS or iOS SDK"
		source = "Made by RetDec Team"
		pattern = "00009DE504108DE2014080E2042181E007D0CDE30230A0E1044093E4000054E3FCFFFF1A????????????????"
	strings:
		$1 = { 00 00 9D E5 04 10 8D E2 01 40 80 E2 04 21 81 E0 07 D0 CD E3 02 30 A0 E1 04 40 93 E4 00 00 54 E3 FC FF FF 1A ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$1
}
rule rule XCode_SDK_arm_2 {
	meta:
		tool = "C"
		name = "XCode"
		extra = "with WatchOS or iOS SDK"
		source = "Made by RetDec Team"
		pattern = "00009DE504108DE2014080E2042181E007D0CDE30230A0E1044093E4000054E3FCFFFF1A18C09FE50CC08FE000C09CE53CFF2FE10CC09FE50CC08FE000C09CE51CFF2FE1????????????????"
	strings:
		$1 = { 00 00 9D E5 04 10 8D E2 01 40 80 E2 04 21 81 E0 07 D0 CD E3 02 30 A0 E1 04 40 93 E4 00 00 54 E3 FC FF FF 1A 18 C0 9F E5 0C C0 8F E0 00 C0 9C E5 3C FF 2F E1 0C C0 9F E5 0C C0 8F E0 00 C0 9C E5 1C FF 2F E1 ?? ?? ?? ?? ?? ?? ?? ?? }
	condition:
		$1
})arm_macho_packer";
