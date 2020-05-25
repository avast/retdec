/**
 * @file src/fileformat/utils/other.cpp
 * @brief Simple utilities.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <array>
#include <cmath>
#include <map>
#include <unordered_map>

#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/fileformat/utils/other.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

namespace
{

const std::map<Format, std::string> formatMap =
{
	{Format::PE, "PE"},
	{Format::ELF, "ELF"},
	{Format::COFF, "COFF"},
	{Format::MACHO, "Mach-O"},
	{Format::INTEL_HEX, "Intel HEX"},
	{Format::RAW_DATA, "Raw Data"}
};

const std::map<Architecture, std::vector<std::string>> architectureMap =
{
	{Architecture::X86, {"Intel x86"}},
	{Architecture::X86_64, {"Intel x86-64"}},
	{Architecture::ARM, {"ARM", "ARM + Thumb"}},
	{Architecture::POWERPC, {"PowerPC"}},
	{Architecture::MIPS, {"MIPS", "PIC32"}}
};

const std::unordered_map<std::size_t, std::string> lcids =
{
	{0, "Unspecified"},
	{1078, "Afrikaans"},
	{1052, "Albanian"},
	{1118, "Amharic"},
	{5121, "Arabic - Algeria"},
	{15361, "Arabic - Bahrain"},
	{3073, "Arabic - Egypt"},
	{2049, "Arabic - Iraq"},
	{11265, "Arabic - Jordan"},
	{13313, "Arabic - Kuwait"},
	{12289, "Arabic - Lebanon"},
	{4097, "Arabic - Libya"},
	{6145, "Arabic - Morocco"},
	{8193, "Arabic - Oman"},
	{16385, "Arabic - Qatar"},
	{1025, "Arabic - Saudi Arabia"},
	{10241, "Arabic - Syria"},
	{7169, "Arabic - Tunisia"},
	{14337, "Arabic - United Arab Emirates"},
	{9217, "Arabic - Yemen"},
	{1067, "Armenian"},
	{1101, "Assamese"},
	{2092, "Azeri - Cyrillic"},
	{1068, "Azeri - Latin"},
	{1069, "Basque"},
	{1059, "Belarusian"},
	{2117, "Bengali - Bangladesh"},
	{1093, "Bengali - India"},
	{5146, "Bosnian"},
	{1026, "Bulgarian"},
	{1109, "Burmese"},
	{1027, "Catalan"},
	{2052, "Chinese - China"},
	{3076, "Chinese - Hong Kong SAR"},
	{5124, "Chinese - Macau SAR"},
	{4100, "Chinese - Singapore"},
	{1028, "Chinese - Taiwan"},
	{1050, "Croatian"},
	{1029, "Czech"},
	{1030, "Danish"},
	{2067, "Dutch - Belgium"},
	{1043, "Dutch - Netherlands"},
	{1126, "Edo"},
	{3081, "English - Australia"},
	{10249, "English - Belize"},
	{4105, "English - Canada"},
	{9225, "English - Caribbean"},
	{2057, "English - Great Britain"},
	{16393, "English - India"},
	{6153, "English - Ireland"},
	{8201, "English - Jamaica"},
	{5129, "English - New Zealand"},
	{13321, "English - Phillippines"},
	{7177, "English - Southern Africa"},
	{11273, "English - Trinidad"},
	{1033, "English - United States"},
	{12297, "English - Zimbabwe"},
	{1061, "Estonian"},
	{1071, "FYRO Macedonia"},
	{1080, "Faroese"},
	{1065, "Farsi - Persian"},
	{1124, "Filipino"},
	{1035, "Finnish"},
	{2060, "French - Belgium"},
	{11276, "French - Cameroon"},
	{3084, "French - Canada"},
	{9228, "French - Congo"},
	{12300, "French - Cote d'Ivoire"},
	{1036, "French - France"},
	{5132, "French - Luxembourg"},
	{13324, "French - Mali"},
	{6156, "French - Monaco"},
	{14348, "French - Morocco"},
	{10252, "French - Senegal"},
	{4108, "French - Switzerland"},
	{7180, "French - West Indies"},
	{1122, "Frisian - Netherlands"},
	{2108, "Gaelic - Ireland"},
	{1084, "Gaelic - Scotland"},
	{1110, "Galician"},
	{1079, "Georgian"},
	{3079, "German - Austria"},
	{1031, "German - Germany"},
	{5127, "German - Liechtenstein"},
	{4103, "German - Luxembourg"},
	{2055, "German - Switzerland"},
	{1032, "Greek"},
	{1140, "Guarani - Paraguay"},
	{1095, "Gujarati"},
	{1279, "Human Interface Device"},
	{1037, "Hebrew"},
	{1081, "Hindi"},
	{1038, "Hungarian"},
	{1039, "Icelandic"},
	{1136, "Igbo - Nigeria"},
	{1057, "Indonesian"},
	{1040, "Italian - Italy"},
	{2064, "Italian - Switzerland"},
	{1041, "Japanese"},
	{1099, "Kannada"},
	{1120, "Kashmiri"},
	{1087, "Kazakh"},
	{1107, "Khmer"},
	{1111, "Konkani"},
	{1042, "Korean"},
	{1088, "Kyrgyz - Cyrillic"},
	{1108, "Lao"},
	{1142, "Latin"},
	{1062, "Latvian"},
	{1063, "Lithuanian"},
	{2110, "Malay - Brunei"},
	{1086, "Malay - Malaysia"},
	{1100, "Malayalam"},
	{1082, "Maltese"},
	{1112, "Manipuri"},
	{1153, "Maori"},
	{1102, "Marathi"},
	{2128, "Mongolian"},
	{1104, "Mongolian"},
	{1121, "Nepali"},
	{1044, "Norwegian - Bokml"},
	{2068, "Norwegian - Nynorsk"},
	{1096, "Oriya"},
	{1045, "Polish"},
	{1046, "Portuguese - Brazil"},
	{2070, "Portuguese - Portugal"},
	{1094, "Punjabi"},
	{1047, "Raeto-Romance"},
	{2072, "Romanian - Moldova"},
	{1048, "Romanian - Romania"},
	{1049, "Russian"},
	{2073, "Russian - Moldova"},
	{1083, "Sami Lappish"},
	{1103, "Sanskrit"},
	{3098, "Serbian - Cyrillic"},
	{2074, "Serbian - Latin"},
	{1072, "Sesotho"},
	{1074, "Setsuana"},
	{1113, "Sindhi"},
	{1115, "Sinhala"},
	{1051, "Slovak"},
	{1060, "Slovenian"},
	{1143, "Somali"},
	{1070, "Sorbian"},
	{11274, "Spanish - Argentina"},
	{16394, "Spanish - Bolivia"},
	{13322, "Spanish - Chile"},
	{9226, "Spanish - Colombia"},
	{5130, "Spanish - Costa Rica"},
	{7178, "Spanish - Dominican Republic"},
	{12298, "Spanish - Ecuador"},
	{17418, "Spanish - El Salvador"},
	{4106, "Spanish - Guatemala"},
	{18442, "Spanish - Honduras"},
	{2058, "Spanish - Mexico"},
	{19466, "Spanish - Nicaragua"},
	{6154, "Spanish - Panama"},
	{15370, "Spanish - Paraguay"},
	{10250, "Spanish - Peru"},
	{20490, "Spanish - Puerto Rico"},
	{1034, "Spanish - Spain (Traditional)"},
	{14346, "Spanish - Uruguay"},
	{8202, "Spanish - Venezuela"},
	{1089, "Swahili"},
	{2077, "Swedish - Finland"},
	{1053, "Swedish - Sweden"},
	{1114, "Syriac"},
	{1064, "Tajik"},
	{1097, "Tamil"},
	{1092, "Tatar"},
	{1098, "Telugu"},
	{1054, "Thai"},
	{1105, "Tibetan"},
	{1073, "Tsonga"},
	{1055, "Turkish"},
	{1090, "Turkmen"},
	{1058, "Ukrainian"},
	{1056, "Urdu"},
	{2115, "Uzbek - Cyrillic"},
	{1091, "Uzbek - Latin"},
	{1075, "Venda"},
	{1066, "Vietnamese"},
	{1106, "Welsh"},
	{1076, "Xhosa"},
	{1085, "Yiddish"},
	{1077, "Zulu"}
};

const std::unordered_map<std::size_t, std::string> codePages =
{
	{0, "Unspecified"},
	{37, "IBM037"},
	{437, "IBM437"},
	{500, "IBM500"},
	{708, "ASMO-708"},
	{709, "Arabic (ASMO-449+, BCON V4)"},
	{710, "Arabic - Transparent Arabic"},
	{720, "DOS-720"},
	{737, "ibm737"},
	{775, "ibm775"},
	{850, "ibm850"},
	{852, "ibm852"},
	{855, "IBM855"},
	{857, "ibm857"},
	{858, "IBM00858"},
	{860, "IBM860"},
	{861, "ibm861"},
	{862, "DOS-862"},
	{863, "IBM863"},
	{864, "IBM864"},
	{865, "IBM865"},
	{866, "cp866"},
	{869, "ibm869"},
	{870, "IBM870"},
	{874, "windows-874"},
	{875, "cp875"},
	{932, "shift_jis"},
	{936, "gb2312"},
	{949, "ks_c_5601-1987"},
	{950, "big5"},
	{1026, "IBM1026"},
	{1047, "IBM01047"},
	{1140, "IBM01140"},
	{1141, "IBM01141"},
	{1142, "IBM01142"},
	{1143, "IBM01143"},
	{1144, "IBM01144"},
	{1145, "IBM01145"},
	{1146, "IBM01146"},
	{1147, "IBM01147"},
	{1148, "IBM01148"},
	{1149, "IBM01149"},
	{1200, "utf-16"},
	{1201, "unicodeFFFE"},
	{1250, "windows-1250"},
	{1251, "windows-1251"},
	{1252, "windows-1252"},
	{1253, "windows-1253"},
	{1254, "windows-1254"},
	{1255, "windows-1255"},
	{1256, "windows-1256"},
	{1257, "windows-1257"},
	{1258, "windows-1258"},
	{1361, "Johab"},
	{10000, "macintosh"},
	{10001, "x-mac-japanese"},
	{10002, "x-mac-chinesetrad"},
	{10003, "x-mac-korean"},
	{10004, "x-mac-arabic"},
	{10005, "x-mac-hebrew"},
	{10006, "x-mac-greek"},
	{10007, "x-mac-cyrillic"},
	{10008, "x-mac-chinesesimp"},
	{10010, "x-mac-romanian"},
	{10017, "x-mac-ukrainian"},
	{10021, "x-mac-thai"},
	{10029, "x-mac-ce"},
	{10079, "x-mac-icelandic"},
	{10081, "x-mac-turkish"},
	{10082, "x-mac-croatian"},
	{12000, "utf-32"},
	{12001, "utf-32BE"},
	{20000, "x-Chinese_CNS"},
	{20001, "x-cp20001"},
	{20002, "x_Chinese-Eten"},
	{20003, "x-cp20003"},
	{20004, "x-cp20004"},
	{20005, "x-cp20005"},
	{20105, "x-IA5"},
	{20106, "x-IA5-German"},
	{20107, "x-IA5-Swedish"},
	{20108, "x-IA5-Norwegian"},
	{20127, "us-ascii"},
	{20261, "x-cp20261"},
	{20269, "x-cp20269"},
	{20273, "IBM273"},
	{20277, "IBM277"},
	{20278, "IBM278"},
	{20280, "IBM280"},
	{20284, "IBM284"},
	{20285, "IBM285"},
	{20290, "IBM290"},
	{20297, "IBM297"},
	{20420, "IBM420"},
	{20423, "IBM423"},
	{20424, "IBM424"},
	{20833, "x-EBCDIC-KoreanExtended"},
	{20838, "IBM-Thai"},
	{20866, "koi8-r"},
	{20871, "IBM871"},
	{20880, "IBM880"},
	{20905, "IBM905"},
	{20924, "IBM00924"},
	{20932, "EUC-JP"},
	{20936, "x-cp20936"},
	{20949, "x-cp20949"},
	{21025, "cp1025"},
	{21027, "(deprecated)"},
	{21866, "koi8-u"},
	{28591, "iso-8859-1"},
	{28592, "iso-8859-2"},
	{28593, "iso-8859-3"},
	{28594, "iso-8859-4"},
	{28595, "iso-8859-5"},
	{28596, "iso-8859-6"},
	{28597, "iso-8859-7"},
	{28598, "iso-8859-8"},
	{28599, "iso-8859-9"},
	{28603, "iso-8859-13"},
	{28605, "iso-8859-15"},
	{29001, "x-Europa"},
	{38598, "iso-8859-8-i"},
	{50220, "iso-2022-jp"},
	{50221, "csISO2022JP"},
	{50222, "iso-2022-jp"},
	{50225, "iso-2022-kr"},
	{50227, "x-cp50227"},
	{50229, "ISO 2022 Traditional Chinese"},
	{50930, "EBCDIC Japanese (Katakana) Extended"},
	{50931, "EBCDIC US-Canada and Japanese"},
	{50933, "EBCDIC Korean Extended and Korean"},
	{50935, "EBCDIC Simplified Chinese Extended and Simplified Chinese"},
	{50936, "EBCDIC Simplified Chinese"},
	{50937, "EBCDIC US-Canada and Traditional Chinese"},
	{50939, "EBCDIC Japanese (Latin) Extended and Japanese"},
	{51932, "euc-jp"},
	{51936, "EUC-CN"},
	{51949, "euc-kr"},
	{51950, "EUC Traditional Chinese"},
	{52936, "hz-gb-2312"},
	{54936, "GB18030"},
	{57002, "x-iscii-de"},
	{57003, "x-iscii-be"},
	{57004, "x-iscii-ta"},
	{57005, "x-iscii-te"},
	{57006, "x-iscii-as"},
	{57007, "x-iscii-or"},
	{57008, "x-iscii-ka"},
	{57009, "x-iscii-ma"},
	{57010, "x-iscii-gu"},
	{57011, "x-iscii-pa"},
	{65000, "utf-7"},
	{65001, "utf-8"}
};

} // anonymous namespace

/**
 * Get real size of selected area in region
 * @param offset Start offset of selected area in region
 * @param requestedSize Requested size of selected area (0 means maximal size from @a offset to end of region)
 * @param regionSize Total size of region
 * @return Real size of selected area in region
 */
std::size_t getRealSizeInRegion(std::size_t offset, std::size_t requestedSize, std::size_t regionSize)
{
	if(offset >= regionSize)
	{
		return 0;
	}

	return (!requestedSize || offset + requestedSize > regionSize) ? regionSize - offset : requestedSize;
}

/**
 * Get file format name
 * @param format File format
 * @return Name of file format
 */
std::string getFileFormatNameFromEnum(Format format)
{
	return mapGetValueOrDefault(formatMap, format, "");
}

/**
 * Get list of all supported file formats
 * @return List of all supported file formats
 */
std::vector<std::string> getSupportedFileFormats()
{
	std::vector<std::string> result;

	for(const auto &item: formatMap)
	{
		result.push_back(item.second);
	}

	return result;
}

/**
 * Get list of all supported target architectures
 */
std::vector<std::string> getSupportedArchitectures()
{
	std::vector<std::string> result;

	for(const auto &i : architectureMap)
	{
		for(const auto &j : i.second)
		{
			result.push_back(j);
		}
	}

	return result;
}

/**
 * Get string representation of language code id
 * @param lcid Language code id
 * @return String representation of @a lcid
 */
std::string lcidToStr(std::size_t lcid)
{
	auto l = lcids.find(lcid);
	if (l == lcids.end())
	{
		return std::to_string(lcid);
	}
	return l->second;
}

/**
 * Get string representation of IBM code page
 * @param cpage Language code id
 * @return String representation of @a code page
 */
std::string codePageToStr(std::size_t cpage)
{
	auto cpg = codePages.find(cpage);
	if (cpg == codePages.end())
	{
		return std::to_string(cpage);
	}
	return cpg->second;
}

/*
 * Compute entropy of given data
 * @param data Data to compute entropy from
 * @param dataLen Length of @a data
 * @return entropy in <0,8>
 */
double computeDataEntropy(const std::uint8_t *data, std::size_t dataLen)
{
	std::array<std::size_t, 256> histogram{};
	double entropy = 0;

	if (!data)
	{
		return 0;
	}

	for (std::size_t i = 0; i < dataLen; i++)
	{
		histogram[data[i]]++;
	}

	for (auto frequency : histogram)
	{
		if (frequency)
		{
			double probability = static_cast<double>(frequency) / dataLen;
			entropy -= probability * std::log2(probability);
		}
	}

	return entropy;
}

} // namespace fileformat
} // namespace retdec
