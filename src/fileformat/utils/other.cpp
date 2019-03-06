/**
 * @file src/fileformat/utils/other.cpp
 * @brief Simple utilities.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

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
	{0, "Unicode"},
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
		return numToStr(lcid, std::dec);
	}
	return l->second;
}

} // namespace fileformat
} // namespace retdec
