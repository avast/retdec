/**
 * @file src/cpdetect/compiler_detector/heuristics/pe_heuristics.cpp
 * @brief Methods of PeHeuristics class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <initializer_list>
#include <map>
#include <regex>

#include <tinyxml2.h>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/cpdetect/compiler_detector/heuristics/pe_heuristics.h"
#include "retdec/cpdetect/settings.h"
#include "retdec/cpdetect/signatures/avg/signature.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/fileformat/utils/file_io.h"
#include "retdec/fileformat/utils/other.h"

using namespace retdec::utils;
using namespace retdec::fileformat;
using namespace std::string_literals;

namespace retdec {
namespace cpdetect {

namespace
{

const std::map<char, std::string> peCompactMap =
{
	{'=', "2.92.0"},
	{'F', "2.96.2"},
	{'M', "2.98.5"},
	{'T', "3.00.2"},
	{'X', "3.01.3"},
	{']', "3.02.1"},
	{'^', "3.02.2"},
	{'c', "3.03.5 (beta)"},
	{'g', "3.03.9 (beta)"},
	{'i', "3.03.10 (beta)"},
	{'n', "3.03.12 (beta)"},
	{'v', "3.03.18 (beta)"},
	{'w', "3.03.19 (beta)"},
	{'x', "3.03.20 (beta)"},
	{'y', "3.03.21 (beta)"},
	{'|', "3.03.23 (beta)"}
};

const std::vector<Signature> x86SlashedSignatures =
{
	{"--MPRMMGVA--", "", "////////892504----00;", "", 0, 0},
	{"DotFix Nice Protect", "", "60BE--------8DBE--------5783CD--/619090505174--83C8--EB;", "", 0, 0},
	{"EXE Stealth", "1.1 - 2.7", "/60/E8000000005D81ED----40;", "", 0, 2},
	{"EXE Stealth", "1.1x", "/60/E8000000005D81ED--274000B91500000083C1;", "", 0, 2},
	{"EXE Stealth", "2.72 - 2.73", "/EB--536861726577617265202D20;", "", 0, 0},
	{"k.kryptor", "3", "/60E8--------5E8D----B9--------4933C05102----D3C04979--33----5900;", "", 0, 0},
	{"Morphnah", "1.0.7", "558BEC87E55D/558BEC83EC--5356576064A1--------8B40--8945--64A1--------C740;", "", 0, 0},
	{"NTSHELL", "5.0", "55E8--------5D81ED--------//8D85--------8DBD--------/8DB5--------/8BCF/2BC84FFD/33DB/8A07/D2C8/2A----/E8;", "", 0, 0},
	{"Obsidium", "", "/50/E8--------//33C0/71--//33C0/64FF30/648920EB;", "", 0, 0},
	{"Obsidium", "", "/E87892000039D7C7B6C7E8FDC1D910BAC96C682E58126D6928776F55A8990B0D4588C754028CC8979109F2B461633A28384037B805A98726CED01F92;", "", 0, 12},
	{"Obsidium", "", "/E8789200005CBF--------A5848CA3--------DC060020598B86--------5553AF0ECC8B4009AD832608BED00A596FD07C893E10A915150201584F0C;", "", 0, 12},
	{"Obsidium", "1.1.1.1 - 1.4.0.0 Beta", "/E8--------//8B------/83------------/33C0/C3;", "", 0, 12},
	{"Obsidium", "1.3.6.x", "/50/E8--000000//8B54240C/8382B8000000--/33C0/C3//33C0/64FF30/648920//8B00/C3/E9--000000/E8;", "", 0, 0},
	{"tElock", "0.60", "/60E8000000005883C008;", "", 0, 0},
	{"UPX", "", "/60BE--------8DBE--------5783CDFF/8B1E83EEFC11DB72EDB801;", "", 0, 0},
	{"yoda's Protector", "1.00", "558BEC53565760E8000000005D81ED--------E803000000/B9;", "", 0, 0},
	{"yoda's Protector", "1.01", "558BEC535657E803000000/E886000000E803000000/E879000000;", "", 0, 0},
	{"yoda's Protector", "1.02", "E803000000/BB55000000E803000000/E88F000000E803000000EB01--E882000000E803000000EB01--E8B8000000E803000000EB01--E8AB000000E803000000EB01--83FB55E803000000EB01--752EE803000000EB01--C360E8000000005D81ED233F42008BD581C2723F420052E801000000C3C3E803000000EB01--E80E000000E8D1FFFFFFC3E803000000EB01--33C064FF30648920CCC3E803000000EB01--33C064FF306489204BCCC3E803000000EB01--33DBB93A66420081E91D4042008BD581C21D4042008D3A8BF733C0E803000000EB01--E817000000909090E9C31F000033C064FF3064892043CCC3;", "Ashkbiz Danehkar", 0, 0},
	{"yoda's Protector", "1.03", "E803000000/BB55000000E803000000/E8--000000E803000000EB;", "Ashkbiz Danehkar", 0, 0},
	{"yoda's Protector", "1.03.1", "E803000000/BB55000000E803000000/E88F000000E803000000EB01--E882000000E803000000EB01--E8B8000000E803000000EB01--E8AB000000E803000000EB01--83FB55E803000000EB01--752EE803000000EB01--C360E8000000005D81ED747242008BD581C2C372420052E801000000C3C3E803000000EB01--E80E000000E8D1FFFFFFC3E803000000EB01--33C064FF30648920CCC3E803000000EB01--33C064FF306489204BCCC3E803000000EB01--33DBB93FA9420081E96E7342008BD581C26E7342008D3A8BF733C0E803000000EB01--E817000000909090E9982E000033C064FF3064892043CCC3;", "Ashkbiz Danehkar", 0, 0},
	{"yoda's Protector", "1.03.2", "E803000000/BB55000000E803000000/E88F000000E803000000EB01--E882000000E803000000EB01--E8B8000000E803000000EB01--E8AB000000E803000000EB01--83FB55E803000000EB01--752EE803000000EB01--C360E8000000005D81ED947342008BD581C2E373420052E801000000C3C3E803000000EB01--E80E000000E8D1FFFFFFC3E803000000EB01--33C064FF30648920CCC3E803000000EB01--33C064FF306489204BCCC3E803000000EB01--33DBB9BFA4420081E98E7442008BD581C28E7442008D3A8BF733C0E803000000EB01--E817000000909090E96329000033C064FF3064892043CCC3;", "Ashkbiz Danehkar", 0, 0},
	{"yoda's Protector", "1.03.3", "E803000000/BB55000000E803000000/E88E000000E803000000EB01--E881000000E803000000EB01--E8B7000000E803000000EB01--E8AA000000E803000000EB01--83FB55E803000000EB01--75;", "Ashkbiz Danehkar", 0, 0}
};

const std::vector<std::string> enigmaPatterns =
{
	"60E8000000005D81ED--------81ED--------E9;",
	"//60E8000000005D81ED--------81ED--------E9;",
	"5051525355565741504151415241534154415541564157489C4881EC080000000FAE1C24E8000000005D;",
	"/83C4--/60E8000000005D81ED--------81ED--------E9;",
	"558BEC83C4--B8--------E8--------9A------------/60E8000000005D--ED;"
};

const std::vector<std::string> dotNetShrinkPatterns =
{
	"20FE2B136028--------13--203B28136028--------13--11--11--161F4028--------26;",
	"20AD65133228--------13--206866133228--------13--11--11--161F4028--------26;",
	"20B9059F0728--------13--2066059F0728--------13--11--11--161F4028--------26;",
	"20E6EA19BE28--------13--2039EA19BE28--------13--11--11--161F4028--------26;"
};

const std::string msvcRuntimeString = "Microsoft Visual C++ Runtime Library";

const std::vector<std::string> msvcRuntimeStrings =
{
	msvcRuntimeString,
	toWide(msvcRuntimeString, 2),
	toWide(msvcRuntimeString, 4)
};

/**
 * Try to find string which indicates AutoIt programming language
 * @param content Content of file
 * @return @c true if string is found, @c false otherwise
 */
bool findAutoIt(const std::string &content)
{
	const std::string prefix = "AU3!EA";
	const std::regex regExp(prefix + "[0-9]{2}");
	const auto offset = content.find(prefix);
	return offset != std::string::npos && regex_match(content.substr(offset, 8), regExp);
}

/**
 * Try to find NSIS version in manifest
 * @param manifest PE file manifest
 * @return version from manifest or empty string if version is not found
 */
std::string getNullsoftManifestVersion(const std::string &manifest)
{
	const auto offset = manifest.find("Nullsoft Install System");
	if (offset != std::string::npos)
	{
		const auto verStart = manifest.find('v', offset + 23);
		const auto verEnd = manifest.find('<', offset + 23);

		std::string version;
		if (verEnd < manifest.size())
		{
			version = manifest.substr(verStart + 1, verEnd - verStart - 1);
			if (regex_match(version, std::regex("[[:digit:]]+.[[:digit:]]+")))
			{
				return version;
			}
		}
	}

	return std::string();
}

} // anonymous namespace

/**
 * Constructor
 */
PeHeuristics::PeHeuristics(
		retdec::fileformat::PeFormat &parser, Search &searcher, ToolInformation &toolInfo)
	: Heuristics(parser, searcher, toolInfo), peParser(parser),
		declaredLength(parser.getDeclaredFileLength()),
		loadedLength(parser.getLoadedFileLength())
{
}

/**
 * Destructor
 */
PeHeuristics::~PeHeuristics()
{
}

/**
 * Try detect version of Enigma protector
 * @return Detected version of Enigma or empty string if version is not detected
 */
std::string PeHeuristics::getEnigmaVersion()
{
	const auto *sec = fileParser.getLastSection();
	if (!sec || !sec->getLoadedSize())
	{
		sec = fileParser.getLastButOneSection();
		if (!sec || !sec->getLoadedSize())
		{
			return "";
		}
	}

	const std::string pattern = "\0\0\0ENIGMA"s;
	const auto &content = search.getPlainString();
	const auto pos = content.find(pattern, sec->getOffset());
	if (pos < sec->getOffset() + sec->getLoadedSize())
	{
		std::uint64_t result1, result2;
		if (fileParser.get1ByteOffset(pos + pattern.length(), result1)
				&& fileParser.get1ByteOffset(pos + pattern.length() + 1, result2))
		{
			return numToStr(result1) + "." + numToStr(result2);
		}
	}

	return "";
}

/**
 * Try detect additional information of UPX packer
 * @return Additional information
 *
 * Each information is enclosed in square brackets separated by the space.
 */
std::string PeHeuristics::getUpxAdditionalInfo(std::size_t metadataPos)
{
	const auto& content = search.getPlainString();

	std::string info;
	if (content.length() > metadataPos + 6)
	{
		switch (content[metadataPos + 6])
		{
			case 0x2:
			case 0x3:
			case 0x4:
				info += "[NRV2B]";
				break;

			case 0x5:
			case 0x6:
			case 0x7:
				info += "[NRV2D]";
				break;

			case 0x8:
			case 0x9:
			case 0xA:
				info += "[NRV2E]";
				break;

			case 0xE:
				info += "[LZMA]";
				break;

			default:
				break;
		}

		if (content.length() > metadataPos + 29)
		{
			info += info.empty() ? "" : " ";

			auto id = static_cast<std::uint32_t>(content[metadataPos + 28]);
			auto param = static_cast<std::uint32_t>(content[metadataPos + 29]);
			info += "[Filter: 0x" + numToStr(id, std::hex)
					+ ", Param: 0x" + numToStr(param, std::hex) + ']';
		}
	}

	return info;
}

/**
 * Try to detect Go language binaries
 */
void PeHeuristics::getGoHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;

	const Section* section = fileParser.getSection(".text");
	if (!section)
	{
		return;
	}

	const auto goString = "\xFF Go build ID: ";
	if (section->getBytes(0, 15) == goString)
	{
		addCompiler(source, DetectionStrength::MEDIUM, "gc");
		addLanguage("Go");
	}
	else if (search.hasStringInSection(goString, section))
	{
		// Go build ID not on start of section
		addCompiler(source, DetectionStrength::LOW, "gc");
		addLanguage("Go");
	}
}

/**
 * Try to detect AutoIt programming language
 */
void PeHeuristics::getAutoItHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	std::string end;
	if (fileParser.getStringFromEnd(end, 8) && findAutoIt(end))
	{
		addCompiler(source, strength, "Aut2Exe");
		addPriorityLanguage("AutoIt", "", true);
	}

	const auto &content = search.getPlainString();
	const auto *rsrc = fileParser.getSection(".rsrc");
	if (rsrc && rsrc->getOffset() < content.length()
			&& findAutoIt(content.substr(rsrc->getOffset())))
	{
		addCompiler(source, strength, "Aut2Exe");
		addPriorityLanguage("AutoIt", "", true);
	}
}

/**
 * Try to detect CIL/.NET
 */
void PeHeuristics::getDotNetHeuristics()
{
	if (peParser.isDotNet() || peParser.isPackedDotNet())
	{
		addLanguage("CIL/.NET", "", true);
	}
}

/**
 * Try to detect Visual Basic
 */
void PeHeuristics::getVisualBasicHeuristics()
{
	auto source = DetectionMethod::LINKED_LIBRARIES_H;
	auto strength = DetectionStrength::HIGH;

	unsigned long long version = 0;
	if (peParser.isVisualBasic(version))
	{
		addCompiler(source, strength, "Visual Basic", numToStr(version));
		addLanguage("Visual Basic");
	}
}

/**
 * Try to detect used compiler or packer based on slashed signatures
 */
void PeHeuristics::getSlashedSignatures()
{
	if (!fileParser.isX86OrX86_64() || !canSearch || !toolInfo.entryPointOffset)
	{
		return;
	}

	const auto stopOffset = toolInfo.epOffset + LIGHTWEIGHT_FILE_SCAN_AREA;
	for (const auto &sig : x86SlashedSignatures)
	{
		auto start = toolInfo.epOffset;
		if (sig.startOffset != std::numeric_limits<unsigned>::max())
		{
			start += sig.startOffset;
		}

		auto end = stopOffset;
		if (sig.endOffset != std::numeric_limits<unsigned>::max())
		{
			end = std::min(stopOffset,
				toolInfo.epOffset + sig.endOffset
					+ fileParser.bytesFromNibblesRounded(sig.pattern.length() - 1) - 1);
		}

		const auto nibbles = search.findSlashedSignature(sig.pattern, start, end);
		if (nibbles)
		{
			addPacker(nibbles, nibbles, sig.name, sig.version, sig.additional);
		}
	}
}

/**
 * Try to detect Morphine encryptor
 */
void PeHeuristics::getMorphineHeuristics()
{
	if (!fileParser.isX86() || !toolInfo.entryPointOffset ||
		toolInfo.epOffset < 0x400 || toolInfo.epOffset > 0x1400)
	{
		return;
	}

	auto source = DetectionMethod::SECTION_TABLE_H;
	auto strength = DetectionStrength::MEDIUM;

	if (noOfSections > 2
			&& sections[0]->getName() == ".text"
			&& sections[1]->getName() == ".data"
			&& sections[2]->getName() == ".idata"
			&& sections[2]->getSizeInFile() == 0x200)
	{
		unsigned long long rva, size;
		if (peParser.getDataDirectoryRelative(1, rva, size) && size == 0x1000)
		{
			addPacker(source, strength, "Morphine", "1.2");
		}
	}
	else if (noOfSections > 1
			&& sections[0]->getName() == ".text"
			&& sections[1]->getName() == ".idata"
			&& (sections[1]->getSizeInFile() == 0x200
					|| sections[1]->getSizeInFile() == 0x400))
	{
		addPacker(source, strength, "Morphine", "2.7");
	}
}

/**
 * Try to detect PELock packer
 */
void PeHeuristics::getPelockHeuristics()
{
	unsigned long long rva, size;
	if (peParser.getDataDirectoryRelative(1, rva, size)
			&& size == 0x5C
			&& peParser.getDataDirectoryRelative(15, rva, size)
			&& size == 0x1000)
	{
		addPacker(DetectionMethod::OTHER_H, DetectionStrength::MEDIUM, "PELock", "1.x");
	}
}

/**
 * Try to detect Eziriz .NET Reactor packer
 */
void PeHeuristics::getEzirizReactorHeuristics()
{
	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::HIGH;

	std::string version;
	if (noOfSections > 3
			&& fileParser.getSection("reacto")
			&& !sections[1]->getSizeInFile()
			&& !sections[2]->getSizeInFile()
			&& !sections[3]->getSizeInFile())
	{
		version = "2.0 - 2.1";
		source = DetectionMethod::SECTION_TABLE_H;
	}
	else if (canSearch)
	{
		const auto *sec0 = peParser.getPeSection(0);
		const auto *sec1 = peParser.getPeSection(1);

		if (sec0 && search.findUnslashedSignature("558BECB90F0000006A006A004975F951535657B8--------E8;",
			sec0->getOffset(), sec0->getOffset() + sec0->getLoadedSize() - 1))
		{
			version = "3.X";
		}
		else if (sec1
				&& sec1->getPeCoffFlags() == 0xC0000040
				&& search.findUnslashedSignature("5266686E204D182276B5331112330C6D0A204D18229EA129611C76B505190158;",
					sec1->getOffset(), sec1->getOffset() + sec1->getLoadedSize() - 1))
		{
			version = "4.8 - 5.0";
		}
		else if (noOfSections >= 4
				&& toolInfo.entryPointOffset
				&& findSectionName(".text") == 1
				&& findSectionName(".rsrc") == 1)
		{
			const auto *resTable = fileParser.getResourceTable();
			const auto *resVer = fileParser.getVersionResource();
			if (resTable && resTable->hasResourceWithName("__") && resVer)
			{
				std::size_t lId;
				if (resVer->getLanguageId(lId) && !lId)
				{
					if (search.exactComparison("E8--------E9--------6A0C68;", toolInfo.epOffset))
					{
						version = "4.2";
					}
					else if (search.exactComparison(
								"E8--------E9--------8BFF558BEC83EC208B45085657;",
								toolInfo.epOffset))
					{
						version = "4.5 - 4.7";
					}
				}
			}
		}
	}

	if (!version.empty())
	{
		addPacker(source, strength, "Eziriz .NET Reactor", version);
		addLanguage("CIL/.NET", "", true);
	}
}

/**
 * Try to detect UPX (Ultimate packer for executables)
 */
void PeHeuristics::getUpxHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::HIGH;

	// UPX 1.00 - UPX 1.07
	// format: UPX 1.0x
	const std::string upxVer = "UPX 1.0";
	const auto &content = search.getPlainString();
	auto pos = content.find(upxVer);
	if (pos < 0x500 && pos < content.length() - upxVer.length())
	{
		// we must decide between UPX and UPX$HiT
		source = DetectionMethod::COMBINED;
		if (noOfSections == 3
				&& sections[0]->getName() == ".code"
				&& sections[1]->getName() == ".text"
				&& sections[2]->getName() == ".rsrc")
		{
			addPacker(source, strength, "UPX", "UPX$HiT");
		}
		else
		{
			const std::string versionPrefix = "1.0";
			addPacker(source, strength, "UPX", versionPrefix + content[pos + upxVer.length()]);
		}

		return;
	}

	// UPX 1.08 and later
	// format: x.xx'\0'UPX!
	const std::size_t minPos = 5, verLen = 4;
	pos = content.find("UPX!");
	if (pos >= minPos && pos < 0x500)
	{
		std::string version;
		std::size_t num;
		if (strToNum(content.substr(pos - minPos, 1), num)
				&& strToNum(content.substr(pos - minPos + 2, 2), num))
		{
			version = content.substr(pos - minPos, verLen);
		}
		std::string additionalInfo = getUpxAdditionalInfo(pos);
		if (!additionalInfo.empty())
		{
			if (!version.empty())
			{
				version += ' ';
			}
			version += additionalInfo;
		}
		addPacker(source, strength, "UPX", version);
	}
}

/**
 * Try to detect FSG packer based on heuristics
 */
void PeHeuristics::getFsgHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	if (search.hasString("FSG!", peParser.getPeHeaderOffset(), peParser.getMzHeaderSize()))
	{
		addPacker(source, strength, "FSG");
	}
}

/**
 * Try to detect PECompact based on heuristics
 */
void PeHeuristics::getPeCompactHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	// format: PEC2[any character]O
	const std::string pattern = "PEC2";
	const auto patLen = pattern.length();

	const auto &content = search.getPlainString();
	const auto pos = content.find(pattern);

	if (pos < 0x500
			&& pos + patLen + 2 <= content.length()
			&& content[pos + patLen + 1] == 'O')
	{
		for (const auto &item : peCompactMap)
		{
			if (content[pos + patLen] == item.first)
			{
				addPacker(source, strength, "PECompact", item.second);
				return;
			}
		}

		addPacker(source, strength, "PECompact");
	}

	if (search.hasString("PECompact2", 0, 0x4FF))
	{
		addPacker(source, strength, "PECompact", "2.xx - 3.xx");
	}
}

/**
 * Try to detect ANDpakk packer
 */
void PeHeuristics::getAndpakkHeuristics()
{
	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::MEDIUM;

	if (noOfSections == 1 && sections[0]->getName() == "ANDpakk2")
	{
		const auto *table = fileParser.getImportTable();
		if (table && table->getNumberOfLibraries() == 1)
		{
			addPacker(source, strength, "ANDpakk", "2.x");
		}
	}
}

/**
 * Try to detect ENIGMA protector
 */
void PeHeuristics::getEnigmaHeuristics()
{
	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::MEDIUM;

	if (canSearch && toolInfo.entryPointOffset
			&& search.exactComparison("60E8000000005D83----81ED;", toolInfo.epOffset))
	{
		const auto *sec = fileParser.getSection(".data");
		if (sec)
		{
			const std::string pattern = "Enigma protector v";
			const auto &content = search.getPlainString();
			const auto pos = content.find(pattern, sec->getOffset());
			if (pos < sec->getOffset() + sec->getSizeInFile() && pos <= content.length() - 4)
			{
				addPacker(source, strength, "Enigma", content.substr(pos + pattern.length(), 4));
				return;
			}
		}
	}

	const auto *importTable = fileParser.getImportTable();
	if (importTable && importTable->getNumberOfImportsInLibrary(1) == 1)
	{
		const auto *import = importTable->getImport("MessageBoxA");
		if (import && import->getLibraryIndex() == 1)
		{
			const auto version = getEnigmaVersion();
			if (!version.empty())
			{
				addPacker(source, strength, "Enigma", version);
				return;
			}
		}
	}

	for (const auto &sign : enigmaPatterns)
	{
		if (canSearch && toolInfo.entryPointOffset
				&& search.exactComparison(sign, toolInfo.epOffset))
		{
			addPacker(DetectionMethod::SIGNATURE, strength, "Enigma", getEnigmaVersion());
			return;
		}
	}

	if (peParser.isDotNet() && search.hasStringInSection("\0\0\0ENIGMA"s, std::size_t(0)))
	{
		addPacker(DetectionMethod::SIGNATURE, strength, "Enigma");
		return;
	}
}

/**
 * Try to detect VBox
 */
void PeHeuristics::getVBoxHeuristics()
{
	auto source = DetectionMethod::SIGNATURE;
	auto strength = DetectionStrength::MEDIUM;

	const std::string sig =
		"FF7424--FF7424--FF7424--68--------68--------68--------68--------FF15--------68--------FFD0C2;";
	if (canSearch && toolInfo.entryPointOffset
			&& search.exactComparison(sig, toolInfo.epOffset))
	{
		std::string version;
		const auto *table = fileParser.getImportTable();
		if (table && table->hasLibrary("vboxp410.dll"))
		{
			source = DetectionMethod::LINKED_LIBRARIES_H;
			strength = DetectionStrength::HIGH;
			version = "4.10";
		}

		addPacker(source, strength, "VBox", version);
	}
}

/**
 * Try to detect Active Delivery
 */
void PeHeuristics::getActiveDeliveryHeuristics()
{
	auto source = DetectionMethod::SIGNATURE;
	auto strength = DetectionStrength::MEDIUM;

	const std::string sig =
		"64A1--------558BEC6A--68--------68--------50648925--------83EC605356578965--FF15;";
	if (canSearch && toolInfo.entryPointOffset
			&& fileParser.getSection("actdlvry")
			&& search.exactComparison(sig, toolInfo.epOffset))
	{
		addPacker(source, strength, "Active Delivery");
	}
}

/**
 * Try to detect Adept Protector
 */
void PeHeuristics::getAdeptProtectorHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	if (peParser.isDotNet()
			&& search.hasStringInSection("ByAdeptProtector", std::size_t(0)))
	{
		std::string version;
		if (search.hasStringInSection("STAThreadAttribute", std::size_t(0)))
		{
			version = "2.1";
		}
		addPacker(source, strength, "Adept Protector", version);
	}
}

/**
 * Try to detect Code-Lock
 */
void PeHeuristics::getCodeLockHeuristics()
{
	auto source = DetectionMethod::LINKED_LIBRARIES_H;
	auto strength = DetectionStrength::MEDIUM;

	const auto *table = fileParser.getImportTable();
	if (table && table->hasLibrary("CODE-LOCK.OCX"))
	{
		addPacker(source, strength, "Code-Lock");
	}
}

/**
 * Try to detect various .NET tools
 */
void PeHeuristics::getNetHeuristic()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	if (!peParser.isDotNet() || !noOfSections)
	{
		return;
	}

	// normal string search
	std::size_t idx = 0;
	if (search.hasStringInSection("Protected_By_Attribute\0NETSpider.Attribute"s, idx))
	{
		addPacker(source, strength, ".NET Spider", "0.5 - 1.3");
	}
	if (search.hasStringInSection("Protected/Packed with ReNET-Pack by stx", idx))
	{
		addPacker(source, strength, "ReNET-pack");
	}
	if (search.hasStringInSection("\0NetzStarter\0netz\0"s, idx))
	{
		addPacker(source, strength, ".NETZ");
	}

	// unslashed signatures
	const auto *sec = fileParser.getSection(0);
	if (canSearch && sec)
	{
		std::string version;
		const auto start = sec->getOffset();
		const auto end = start + sec->getLoadedSize() - 1;

		const std::string sig =
			"0000010B160C----------0208----------0D0906085961D21304091E630861D21305070811051E62110460D19D081758;";
		if (search.findUnslashedSignature(sig, start, end))
		{
			version = "1.7 - 1.8";
		}
		else if (search.hasStringInSection("?.resources", sec))
		{
			version = "1.x";
		}
		if (!version.empty())
		{
			addPacker(source, strength, "Phoenix", version);
		}

		if (search.findUnslashedSignature("282D00000A6F2E00000A14146F2F00000A;", start, end))
		{
			addPacker(source, strength, "AssemblyInvoke");
		}

		if (search.findUnslashedSignature("436C69005300650063007500720065;", start, end))
		{
			addPacker(source, strength, "CliSecure");
		}

		// Note: Before modifying the following loop to std::any_of(),
		//       please see #231 (compilation bug with GCC 5).
		for (const auto& str : dotNetShrinkPatterns)
		{
			if (search.findUnslashedSignature(str, start, end))
			{
				addPacker(source, strength, ".netshrink", "2.01 (demo)");
				break;
			}
		}
	}
}

/**
 * Try to detect Excelsior Installer
 */
void PeHeuristics::getExcelsiorHeuristics()
{
	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::MEDIUM;

	const std::string sig =
		"83EC--53555657E8--------6A--5B391D--------8BF37E--8B3D--------A1--------8B----8A08;";
	if (canSearch && toolInfo.entryPointOffset
			&& search.exactComparison(sig, toolInfo.epOffset)
			&& search.hasString("ExcelsiorII1", declaredLength, loadedLength - 1))
	{
		addInstaller(source, strength, "Excelsior Installer");
	}
}

/**
 * Try to detect VM Protect
 */
void PeHeuristics::getVmProtectHeuristics()
{
	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::HIGH;

	if (noOfSections < 3 || (noOfSections == 3 && !sections[0]->getSizeInFile()))
	{
		return;
	}

	if (toolInfo.entryPointOffset && canSearch)
	{
		const std::string sig = "54C70424--------9C60C74424----------C64424----887424--60;";
		if (search.exactComparison(sig, toolInfo.epOffset))
		{
			addPacker(source, strength, "VMProtect", "2.06");
			return;
		}
		else if (fileParser.getSection(".vmp0")
				&& (search.exactComparison("68--------E9;", toolInfo.epOffset)
					|| search.exactComparison("68--------E8;", toolInfo.epOffset)))
		{
			addPacker(source, strength, "VMProtect", "1.60 - 2.05");
			return;
		}
	}

	for (const std::string secName : {".vmp0", ".vmp1", ".vmp2"})
	{
		if (fileParser.getSection(secName))
		{
			addPacker(source, strength, "VMProtect");
			return;
		}
	}
}

/**
 * Try to detect Borland Delphi
 */
void PeHeuristics::getBorlandDelphiHeuristics()
{
	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::MEDIUM;

	unsigned long long imageBaseAddr;
	if (!fileParser.getImageBaseAddress(imageBaseAddr)
			|| !toolInfo.entryPointSection
			|| toolInfo.epSection.getIndex()
			|| toolInfo.epSection.getOffset() != 0x400
			|| toolInfo.epSection.getAddress() < imageBaseAddr
			|| toolInfo.epSection.getAddress() - imageBaseAddr != 0x1000
			|| toolInfo.epSection.getName() != "CODE"
			|| noOfSections < 8
			|| sections[1]->getName() != "DATA"
			|| sections[2]->getName() != "BSS"
			|| sections[3]->getName() != ".idata"
			|| sections[4]->getName() != ".tls"
			|| sections[5]->getName() != ".rdata"
			|| sections[6]->getName() != ".reloc"
			|| sections[7]->getName() != ".rsrc")
	{
		return;
	}

	const std::string str = "SOFTWARE\\Borland\\Delphi\\RTL\0FPUMaskValue"s;
	if (search.hasStringInSection(str, sections[0])
			|| peParser.getTimeStamp() == 0x2A425E19) // 1992-06-19
	{
		addCompiler(source, strength, "Borland Delphi");
	}
}

/**
 * Try to detect BeRo Tiny Pascal
 */
void PeHeuristics::getBeRoHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	const std::string &str = "Compiled by: BeRoTinyPascal - (C) Copyright 2006, Benjamin";
	if (toolInfo.entryPointSection
			&& search.hasStringInSection(str, toolInfo.epSection.getIndex()))
	{
		addCompiler(source, strength, "BeRo Tiny Pascal");
		addLanguage("Pascal");
	}
}

/**
 * Try to detect Microsoft Visual C++ compiler or Intel XE compiler
 */
void PeHeuristics::getMsvcIntelHeuristics()
{
	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::MEDIUM;

	if (std::none_of(msvcRuntimeStrings.begin(), msvcRuntimeStrings.end(),
		[this] (const auto &str)
		{
			return this->search.hasStringInSection(str, ".rdata");
		}
	))
	{
		return;
	}

	if (findSectionName(".reloc") == 1)
	{
		addCompiler(source, strength, "MSVC");
		addPriorityLanguage("C++");
		return;
	}
	else if (findSectionName(".data1") == 1)
	{
		addCompiler(source, strength, "Intel XE");
	}
}

/**
 * Try to detect Armadillo packer
 */
void PeHeuristics::getArmadilloHeuristic()
{
	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::LOW;

	auto majorVersion = peParser.getMajorLinkerVersion();
	auto minorVersion = peParser.getMinorLinkerVersion();

	if (majorVersion == 'S' && minorVersion == 'R')
	{
		for (const Section* section : peParser.getSections())
		{
			std::string bytes;
			if (section->getString(bytes, 0, 8) && startsWith(bytes, "PDATA000"))
			{
				strength = DetectionStrength::HIGH;
				break;
			}
		}

		addPacker(source, strength, "Armadillo");
	}
}

/**
 * Try to detect StarForce packer
 */
void PeHeuristics::getStarforceHeuristic()
{
	auto source = DetectionMethod::SECTION_TABLE_H;
	auto strength = DetectionStrength::MEDIUM;

	if (noOfSections < 2)
	{
		return;
	}

	// Check import table for protect.dll library
	const auto importTab = peParser.getImportTable();
	if (importTab && importTab->hasLibraryCaseInsensitive("protect.dll"))
	{
		strength = DetectionStrength::HIGH;

		// This section name seems to appear in other binaries
		// too so check only if protect.dll is linked
		if (findSectionName(".ps4") > 0)
		{
			addPacker(source, strength, "StarForce", "4.x - 5.x");
			return;
		}
	}

	const auto first = sections[0]->getName();
	if (startsWith(first, ".sforce") || findSectionName(".brick") > 0)
	{
		std::string version;
		if (first == ".sforce3")
		{
			version = "3.x";
		}

		addPacker(source, strength, "StarForce", version);
	}
}

/**
 * Try to detect compiler by linker version
 */
void PeHeuristics::getLinkerVersionHeuristic()
{
	if (!peParser.getRichHeader())
	{
		// Rich header control was previously removed but there
		// are apparently other linkers with same versions
		return;
	}

	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::HIGH;

	auto majorVersion = peParser.getMajorLinkerVersion();
	auto minorVersion = peParser.getMinorLinkerVersion();

	// Source: https://en.wikipedia.org/wiki/Microsoft_Visual_C++
	// Source: https://en.wikipedia.org/wiki/Microsoft_Visual_Studio

	std::string studioVersion, linkerVersion;
	if (majorVersion == 14 && minorVersion == 10)
	{
		studioVersion = "2017";
		linkerVersion = "14.1";
	}
	else if (majorVersion == 14 && minorVersion == 0)
	{
		studioVersion = "2015";
		linkerVersion = "14.0";
	}
	else if (majorVersion == 12 && minorVersion == 0)
	{
		studioVersion = "2013";
		linkerVersion = "12.0";
	}
	else if (majorVersion == 11 && minorVersion == 0)
	{
		studioVersion = "2012";
		linkerVersion = "11.0";
	}
	else if (majorVersion == 10 && minorVersion == 0)
	{
		studioVersion = "2010";
		linkerVersion = "10.0";
	}
	else if (majorVersion == 9 && minorVersion == 0)
	{
		studioVersion = "2008";
		linkerVersion = "9.0";
	}
	else if (majorVersion == 8 && minorVersion == 0)
	{
		studioVersion = "2005";
		linkerVersion = "8.0";
	}
	else if (majorVersion == 7 && minorVersion == 10)
	{
		studioVersion = ".NET 2003";
		linkerVersion = "7.1";
	}
	else if (majorVersion == 7 && minorVersion == 0)
	{
		studioVersion = ".NET 2002";
		linkerVersion = "7.0";
	}
	else if (majorVersion == 6 && minorVersion == 0)
	{
		studioVersion = "6.0";
		linkerVersion = "6.0";
	}
	else if (majorVersion == 5 && minorVersion == 0)
	{
		studioVersion = "97";
		linkerVersion = "5.0";
	}
	else if (majorVersion == 4 && minorVersion == 0)
	{
		linkerVersion = "4.x";
	}

	if (linkerVersion.empty())
	{
		// Version did not match with any known version
		return;
	}

	// Add linker
	addLinker(source, strength, "Microsoft Linker", linkerVersion);

	// Add more info if we are sure that binary is MSVC
	if (isDetected("MSVC", DetectionStrength::MEDIUM))
	{
		// MSVC version is same as linker except for v14.1
		auto msvcVersion = linkerVersion == "14.1" ? "15.0" : linkerVersion;

		// Detect possible debug version
		for (const auto tool : toolInfo.detectedTools)
		{
			// Check for debug keyword in signature detections
			if (tool.isCompiler() && tool.name == "MSVC"
					&& contains(tool.versionInfo, "debug"))
			{
				msvcVersion += " debug";
				break;
			}
		}

		studioVersion = "Visual Studio " + studioVersion;
		addCompiler(source, strength, "MSVC", msvcVersion, studioVersion);

		// Do not add language if MSIL is detected
		if (!peParser.isDotNet() && !peParser.isPackedDotNet())
		{
			addLanguage("C++");
		}
	}
}

/**
 * Various PE specific .rdata section heuristics
 */
void PeHeuristics::getRdataHeuristic()
{
	auto source = DetectionMethod::COMMENT_H;
	auto strength = DetectionStrength::MEDIUM;

	std::string content;
	const Section* section = fileParser.getSection(".rdata");
	if (!section || !section->getString(content))
	{
		return;
	}

	std::vector<std::string> records;
	separateStrings(content, records);

	std::string name, version, extra;
	for (const auto& record : records)
	{
		// AutoIt detections
		if (startsWith(record, "This is a third-party compiled AutoIt script.")
				|| startsWith(record, "This is a compiled AutoIt script."))
		{
			name = "Aut2Exe";
			version = "3.x";
			addPriorityLanguage("AutoIt", "", true);
			break;
		}
		else if (startsWith(record, "Compiled AutoIt"))
		{
			name = "Aut2Exe";
			version = "2.x";
			addPriorityLanguage("AutoIt", "", true);
			break;
		}
	}

	if (!name.empty())
	{
		addCompiler(source, strength, name, version, extra);
	}
}

/**
 * Search for NSIS installer
 */
void PeHeuristics::getNullsoftHeuristic()
{
	auto source = DetectionMethod::SECTION_TABLE_H;
	auto strength = DetectionStrength::MEDIUM;

	const Section* section = peParser.getSection(".ndata");
	if (section && section->getAddress() && !section->getOffset())
	{
		unsigned long long address;
		if (section->getSizeInMemory(address) && address)
		{
			addInstaller(source, strength, "Nullsoft Install System");
		}
	}
}

/**
 * Search manifest for possible tool clues
 */
void PeHeuristics::getManifestHeuristic()
{
	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::HIGH;

	std::string manifest;
	const auto *resource = fileParser.getManifestResource();
	if (!resource || !resource->getString(manifest))
	{
		return;
	}

	tinyxml2::XMLDocument parsedManifest;
	if (parsedManifest.Parse(manifest.c_str(), manifest.length()) != tinyxml2::XML_SUCCESS)
	{
		return;
	}

	if (isDetected("Nullsoft"))
	{
		auto version = getNullsoftManifestVersion(manifest);
		if (!version.empty())
		{
			addInstaller(source, strength, "Nullsoft Install System", version);
			return;
		}
	}

	if (isDetected("WinZip SFX"))
	{
		if (auto* root = parsedManifest.FirstChildElement("assembly"))
		{
			if (auto* identity = root->FirstChildElement("assemblyIdentity"))
			{
				if (endsWith(identity->Attribute("name"), "WZSFX")
						|| endsWith(identity->Attribute("name"), "WZSEPE32"))
				{
					std::string version = identity->Attribute("version");
					addInstaller(source, strength, "WinZip SFX", version.substr(0, 3));
					return;
				}
			}
		}
	}

	if (fileParser.getOverlaySize() && contains(manifest, "WinRAR SFX module"))
	{
		std::string magic;
		if (fileParser.getString(magic, declaredLength, 4))
		{
			if (magic == "Rar!")
			{
				addInstaller(source, strength, "WinRAR SFX");
				return;
			}

			if (startsWith(magic, "PK"))
			{
				addInstaller(source, strength, "WinRAR SFX", "", "with ZIP payload");
				return;
			}
		}
	}

	if (fileParser.getOverlaySize() && contains(manifest, "WinRAR archiver"))
	{
		std::string magic;
		if (fileParser.getString(magic, declaredLength, 4))
		{
			if (magic == "Rar!")
			{
				addInstaller(source, strength, "WinRAR SFX", "", "console version");
				return;
			}
		}
	}
}

/**
 * Try to detect 7-zip SFX
 */
void PeHeuristics::getSevenZipHeuristics()
{
	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::HIGH;

	if (!fileParser.getOverlaySize())
	{
		return;
	}

	bool detected = false;
	std::string magic;
	if (fileParser.getString(magic, declaredLength, 18))
	{
		if (magic == ";!@Install@!UTF-8!")
		{
			detected = true;
		}
	}
	if (fileParser.getString(magic, declaredLength, 6))
	{
		if (magic == "7z\xBC\xAF\x27\x1C")
		{
			detected = true;
		}
	}

	if (detected)
	{
		auto resourceTable = peParser.getResourceTable();
		if (resourceTable)
		{
			// See: VS_VERSIONINFO structure documentation
			auto resource = resourceTable->getResourceWithType(16);
			if (resource)
			{
				std::uint64_t infoL = 0;
				auto offset =  resource->getOffset();
				peParser.get2ByteOffset(offset + 2, infoL, Endianness::LITTLE);

				if (infoL)
				{
					offset += 0x38; // skip to product version - minor
					std::uint64_t minV = 0;
					peParser.get2ByteOffset(offset, minV, Endianness::LITTLE);
					offset += 0x02; // skip to product version - major
					std::uint64_t majV = 0;
					peParser.get2ByteOffset(offset, majV, Endianness::LITTLE);

					std::stringstream version;
					version << majV << "." << std::setfill('0') << std::setw(2) << minV;
					addInstaller(source, strength, "7-Zip SFX", version.str());
				}
			} // resource
		} // resource table
	}
}

/**
 * Try to detect MEW packer
 */
void PeHeuristics::getMewSectionHeuristics()
{
	auto source = DetectionMethod::SECTION_TABLE_H;
	auto strength = DetectionStrength::MEDIUM;

	std::string version;
	if (noOfSections == 2)
	{
		if (startsWith(sections[0]->getName(), "MEWF"))
		{
			version = "11 SE 1.x";
		}
		else if (sections[0]->getName() == ".data"
					&& sections[1]->getName() == ".decode")
		{
			version = "11 SE 1.x";
		}
	}

	if (!version.empty())
	{
		addPacker(source, strength, "MEW", version);
	}
}

/**
 * Try to detect NsPack packer
 */
void PeHeuristics::getNsPackSectionHeuristics()
{
	auto source = DetectionMethod::SECTION_TABLE_H;
	auto strength = DetectionStrength::MEDIUM;

	if (!noOfSections)
	{
		return;
	}

	const auto &firstName = sections[0]->getName();
	if (firstName == "nsp0" || firstName == ".nsp0")
	{
		const auto namePrefix = firstName.substr(0, firstName.length() - 1);

		std::size_t counter = 0;
		for (std::size_t i = 1; i < noOfSections; ++i)
		{
			if (sections[i]->getName() != (namePrefix + numToStr(i)))
			{
				if (++counter > 1)
				{
					return;
				}
			}
		}

		auto version = sections[0]->getName() == "nsp0" ? "2.x" : "3.x";
		addPacker(source, strength, "NsPack", version);
	}
}

/**
 * Detect tools by specific section names
 */
void PeHeuristics::getPeSectionHeuristics()
{
	auto source = DetectionMethod::SECTION_TABLE_H;
	auto strength = DetectionStrength::HIGH;

	if (!noOfSections)
	{
		return;
	}

	// Get often used names
	const auto firstName = sections[0]->getName();
	const auto lastName = sections[noOfSections - 1]->getName();

	// Get often used conditional names
	const auto secondName = noOfSections > 1 ? sections[1]->getName() : "";
	const auto secondLastName = noOfSections > 2 ? sections[noOfSections - 2]->getName() : "";
	const auto epName =  toolInfo.entryPointSection ? toolInfo.epSection.getName() : "";

	// Installer detections
	if (lastName == "_winzip_")
	{
		addInstaller(source, strength, "WinZip SFX");
	}

	// Other tools
	if (findSectionName(".mackt") >= 1)
	{
		toolInfo.addTool(source, strength, ToolType::OTHER, "ImpREC reconstructed");
	}
	if (findSectionName(".winapi") >= 1)
	{
		toolInfo.addTool(source, strength, ToolType::OTHER, "API Override tool");
	}

	// Packer detections
	if (lastName == ".taz")
	{
		addPacker(source, strength, "PESpin");
	}
	if (lastName == ".ccg")
	{
		addPacker(source, strength, "CCG packer");
	}
	if (lastName == ".svkp")
	{
		addPacker(source, strength, "SVKProtector");
	}
	if (lastName == "PEPACK!!")
	{
		addPacker(source, strength, "PE-PACK");
	}
	if (lastName == ".WWP32")
	{
		addPacker(source, strength, "WWPack32");
	}
	if (lastName == "lamecryp")
	{
		addPacker(source, strength, "LameCrypt");
	}
	if (lastName == ".rmnet")
	{
		addPacker(source, strength, "Ramnit");
	}
	if (firstName == ".Upack" || firstName == ".ByDwing")
	{
		addPacker(source, strength, "Upack");
	}
	if (lastName == "yC" || lastName == ".y0da" || lastName == ".yP")
	{
		addPacker(source, strength, "yoda's Crypter");
	}
	if (findSectionName(".petite") == 1)
	{
		addPacker(source, strength, "Petite");
	}
	if (findSectionName(".pklstb") == 1)
	{
		addPacker(source, strength, "PKLite");
	}
	if (findSectionName("hmimys") == 1)
	{
		addPacker(source, strength, "hmimys");
	}
	if (findSectionName(".securom") == 1)
	{
		addPacker(source, strength, "SecuROM");
	}
	if (findSectionName(".neolit") == 1 || findSectionName(".neolite") == 1)
	{
		addPacker(source, strength, "NeoLite");
	}
	if (findSectionName("RCryptor") == 1 || findSectionName(".RCrypt") == 1)
	{
		addPacker(source, strength, "RCryptor");
	}
	if (findSectionName(".MPRESS1") == 1 && findSectionName(".MPRESS2") == 1)
	{
		addPacker(source, strength, "MPRESS");
	}
	if (findSectionName(".dyamarC") == 1 && findSectionName(".dyamarD") == 1)
	{
		addPacker(source, strength, "DYAMAR");
	}
	if (findSectionName("krypton") == 1 && findSectionName("YADO") >= 1)
	{
		addPacker(source, strength, "Krypton");
	}
	if (findSectionName(".boom") >= 1)
	{
		addPacker(source, strength, "The Boomerang");
	}
	if (findSectionName("DAStub") >= 1)
	{
		addPacker(source, strength, "DAStub Dragon Armor Protector");
	}
	if (findSectionName("!EPack") >= 1)
	{
		addPacker(source, strength, "EPack");
	}
	if (findSectionName(".MaskPE") >= 1)
	{
		addPacker(source, strength, "MaskPE");
	}
	if (findSectionName(".perplex") >= 1)
	{
		addPacker(source, strength, "Perplex PE Protector");
	}
	if (findSectionName("ProCrypt") >= 1)
	{
		addPacker(source, strength, "ProCrypt");
	}
	if (findSectionName(".seau") >= 1)
	{
		addPacker(source, strength, "SeauSFX");
	}
	if (findSectionName(".spack") >= 1)
	{
		addPacker(source, strength, "Simple Pack");
	}
	if (findSectionName(".charmve") >= 1 || findSectionName(".pinclie") >= 1)
	{
		addPacker(source, strength, "PIN tool");
	}
	if (epName == "TheHyper")
	{
		addPacker(source, strength, "TheHyper's protector");
	}
	if (startsWith(epName, "Themida"))
	{
		addPacker(source, strength, "Themida");
	}
	if (findSectionName("NFO") == noOfSections)
	{
		addPacker(source, strength, "NFO");
	}
	if (findSectionName("kkrunchy") == 1 && noOfSections == 1)
	{
		addPacker(source, strength, "kkrunchy");
	}
	if (noOfSections > 1)
	{
		if (lastName == "pebundle" && secondLastName == "pebundle")
		{
			addPacker(source, strength, "PEBundle");
		}
	}
	if (noOfSections == 2)
	{
		if (firstName == ".packed" && lastName == ".RLPack")
		{
			addPacker(source, strength, "RLPack");
		}
		if (firstName == ".rsrc" && lastName == "coderpub")
		{
			addPacker(source, strength, "DxPack");
		}
	}
	if (noOfSections > 2)
	{
		if (firstName == "UPX0" && secondName == "UPX1")
		{
			addPacker(source, strength, "UPX");
		}
		if (lastName == ".data" && secondLastName == ".data"
				&& findSectionName("") == noOfSections - 2)
		{
			addPacker(source, strength, "ASProtect");
		}
	}
	if (noOfSections >= 2)
	{
		if (findSectionName("BitArts") == noOfSections - 1)
		{
			addPacker(source, strength, "Crunch/PE");
		}
		if (secondLastName == ".tsustub" && lastName == ".tsuarch")
		{
			addPacker(source, strength, "TSULoader");
		}
		if (secondLastName == ".gentee")
		{
			addPacker(source, strength, "Gentee");
		}
	}
	if (firstName == "pec1" && epName == "pec2" && toolInfo.epSection.getIndex() == 1)
	{
		addPacker(source, strength, "PECompact", "1.xx");
	}
	if (epName == "ExeS" && toolInfo.epSection.getSizeInFile() == 0xD9F
			&& startsWith(toolInfo.epBytes, "EB00EB"))
	{
		addPacker(source, strength, "EXE Stealth", "2.72 - 2.73");
	}
	if (epName == ".aspack")
	{
		auto epSecIndex = toolInfo.epSection.getIndex();
		if (epSecIndex + 1 < noOfSections - 1
				&& sections[epSecIndex + 1]->getName() == ".adata")
		{
			addPacker(source, strength, "ASPack");
		}
	}

	std::size_t sameName = 0;
	if ((sameName = findSectionName(".pelock")) && sameName >= noOfSections - 1)
	{
		addPacker(source, strength, "PELock", "1.x");
	}
	if ((sameName = findSectionName("PELOCKnt"))
			&& (sameName >= noOfSections - 2 || noOfSections < 2))
	{
		addPacker(source, strength, "PELock", "NT");
	}

	getMewSectionHeuristics();
	getNsPackSectionHeuristics();
}

void PeHeuristics::getFormatSpecificLanguageHeuristics()
{
	getGoHeuristics();
	getAutoItHeuristics();
	getDotNetHeuristics();
	getVisualBasicHeuristics();
}

void PeHeuristics::getFormatSpecificCompilerHeuristics()
{
	getSlashedSignatures();
	getMorphineHeuristics();
	getPelockHeuristics();
	getEzirizReactorHeuristics();
	getUpxHeuristics();
	getFsgHeuristics();
	getPeCompactHeuristics();
	getAndpakkHeuristics();
	getEnigmaHeuristics();
	getVBoxHeuristics();
	getActiveDeliveryHeuristics();
	getAdeptProtectorHeuristics();
	getCodeLockHeuristics();
	getNetHeuristic();
	getExcelsiorHeuristics();
	getVmProtectHeuristics();
	getBorlandDelphiHeuristics();
	getBeRoHeuristics();
	getMsvcIntelHeuristics();
	getStarforceHeuristic();
	getArmadilloHeuristic();
	getRdataHeuristic();
	getNullsoftHeuristic();
	getLinkerVersionHeuristic();
	getManifestHeuristic();
	getSevenZipHeuristics();
	getPeSectionHeuristics();
}

} // namespace cpdetect
} // namespace retdec
