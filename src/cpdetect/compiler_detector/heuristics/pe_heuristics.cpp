/**
 * @file src/cpdetect/compiler_detector/heuristics/pe_heuristics.cpp
 * @brief Methods of PeHeuristics class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <initializer_list>
#include <map>
#include <regex>

#include <tinyxml2.h>

#include "tl-cpputils/conversion.h"
#include "tl-cpputils/string.h"
#include "cpdetect/compiler_detector/heuristics/pe_heuristics.h"
#include "cpdetect/settings.h"
#include "cpdetect/signatures/avg/signature.h"
#include "fileformat/utils/conversions.h"
#include "fileformat/utils/file_io.h"
#include "fileformat/utils/other.h"

using namespace tl_cpputils;
using namespace fileformat;
using namespace std::string_literals;

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
 * Try find string which indicate AutoIt programming language
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
 * Try find NSIS version in manifest
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
PeHeuristics::PeHeuristics(fileformat::PeFormat &parser, Search &searcher, ToolInformation &toolInfo) :
	Heuristics(parser, searcher, toolInfo), peParser(parser)
{

}

/**
 * Destructor
 */
PeHeuristics::~PeHeuristics()
{

}

/**
 * Try detect version od Enigma protector
 * @return Detected version of Enigma or empty string is version is not detected
 */
std::string PeHeuristics::getEnigmaVersion()
{
	const auto *sec = fileParser.getLastSection();
	if(!sec || !sec->getLoadedSize())
	{
		sec = fileParser.getLastButOneSection();
		if(!sec || !sec->getLoadedSize())
		{
			return "";
		}
	}

	const std::string pattern = "\0\0\0ENIGMA"s;
	const auto &content = search.getPlainString();
	const auto pos = content.find(pattern, sec->getOffset());
	if(pos < sec->getOffset() + sec->getLoadedSize())
	{
		std::uint64_t result1, result2;
		if(fileParser.get1ByteOffset(pos + pattern.length(), result1) && fileParser.get1ByteOffset(pos + pattern.length() + 1, result2))
		{
			return numToStr(result1) + "." + numToStr(result2);
		}
	}

	return "";
}

/**
 * Try detect additional information of UPX packer
 * @return Additional information. Each information enclosed in square brackets separated by the space.
 */
std::string PeHeuristics::getUpxAdditionalInfo(std::size_t metadataPos)
{
	const auto& content = search.getPlainString();

	std::string additionalInfo;
	if(content.length() > metadataPos + 6)
	{
		switch(content[metadataPos + 6])
		{
			case 0x2:
			case 0x3:
			case 0x4:
				additionalInfo += "[NRV2B]";
				break;
			case 0x5:
			case 0x6:
			case 0x7:
				additionalInfo += "[NRV2D]";
				break;
			case 0x8:
			case 0x9:
			case 0xA:
				additionalInfo += "[NRV2E]";
				break;
			case 0xE:
				additionalInfo += "[LZMA]";
				break;
			default:
				break;
		}
	}

	if(content.length() > metadataPos + 29)
	{
		if(!additionalInfo.empty())
		{
			additionalInfo += ' ';
		}

		std::uint32_t filterId = static_cast<std::uint32_t>(content[metadataPos + 28]);
		std::uint32_t filterParam = static_cast<std::uint32_t>(content[metadataPos + 29]);
		additionalInfo += "[Filter: 0x" + numToStr(filterId, std::hex) + ", Param: 0x" + numToStr(filterParam, std::hex) + ']';
	}

	return additionalInfo;
}

/**
 * Try to detect Go language binaries
 */
void PeHeuristics::getGoHeuristics()
{
	const auto* section = fileParser.getSection(".text");
	if (section && section->getBytes(0, 15) ==  "\xFF Go build ID: ")
	{
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
	if(fileParser.getStringFromEnd(end, 8) && findAutoIt(end))
	{
		addCompiler(source, strength, "Aut2Exe");
		addPriorityLanguage("AutoIt", "", true);
	}

	const auto &content = search.getPlainString();
	const auto *rsrc = fileParser.getSection(".rsrc");
	if(rsrc && rsrc->getOffset() < content.length()
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
	if(peParser.isDotNet() || peParser.isPackedDotNet())
	{
		addLanguage("CIL/.NET", "", true);
	}
}

/**
 * Try to detect Visual Basic=
 */
void PeHeuristics::getVisualBasicHeuristics()
{
	auto source = DetectionMethod::LINKED_LIBRARIES_H;
	auto strength = DetectionStrength::HIGH;

	unsigned long long version = 0;
	if(peParser.isVisualBasic(version))
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
	if(!fileParser.isX86OrX86_64() || !canSearch || !toolInfo.entryPointOffset)
	{
		return;
	}

	const auto stopOffset = toolInfo.epOffset + LIGHTWEIGHT_FILE_SCAN_AREA;

	for(const auto &sig : x86SlashedSignatures)
	{
		const auto start = toolInfo.epOffset + ((sig.startOffset == std::numeric_limits<unsigned>::max()) ? 0 : sig.startOffset);
		const auto end = (sig.endOffset == std::numeric_limits<unsigned>::max()) ? stopOffset :
			std::min(stopOffset, toolInfo.epOffset + sig.endOffset + fileParser.bytesFromNibblesRounded(sig.pattern.length() - 1) - 1);
		const auto nibbles = search.findSlashedSignature(sig.pattern, start, end);
		if(nibbles)
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
	if(!fileParser.isX86() || !toolInfo.entryPointOffset ||
		toolInfo.epOffset < 0x400 || toolInfo.epOffset > 0x1400)
	{
		return;
	}

	auto source = DetectionMethod::SECTION_TABLE_H;
	auto strength = DetectionStrength::MEDIUM;

	if(noOfSections > 2 && sections[0]->getName() == ".text" && sections[1]->getName() == ".data" &&
		sections[2]->getName() == ".idata" && sections[2]->getSizeInFile() == 0x200)
	{
		unsigned long long rva, size;
		if(peParser.getDataDirectoryRelative(1, rva, size) && size == 0x1000)
		{
			addPacker(source, strength, "Morphine", "1.2");
		}
	}
	else if(noOfSections > 1 && sections[0]->getName() == ".text" && sections[1]->getName() == ".idata" &&
			(sections[1]->getSizeInFile() == 0x200 || sections[1]->getSizeInFile() == 0x400))
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
	if(peParser.getDataDirectoryRelative(1, rva, size) && size == 0x5C &&
		peParser.getDataDirectoryRelative(15, rva, size) && size == 0x1000)
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
	if(fileParser.getSection("reacto") && noOfSections > 3 && !sections[1]->getSizeInFile() &&
		!sections[2]->getSizeInFile() && !sections[3]->getSizeInFile())
	{
		version = "2.0 - 2.1";
		source = DetectionMethod::SECTION_TABLE_H;
	}
	else if(canSearch)
	{
		const auto *sec0 = peParser.getPeSection(0);
		const auto *sec1 = peParser.getPeSection(1);
		if(sec0 && search.findUnslashedSignature("558BECB90F0000006A006A004975F951535657B8--------E8;",
			sec0->getOffset(), sec0->getOffset() + sec0->getLoadedSize() - 1))
		{
			version = "3.X";
		}
		else if(sec1 && search.findUnslashedSignature("5266686E204D182276B5331112330C6D0A204D18229EA129611C76B505190158;",
			sec1->getOffset(), sec1->getOffset() + sec1->getLoadedSize() - 1) && sec1->getPeCoffFlags() == 0xC0000040)
		{
			version = "4.8 - 5.0";
		}
		else if(noOfSections >= 4 && findSectionName(".text") == 1 && findSectionName(".rsrc") == 1 && toolInfo.entryPointOffset)
		{
			const auto *resTable = fileParser.getResourceTable();
			const auto *resVer = fileParser.getVersionResource();
			if(resTable && resTable->hasResourceWithName("__") && resVer)
			{
				std::size_t lId;
				if(resVer->getLanguageId(lId) && !lId)
				{
					if(search.exactComparison("E8--------E9--------6A0C68;", toolInfo.epOffset))
					{
						version = "4.2";
					}
					else if(search.exactComparison("E8--------E9--------8BFF558BEC83EC208B45085657;", toolInfo.epOffset))
					{
						version = "4.5 - 4.7";
					}
				}
			}
		}
	}

	if(!version.empty())
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
	if(pos < 0x500 && pos < content.length() - upxVer.length())
	{
		// we must decide between UPX and UPX$HiT
		source = DetectionMethod::COMBINED;
		if(noOfSections == 3 && sections[0]->getName() == ".code" &&
			sections[1]->getName() == ".text" && sections[2]->getName() == ".rsrc")
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
	if(pos >= minPos && pos < 0x500)
	{
		std::string version;
		std::size_t num;
		if(strToNum(content.substr(pos - minPos, 1), num) && strToNum(content.substr(pos - minPos + 2, 2), num))
		{
			version = content.substr(pos - minPos, verLen);
		}
		std::string additionalInfo = getUpxAdditionalInfo(pos);
		if(!additionalInfo.empty())
		{
			if(!version.empty())
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

	if(search.hasString("FSG!", peParser.getPeHeaderOffset(), peParser.getMzHeaderSize()))
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

	// format: PEC2(any character)O
	const std::string pattern = "PEC2";
	const auto patLen = pattern.length();
	const auto &content = search.getPlainString();
	const auto pos = content.find(pattern);
	if(pos < 0x500 && pos <= content.length() - patLen - 2 && content[pos + patLen + 1] == 'O')
	{
		for(const auto &item : peCompactMap)
		{
			if(content[pos + patLen] == item.first)
			{
				addPacker(source, strength, "PECompact", item.second);
				return;
			}
		}

		addPacker(source, strength, "PECompact");
	}

	if(search.hasString("PECompact2", 0, 0x4FF))
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

	if(noOfSections == 1 && sections[0]->getName() == "ANDpakk2")
	{
		const auto *table = fileParser.getImportTable();
		if(table && table->getNumberOfLibraries() == 1)
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

	if(toolInfo.entryPointOffset && canSearch && search.exactComparison("60E8000000005D83----81ED;", toolInfo.epOffset))
	{
		const auto *sec = fileParser.getSection(".data");
		if(sec)
		{
			const std::string pattern = "Enigma protector v";
			const auto &content = search.getPlainString();
			const auto pos = content.find(pattern, sec->getOffset());
			if(pos < sec->getOffset() + sec->getSizeInFile() && pos <= content.length() - 4)
			{
				addPacker(source, strength, "Enigma", content.substr(pos + pattern.length(), 4));
				return;
			}
		}
	}

	const auto *importTable = fileParser.getImportTable();
	if(importTable && importTable->getNumberOfImportsInLibrary(1) == 1)
	{
		const auto *import = importTable->getImport("MessageBoxA");
		if(import && import->getLibraryIndex() == 1)
		{
			const auto version = getEnigmaVersion();
			if(!version.empty())
			{
				addPacker(source, strength, "Enigma", version);
				return;
			}
		}
	}

	for(const auto &sign : enigmaPatterns)
	{
		if(toolInfo.entryPointOffset && canSearch && search.exactComparison(sign, toolInfo.epOffset))
		{
			addPacker(DetectionMethod::SIGNATURE, strength, "Enigma", getEnigmaVersion());
			return;
		}
	}

	if(peParser.isDotNet() && search.hasStringInSection("\0\0\0ENIGMA"s, std::size_t(0)))
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

	if(toolInfo.entryPointOffset && canSearch &&
		search.exactComparison("FF7424--FF7424--FF7424--68--------68--------68--------68--------FF15--------68--------FFD0C2;", toolInfo.epOffset))
	{
		std::string version;
		const auto *table = fileParser.getImportTable();
		if(table && table->hasLibrary("vboxp410.dll"))
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

	if(fileParser.getSection("actdlvry") && toolInfo.entryPointOffset && canSearch &&
		search.exactComparison("64A1--------558BEC6A--68--------68--------50648925--------83EC605356578965--FF15;", toolInfo.epOffset))
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

	if(peParser.isDotNet() && search.hasStringInSection("ByAdeptProtector", std::size_t(0)))
	{
		std::string version;
		if(search.hasStringInSection("STAThreadAttribute", std::size_t(0)))
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
	if(table && table->hasLibrary("CODE-LOCK.OCX"))
	{
		addPacker(source, strength, "Code-Lock");
	}
}

/**
 * Try to detect Phoenix
 */
void PeHeuristics::getPhoenixHeuristics()
{
	auto source = DetectionMethod::SIGNATURE;
	auto strength = DetectionStrength::MEDIUM;

	const auto *sec = fileParser.getSection(0);
	if(sec && peParser.isDotNet())
	{
		std::string version;
		if(canSearch && search.findUnslashedSignature("0000010B160C----------0208----------0D0906085961D21304091E630861D21305070811051E62110460D19D081758;",
			sec->getOffset(), sec->getOffset() + sec->getLoadedSize() - 1))
		{
			version = "1.7 - 1.8";
		}
		else if(search.hasStringInSection("?.resources", sec))
		{
			version = "1.x";
		}

		if(!version.empty())
		{
			addPacker(source, strength, "Phoenix", version);
		}
	}
}

/**
 * Try detect AssemblyInvoke
 */
void PeHeuristics::getAssemblyInvokeHeuristics()
{
	auto source = DetectionMethod::SIGNATURE;
	auto strength = DetectionStrength::MEDIUM;

	const auto *sec = fileParser.getSection(0);
	if(sec && peParser.isDotNet())
	{
		if(canSearch && search.findUnslashedSignature("282D00000A6F2E00000A14146F2F00000A;", sec->getOffset(), sec->getOffset() + sec->getLoadedSize() - 1))
		{
			addCompiler(source, strength, "AssemblyInvoke"); ///< @todo packer?
		}
	}
}

/**
 * Try to detect CliSecure
 */
void PeHeuristics::getCliSecureHeuristics()
{
	auto source = DetectionMethod::SIGNATURE;
	auto strength = DetectionStrength::MEDIUM;

	const auto *sec = fileParser.getSection(0);
	if(sec && peParser.isDotNet())
	{
		if(canSearch && search.findUnslashedSignature("436C69005300650063007500720065;", sec->getOffset(), sec->getOffset() + sec->getLoadedSize() - 1))
		{
			addPacker(source, strength, "CliSecure");
		}
	}
}

/**
 * Try to detect ReNET-pack
 */
void PeHeuristics::getReNetPackHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	if(peParser.isDotNet() && search.hasStringInSection("Protected/Packed with ReNET-Pack by stx", std::size_t(0)))
	{
		addPacker(source, strength, "ReNET-pack");
	}
}

/**
 * Try to detect .NETZ
 */
void PeHeuristics::getDotNetZHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	if(peParser.isDotNet() && search.hasStringInSection("\0NetzStarter\0netz\0"s, std::size_t(0)))
	{
		addPacker(source, strength, ".NETZ");
	}
}

/**
 * Try to detect .NET Spider
 */
void PeHeuristics::getDotNetSpiderHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	if(peParser.isDotNet() && search.hasStringInSection("Protected_By_Attribute\0NETSpider.Attribute"s, std::size_t(0)))
	{
		addPacker(source, strength, ".NET Spider", "0.5 - 1.3");
	}
}

/**
 * Try to detect .netshrink
 */
void PeHeuristics::getDotNetShrinkHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	const auto *sec = fileParser.getSection(0);
	if(sec && peParser.isDotNet() && std::any_of(dotNetShrinkPatterns.begin(), dotNetShrinkPatterns.end(),
		[&] (const auto &str)
		{
			return this->canSearch && this->search.findUnslashedSignature(str, sec->getOffset(), sec->getOffset() + sec->getLoadedSize() - 1);
		}
	))
	{
		addPacker(source, strength, ".netshrink", "2.01 (demo)");
	}
}

/**
 * Try to detect Excelsior Installer
 */
void PeHeuristics::getExcelsiorHeuristics()
{
	auto source = DetectionMethod::COMBINED;
	auto strength = DetectionStrength::MEDIUM;

	if(toolInfo.entryPointOffset && canSearch &&
		search.exactComparison("83EC--53555657E8--------6A--5B391D--------8BF37E--8B3D--------A1--------8B----8A08;", toolInfo.epOffset) &&
		search.hasString("ExcelsiorII1", fileParser.getDeclaredFileLength(), fileParser.getLoadedFileLength() - 1))
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

	if(noOfSections < 3 || (noOfSections == 3 && !sections[0]->getSizeInFile()))
	{
		return;
	}

	if(toolInfo.entryPointOffset && canSearch)
	{
		if(search.exactComparison("54C70424--------9C60C74424----------C64424----887424--60;", toolInfo.epOffset))
		{
			addPacker(source, strength, "VMProtect", "2.06");
			return;
		}
		else if(fileParser.getSection(".vmp0") &&
				(search.exactComparison("68--------E9;", toolInfo.epOffset) ||
				 search.exactComparison("68--------E8;", toolInfo.epOffset)))
		{
			addPacker(source, strength, "VMProtect", "1.60 - 2.05");
			return;
		}
	}

	for(const std::string secName : {".vmp0", ".vmp1", ".vmp2"})
	{
		if(fileParser.getSection(secName))
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
	if(!toolInfo.entryPointSection || toolInfo.epSection.getIndex() ||
		toolInfo.epSection.getOffset() != 0x400 || !fileParser.getImageBaseAddress(imageBaseAddr) ||
		toolInfo.epSection.getAddress() < imageBaseAddr ||
		toolInfo.epSection.getAddress() - imageBaseAddr != 0x1000 ||
		toolInfo.epSection.getName() != "CODE" || noOfSections < 8 ||
		sections[1]->getName() != "DATA" || sections[2]->getName() != "BSS" ||
		sections[3]->getName() != ".idata" || sections[4]->getName() != ".tls" ||
		sections[5]->getName() != ".rdata" || sections[6]->getName() != ".reloc" ||
		sections[7]->getName() != ".rsrc")
	{
		return;
	}

	if(search.hasStringInSection("SOFTWARE\\Borland\\Delphi\\RTL\0FPUMaskValue"s, sections[0]))
	{
		addCompiler(source, strength, "Borland Delphi");
	}
	else if(peParser.getTimeStamp() == 0x2A425E19) // 1992-06-19
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

	const std::string &beroString = "Compiled by: BeRoTinyPascal - (C) Copyright 2006, Benjamin";
	if(toolInfo.entryPointSection && search.hasStringInSection(beroString, toolInfo.epSection.getIndex()))
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

	if(std::none_of(msvcRuntimeStrings.begin(), msvcRuntimeStrings.end(),
		[this] (const auto &str)
		{
			return this->search.hasStringInSection(str, ".rdata");
		}
	))
	{
		return;
	}

	if(findSectionName(".reloc") == 1)
	{
		addCompiler(source, strength, "MSVC");
		addPriorityLanguage("Visual C++");
		return;
	}
	else if(findSectionName(".data1") == 1)
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

	if (noOfSections < 2) {
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

	// Detected linker is always added
	addLinker(source, strength, "Microsoft Linker", linkerVersion);
	if (peParser.isDotNet() || peParser.isPackedDotNet())
	{
		// Do not continue if MSIL is detetced
		return;
	}

	// Add more info if we are sure that binary is MSVC
	if (const auto* detection = isDetected("MSVC"))
	{
		// MSVC version is same as linker except for v14.1
		auto msvcVersion = linkerVersion == "14.1" ? "15.0" : linkerVersion;
		if (endsWith(detection->versionInfo, "(Debug)"))
		{
			// Check for debug keyword in previous detection.
			msvcVersion += " (Debug)";
		}

		studioVersion = "Visual Studio " + studioVersion;
		addCompiler(source, strength, "MSVC", msvcVersion, studioVersion);
		addLanguage("Visual C++");
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
	if(!section || !section->getString(content))
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
	if(!resource || !resource->getString(manifest))
	{
		return;
	}

	tinyxml2::XMLDocument parsedManifest;
	if(parsedManifest.Parse(manifest.c_str(), manifest.length()) != tinyxml2::XML_SUCCESS)
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

	if (isDetected("WinZip Self-Extractor"))
	{
		if (auto* root = parsedManifest.FirstChildElement("assembly"))
		{
			if (auto* identity = root->FirstChildElement("assemblyIdentity"))
			{
				if (endsWith(identity->Attribute("name"), "WZSFX") ||
						endsWith(identity->Attribute("name"), "WZSEPE32"))
				{
					std::string version = identity->Attribute("version");
					addInstaller(source, strength, "WinZip Self-Extractor", version.substr(0, 3));
					return;
				}
			}
		}
	}

	if (fileParser.getOverlaySize() && contains(manifest, "WinRAR SFX module"))
	{
		std::string magic;
		if (fileParser.getString(magic, fileParser.getDeclaredFileLength(), 4))
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
		if (fileParser.getString(magic, fileParser.getDeclaredFileLength(), 4))
		{
			if (magic == "Rar!")
			{
				addInstaller(source, strength, "WinRAR SFX", "", "console version");
				return;
			}
		}
	}
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
	getPhoenixHeuristics();
	getAssemblyInvokeHeuristics();
	getCliSecureHeuristics();
	getReNetPackHeuristics();
	getDotNetZHeuristics();
	getDotNetSpiderHeuristics();
	getDotNetShrinkHeuristics();
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
}

} // namespace cpdetect
