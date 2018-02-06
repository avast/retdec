/**
 * @file src/cpdetect/compiler_detector/heuristics/heuristics.cpp
 * @brief Class for heuristics detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <regex>

#include "retdec/fileformat-libdwarf-interface/bin_interface.h"

#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/cpdetect/compiler_detector/heuristics/heuristics.h"
#include "retdec/cpdetect/utils/version_solver.h"
#include "retdec/fileformat/utils/conversions.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace cpdetect {

namespace
{

const std::size_t MINIMUM_GO_FUNCTIONS = 5;
const std::size_t MINIMUM_RUST_FUNCTIONS = 5;

const std::size_t MINIMUM_GHC_SYMBOLS = 15;
const std::size_t MINIMUM_GHC_RECORD_SIZE = 9; // "GHC X.X.X"

/**
 * Delphi version names
 *
 * Source: http://delphi.wikia.com/wiki/CompilerVersion_Constant
 */
const std::map<std::string, std::string> delphiVersionMap =
{
	{"32.0", "10.2 Tokyo"},
	{"31.0", "10.1 Berlin"},
	{"30.0", "10 Seattle"},
	{"29.0", "XE8"},
	{"28.0", "XE7"},
	{"27.0", "XE6"},
	{"26.0", "XE5"},
	{"25.0", "XE4"},
	{"24.0", "XE3"},
	{"23.0", "XE2"},
	{"22.0", "XE"},
};

/**
 * Delphi compiler version identification strings with version offset
 *
 * Order matters for iPhone strings, we have to look first for longer.
 * If string is found at position x, version is placed at x + offset.
 */
const std::vector<std::pair<std::string, std::size_t>> delphiStrings =
{
	{"for Win", 46},
	{"for Android", 48},
	{"for Mac OS X", 49},
	{"for Linux 64 bit", 53},
	{"Next Generation for iPhone Simulator", 73},
	{"Next Generation for iPhone ARM64", 69},
	{"Next Generation for iPhone", 63}
};

/**
 * Get name of original programming language as string
 */
bool getDwarfLanguageString(Dwarf_Unsigned langCode, std::string &result)
{
	switch(langCode)
	{
		case DW_LANG_C:
		case DW_LANG_C89:
		case DW_LANG_C99:
			result = "C";
			return true;
		case DW_LANG_C_plus_plus:
			result = "C++";
			return true;
		case DW_LANG_ObjC:
			result = "Objective-C";
			return true;
		case DW_LANG_ObjC_plus_plus:
			result = "Objective-C++";
			return true;
		case DW_LANG_Ada83:
		case DW_LANG_Ada95:
			result = "Ada";
			return true;
		case DW_LANG_Cobol74:
		case DW_LANG_Cobol85:
			result = "Cobol";
			return true;
		case DW_LANG_Fortran77:
		case DW_LANG_Fortran90:
		case DW_LANG_Fortran95:
			result = "Fortran";
			return true;
		case DW_LANG_Modula2:
		case DW_LANG_Modula3:
			result = "Modula";
			return true;
		case DW_LANG_Java:
			result = "Java";
			return true;
		case DW_LANG_Pascal83:
			result = "Pascal";
			return true;
		case DW_LANG_PLI:
			result = "PL/I";
			return true;
		case DW_LANG_UPC:
			result = "Unified Parallel C";
			return true;
		case DW_LANG_D:
			result = "D";
			return true;
		case DW_LANG_Python:
			result = "Python";
			return true;
		case DW_LANG_OpenCL:
			result = "Open Computing Language";
			return true;
		case DW_LANG_Go:
			result = "Go";
			return true;
		case DW_LANG_Haskel:
			result = "Haskell";
			return true;
		default:
			return false;
	}
}

/**
 * Is the given symbol a function from the Go language?
 * @param symbol Input symbol
 * @return @c true if symbol is Go symbol, @c false otherwise
 */
bool isGoFunction(const std::shared_ptr<retdec::fileformat::Symbol> &symbol)
{
	if (!symbol->isFunction())
	{
		// Ignore data and other symbols
		return false;
	}

	const auto &name = symbol->getName();
	return startsWith(name, "__go_") || startsWith(name, "__cgo_");
}

/**
 * Is the given symbol a function from the Rust?
 * @param symbol Input symbol
 * @return @c true if symbol is rust symbol, @c false otherwise
 */
bool isRustFunction(const std::shared_ptr<retdec::fileformat::Symbol> &symbol)
{
	if (!symbol->isFunction())
	{
		// Ignore data and other symbols
		return false;
	}

	const auto &name = symbol->getName();
	return startsWith(name, "__rust_") || startsWith(name, "rust_");
}

/**
 * Is the given symbol from the GHC Haskell?
 * @param symbol Input symbol
 * @return @c true if symbol is GHC symbol, @c false otherwise
 */
bool isGhcSymbol(const std::shared_ptr<retdec::fileformat::Symbol> &symbol)
{
	const auto offset = symbol->getName().find("base_GHC");
	return offset == 0 || offset == 1;
}

/**
 * Convert Embarcadero Delphi version to text extra information
 * @param version compiler version
 * @return extra info
 */
std::string embarcaderoVersionToExtra(const std::string &version)
{
	auto pair = delphiVersionMap.find(version);
	if (pair != delphiVersionMap.end())
	{
		return pair->second;
	}

	return std::string();
}

/**
 * Get file format specific comment section name
 * @param format input file format
 * @return typical comment section name
 */
std::string commentSectionNameByFormat(Format format)
{
	switch (format) {
		case Format::PE:
			return ".rdata";

		case Format::ELF:
			return ".comment";

		case Format::MACHO:
			return "__comment";

		default:
			return std::string();
	}
}

} // anonymous namespace

/**
 * Constructor
 * @param parser Parser of input file
 * @param searcher Signature search engine
 * @param toolInfo Structure for information about detected tools
 */
Heuristics::Heuristics(
		retdec::fileformat::FileFormat &parser, Search &searcher, ToolInformation &toolInfo)
	: fileParser(parser), search(searcher), toolInfo(toolInfo)
{
	canSearch = search.isFileLoaded() && search.isFileSupported();

	const auto secCounter = fileParser.getNumberOfSections();
	sections.reserve(secCounter);
	for (std::size_t i = 0; i < secCounter; ++i)
	{
		const auto *fsec = fileParser.getSection(i);
		if (fsec)
		{
			sections.push_back(fsec);

			// Add names to map
			auto secName = fsec->getName();
			if (!secName.empty()) {
				sectionNameMap[secName]++;
			}
		}
	}

	noOfSections = sections.size();
}

/**
 * Destructor
 */
Heuristics::~Heuristics()
{

}

/**
 * Save all information about detected compiler
 * @param source Used detection method
 * @param strength Strength of detection method
 * @param name Name of detected compiler
 * @param version Version of detected compiler
 * @param extra Extra information about compiler
 */
void Heuristics::addCompiler(
		DetectionMethod source, DetectionStrength strength, const std::string &name,
		const std::string &version, const std::string &extra)
{
	toolInfo.addTool(source, strength, ToolType::COMPILER, name, version, extra);
}

/**
 * Save all information about detected linker
 * @param source Used detection method
 * @param strength Strength of detection method
 * @param name Name of detected linker
 * @param version Version of detected linker
 * @param extra Extra information about linker
 */
void Heuristics::addLinker(
		DetectionMethod source, DetectionStrength strength, const std::string &name,
		const std::string &version, const std::string &extra)
{
	toolInfo.addTool(source, strength, ToolType::LINKER, name, version, extra);
}

/**
 * Save all information about detected installer
 * @param source Used detection method
 * @param strength Strength of detection method
 * @param name Name of detected installer
 * @param version Version of detected installer
 * @param extra Extra information about installer
 */
void Heuristics::addInstaller(
		DetectionMethod source, DetectionStrength strength, const std::string &name,
		const std::string &version, const std::string &extra)
{
	toolInfo.addTool(source, strength, ToolType::INSTALLER, name, version, extra);
}

/**
 * Save all information about detected packer
 * @param source Used detection method
 * @param strength Strength of detection method
 * @param name Name of detected packer
 * @param version Version of detected packer
 * @param extra Extra information about packer
 */
void Heuristics::addPacker(
		DetectionMethod source, DetectionStrength strength, const std::string &name,
		const std::string& version, const std::string& extra)
{
	toolInfo.addTool(source, strength, ToolType::PACKER, name, version, extra);
}

/**
 * Save all information about detected compiler
 * @param matchNibbles Number of significant nibbles agreeing with file content
 * @param totalNibbles Total number of significant nibbles of signature
 * @param name Name of detected compiler
 * @param version Version of detected compiler
 * @param extra Extra information about compiler
 *
 * This method implies DetectResultSource::SIGNATURE. Strength is computed.
 */
void Heuristics::addCompiler(
		std::size_t matchNibbles, std::size_t totalNibbles, const std::string &name,
		const std::string &version, const std::string &extra)
{
	toolInfo.addTool(matchNibbles, totalNibbles, ToolType::COMPILER, name, version, extra);
}

/**
 * Save all information about detected packer
 * @param matchNibbles Number of significant nibbles agreeing with file content
 * @param totalNibbles Total number of significant nibbles of signature
 * @param name Name of detected packer
 * @param version Version of detected packer
 * @param extra Extra information about packer
 *
 * This method implies DetectResultSource::SIGNATURE. Strength is computed.
 */
void Heuristics::addPacker(
		std::size_t matchNibbles, std::size_t totalNibbles, const std::string &name,
		const std::string &version, const std::string &extra)
{
	toolInfo.addTool(matchNibbles, totalNibbles, ToolType::PACKER, name, version, extra);
}

/**
 * Add information about detected programming language
 * @param name Name of detected programming language
 * @param extraInfo Additional information about language
 * @param isBytecode @c true if detected language is bytecode, @c false otherwise
 */
void Heuristics::addLanguage(
		const std::string &name, const std::string &extraInfo, bool isBytecode)
{
	if (priorityLanguageIsSet)
	{
		return;
	}

	toolInfo.addLanguage(name, extraInfo, isBytecode);
}

/**
 * Add information about detected programming language
 * @param name Name of detected programming language
 * @param extraInfo Additional information about language
 * @param isBytecode @c true if detected language is bytecode, @c false otherwise
 *
 * This removes previously detected languages and prevents further detections
 */
void Heuristics::addPriorityLanguage(
		const std::string &name, const std::string &extraInfo, bool isBytecode)
{
	if (priorityLanguageIsSet)
	{
		return;
	}

	priorityLanguageIsSet = true;
	toolInfo.detectedLanguages.clear();
	toolInfo.addLanguage(name, extraInfo, isBytecode);
}

/**
 * Get number of sections which have name equal to @a sectionName
 * @param sectionName Required section name
 * @return Number of sections which have name equal to @a sectionName
 */
std::size_t Heuristics::findSectionName(const std::string &sectionName) const
{
	return mapGetValueOrDefault(sectionNameMap, sectionName, 0);
}

/**
 * Get number of sections with name starting with @a sectionName
 * @param sectionName Required section name
 * @return Number of sections which have name equal to @a sectionName
 */
std::size_t Heuristics::findSectionNameStart(const std::string &sectionName) const
{
	std::size_t result = 0;
	for (const Section* section : sections)
	{
		std::string name = section->getName();
		if (startsWith(name, sectionName))
		{
			result++;
		}
	}

	return result;
}

/**
 * Try to detect tools by section names
 */
void Heuristics::getSectionHeuristics()
{
	auto source = DetectionMethod::SECTION_TABLE_H;
	auto strength = DetectionStrength::HIGH;

	if (!noOfSections)
	{
		return;
	}

	// Compiler detections
	if (findSectionName(".go_export"))
	{
		addCompiler(source, strength, "gccgo");
		addPriorityLanguage("Go");
	}
	if (findSectionName(".note.go.buildid"))
	{
		addCompiler(source, strength, "gc");
		addPriorityLanguage("Go");
	}
	if (findSectionName(".gosymtab") || findSectionName(".gopclntab"))
	{
		addPriorityLanguage("Go");
	}
	if (findSectionName(".debug-ghc-link-info"))
	{
		addCompiler(source, strength, "GHC");
		addPriorityLanguage("Haskell");
	}
	if (findSectionName(".HP.init"))
	{
		addCompiler(source, strength, "HP C++");
		addLanguage("C++");
	}
}

/**
 * Parse GCC record from comment section
 * @param record Record from comment section
 * @return @c true if compiler was detected, @c false otherwise
 */
bool Heuristics::parseGccComment(const std::string &record)
{
	auto source = DetectionMethod::COMMENT_H;
	auto strength = DetectionStrength::LOW;

	const std::string prefix = "GCC: ";
	if (!startsWith(record, prefix))
	{
		return false;
	}

	std::string version;
	if (getVersion(std::regex_replace(record, std::regex("\\([^\\)]+\\)"), ""), version))
	{
		addCompiler(source, strength, "GCC", version);
		return true;
	}

	return false;
}

/**
 * Parse GHC record from comment section
 * @param record Record from comment section
 * @return @c true if GHC was detected, @c false otherwise
 */
bool Heuristics::parseGhcComment(const std::string &record)
{
	auto source = DetectionMethod::COMMENT_H;
	auto strength = DetectionStrength::LOW;

	if (record.size() < MINIMUM_GHC_RECORD_SIZE || !startsWith(record, "GHC"))
	{
		return false;
	}

	const std::string version = record.substr(4);
	if (std::regex_match(version, std::regex("[[:digit:]]+.[[:digit:]]+.[[:digit:]]+")))
	{
		// Check for prior methods results
		if (isDetected("GHC"))
		{
			source = DetectionMethod::COMBINED;
			strength = DetectionStrength::HIGH;
		}

		addCompiler(source, strength, "GHC", version);
		addPriorityLanguage("Haskell");
		return true;
	}

	return false;
}

/**
 * Parse Open64 record from comment section
 * @param record Record from comment section
 * @return @c true if Open64 was detected, @c false otherwise
 */
bool Heuristics::parseOpen64Comment(const std::string &record)
{
	auto source = DetectionMethod::COMMENT_H;
	auto strength = DetectionStrength::LOW;

	const std::string prefix = "#Open64 Compiler Version ";
	const auto prefixLen = prefix.length();
	if (!startsWith(record, prefix))
	{
		return false;
	}

	const std::string separator = " : ";
	const auto separatorLen = separator.length();
	const auto pos = record.find(separator, prefixLen);
	if (pos == std::string::npos)
	{
		return false;
	}

	std::string additionalInfo;
	if (pos + separatorLen < record.length())
	{
		additionalInfo = record.substr(pos + separatorLen);
	}
	std::string version = record.substr(prefixLen, pos - prefixLen);
	addCompiler(source, strength, "Open64", version, additionalInfo);
	return true;
}

/**
 * Try to detect used compiler based on content of comment sections
 * @return @c true if used compiler was successfully detected, @c false otherwise
 */
void Heuristics::getCommentSectionsHeuristics()
{
	for (const auto *sec : fileParser.getSections({".comment", ".rdata"}))
	{
		std::string secContent;
		if (!sec || !sec->getString(secContent))
		{
			continue;
		}

		std::vector<std::string> records;
		separateStrings(secContent, records);

		for (const auto &item : records)
		{
			parseGccComment(item) || parseGhcComment(item) || parseOpen64Comment(item);
		}
	}
}

/**
 * Parse GCC producer from DWARF debug information
 * @param producer DWARF record
 * @return @c true if compiler was detected, @c false otherwise
 */
bool Heuristics::parseGccProducer(const std::string &producer)
{
	auto source = DetectionMethod::DWARF_DEBUG_H;
	auto strength = DetectionStrength::MEDIUM;

	const auto cpp = startsWith(producer, "GNU C++");
	const auto c = !cpp && startsWith(producer, "GNU C");
	const auto fortran = startsWith(producer, "GNU Fortran");
	if (!c && !cpp && !fortran)
	{
		return false;
	}

	std::string version;
	getVersion(producer, version);

	addCompiler(source, strength, "GCC", version);
	addLanguage((c ? "C" : (cpp ? "C++" : "Fortran")));
	return true;
}

/**
 * Parse clang producer from DWARF debug information
 * @param producer DWARF record
 * @return @c true if clang was detected, @c false otherwise
 */
bool Heuristics::parseClangProducer(const std::string &producer)
{
	auto source = DetectionMethod::DWARF_DEBUG_H;
	auto strength = DetectionStrength::MEDIUM;

	if (!contains(producer, "clang"))
	{
		return false;
	}

	std::string version;
	getVersion(producer, version);
	addCompiler(source, strength, "LLVM", version);
	return true;
}

/**
 * Parse Texas Instruments producer from DWARF debug information
 * @param producer DWARF record
 * @return @c true if Texas Instruments was detected, @c false otherwise
 */
bool Heuristics::parseTmsProducer(const std::string &producer)
{
	auto source = DetectionMethod::DWARF_DEBUG_H;
	auto strength = DetectionStrength::MEDIUM;

	if (!startsWith(producer, "TMS470 C/C++"))
	{
		return false;
	}

	std::string version;
	getVersion(producer, version);
	addCompiler(source, strength, "Texas Instruments C/C++", version, "for TMS470");
	return true;
}

/**
 * Try to detect compiler based on DWARF debugging information
 */
void Heuristics::getDwarfInfo()
{
	std::string lang;
	std::size_t langIndex;
	std::vector<std::string> languages;
	std::vector<std::size_t> modulesCounter;

	BinInt binInt(fileParser.getPathToFile(), &fileParser);
	if (!binInt.success())
	{
		return;
	}

	Dwarf_Handler eh = nullptr;
	Dwarf_Ptr ea = nullptr;
	Dwarf_Debug dbg;
	Dwarf_Error err;
	if (dwarf_object_init(binInt.getInt(), eh, ea, &dbg, &err) != DW_DLV_OK)
	{
		return;
	}

	Dwarf_Unsigned cu_header_length = 0;
	Dwarf_Half version_stamp = 0;
	Dwarf_Unsigned abbrev_offset = 0;
	Dwarf_Half address_size = 0;
	Dwarf_Half offset_size = 0;
	Dwarf_Half extension_size = 0;
	Dwarf_Sig8 signature;
	Dwarf_Unsigned typeoffset = 0;
	Dwarf_Unsigned next_cu_header = 0;
	Dwarf_Bool is_info = true;

	while (dwarf_next_cu_header_c(
				dbg,
				is_info,
				&cu_header_length,
				&version_stamp,
				&abbrev_offset,
				&address_size,
				&offset_size,
				&extension_size,
				&signature,
				&typeoffset,
				&next_cu_header,
				&err) == DW_DLV_OK)
	{
		Dwarf_Die cuDie = nullptr;

		// CU have single sibling - CU DIE
		// nullptr - descriptor of first die in CU
		if (dwarf_siblingof_b(dbg, nullptr, is_info, &cuDie, &err) != DW_DLV_OK)
		{
			return;
		}

		Dwarf_Half tag = 0;
		if (dwarf_tag(cuDie, &tag, &err) != DW_DLV_OK
				|| tag != DW_TAG_compile_unit)
		{
			dwarf_dealloc(dbg, cuDie, DW_DLA_DIE);
			return;
		}

		Dwarf_Attribute attr;
		char* name = nullptr;
		if (dwarf_attr(cuDie, DW_AT_producer, &attr, &err) == DW_DLV_OK
				&& dwarf_formstring(attr, &name, &err) == DW_DLV_OK
				&& name)
		{
			std::string producer = name;
			parseGccProducer(producer)
					|| parseClangProducer(producer)
					|| parseTmsProducer(producer);
		}

		Dwarf_Unsigned language;
		if (dwarf_attr(cuDie, DW_AT_language, &attr, &err) == DW_DLV_OK
				&& dwarf_formudata(attr, &language, &err) == DW_DLV_OK)
		{
			if (getDwarfLanguageString(language, lang))
			{
				if (addUniqueValue(languages, lang, langIndex))
				{
					modulesCounter.push_back(1);
				}
				else
				{
					++modulesCounter[langIndex];
				}
			}
		}

		dwarf_dealloc(dbg, cuDie, DW_DLA_DIE);
	}

	dwarf_object_finish(dbg, &err);

	const auto noOfLanguages = modulesCounter.size();
	if (noOfLanguages == 1)
	{
		addLanguage(languages[0]);
	}
	else
	{
		for (std::size_t i = 0; i < noOfLanguages; ++i)
		{
			addLanguage(languages[i], numToStr(modulesCounter[i])
						+ " module" + (modulesCounter[i] > 1 ? "s" : ""));
		}
	}

	return;
}

/**
 * Get Embarcadero Delphi version
 * @return Delphi version
 */
std::string Heuristics::getEmbarcaderoVersion()
{
	// Get comment section name
	auto sectionName = commentSectionNameByFormat(fileParser.getFileFormat());

	std::string content;
	const Section* section = fileParser.getSection(sectionName);
	if (section && section->getString(content, 0, 0))
	{
		// Get offset to version in compiler ID string
		auto startOffset = content.find("Embarcadero Delphi ");
		if (startOffset != std::string::npos)
		{
			// Search for platform specific string
			std::string::size_type offset = startOffset + 19;
			for (const auto pair : delphiStrings)
			{
				offset = content.find(pair.first, startOffset);
				if (offset != std::string::npos)
				{
					offset = pair.second;
					break;
				}
			}

			// Search for compiler version in xx.x format
			if (offset != std::string::npos)
			{
				auto version = content.substr(startOffset + offset, 4);
				if (std::regex_match(version, std::regex("[[:digit:]]+.[[:digit:]]")))
				{
					return version;
				}
			}
		}
	}

	return std::string();
}

/**
 * Try to detect Embarcadero Delphi compiler
 */
void Heuristics::getEmbarcaderoHeuristics()
{
	auto source = DetectionMethod::COMMENT_H;
	auto strength = DetectionStrength::MEDIUM;

	// Try to check for version in comment section
	auto version = getEmbarcaderoVersion();
	auto extra = embarcaderoVersionToExtra(version);

	// Special function often exported by Delphi XE5 and higher
	if (fileParser.getExport("TMethodImplementationIntercept"))
	{
		if (!version.empty())
		{
			// Increase detection strength
			source = DetectionMethod::COMBINED;
			strength = DetectionStrength::HIGH;
		}
		else
		{
			source = DetectionMethod::EXPORT_TABLE_H;
			strength = DetectionStrength::MEDIUM;

			version = "26.0+";
			extra = "XE5 or higher";
		}
	}

	if (!version.empty())
	{
		addCompiler(source, strength, "Embarcadero Delphi", version, extra);
		addPriorityLanguage("Delphi");
	}
}

/**
 * Try to detect compilers by specific symbol names
 */
void Heuristics::getSymbolHeuristic()
{
	auto source = DetectionMethod::SYMBOL_TABLE_H;
	auto strength = DetectionStrength::HIGH;

	std::size_t goCount = 0;
	std::size_t ghcCount = 0;
	std::size_t rustCount = 0;

	for (const SymbolTable* symbolTable : fileParser.getSymbolTables())
	{
		for (auto it = symbolTable->begin(), e = symbolTable->end(); it < e; ++it)
		{
			ghcCount += isGhcSymbol(*it) ? 1 : 0;
			goCount += isGoFunction(*it) ? 1 : 0;
			rustCount += isRustFunction(*it) ? 1 : 0;

			if (goCount > MINIMUM_GO_FUNCTIONS)
			{
				addPriorityLanguage("Go");
				return;
			}

			if (ghcCount > MINIMUM_GHC_SYMBOLS)
			{
				addCompiler(source, strength, "GHC");
				addPriorityLanguage("Haskell");
				return;
			}

			if (rustCount > MINIMUM_RUST_FUNCTIONS)
			{
				addCompiler(source, strength, "rustc");
				addPriorityLanguage("Rust");
				return;
			}
		}
	}
}

/**
 * Try to detect tools
 */
void Heuristics::getCommonToolsHeuristics()
{
	getSymbolHeuristic();
	getEmbarcaderoHeuristics();
	getSectionHeuristics();
	getDwarfInfo();
	getCommentSectionsHeuristics();
}

/**
 * Try to detect original language
 */
void Heuristics::getCommonLanguageHeuristics()
{
}

/**
 * Check if compiler is already detected
 * @param name Name of compiler
 * @param minStrength Minimal strength of used method
 * @return pointer to detection if compiler is detected, @b nullptr otherwise
 */
const DetectResult* Heuristics::isDetected(
		const std::string &name, const DetectionStrength minStrength)
{
	for (const auto &detection : toolInfo.detectedTools)
	{
		if (startsWith(detection.name, name) && detection.strength >= minStrength)
		{
			return &detection;
		}
	}

	return nullptr;
}

/**
 * Try detect version of UPX packer
 * @return Detected version of UPX or empty string is version is not detected
 */
std::string Heuristics::getUpxVersion()
{
	if (fileParser.isElf() || fileParser.isMacho())
	{
		// format: $Id: UPX x.xx
		const std::string pattern = "$Id: UPX ";
		const auto &content = search.getPlainString();
		const auto pos = content.find(pattern);
		const std::size_t versionLen = 4;
		if (pos <= content.length() - pattern.length() - versionLen)
		{
			return content.substr(pos + pattern.length(), versionLen);
		}
	}

	return "";
}

/**
 * Get all compiler heuristics which are specific for one file format
 */
void Heuristics::getFormatSpecificCompilerHeuristics()
{
}

/**
 * Get all language heuristics which are specific for one file format
 */
void Heuristics::getFormatSpecificLanguageHeuristics()
{
}

/**
 * Try detect compiler based on all available heuristics
 */
void Heuristics::getAllHeuristics()
{
	// Detect languages
	getCommonLanguageHeuristics();
	getFormatSpecificLanguageHeuristics();

	// Detect compilers
	getCommonToolsHeuristics();
	getFormatSpecificCompilerHeuristics();
}

} // namespace cpdetect
} // namespace retdec
