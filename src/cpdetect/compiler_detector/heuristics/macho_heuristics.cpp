/**
 * @file src/cpdetect/compiler_detector/heuristics/macho_heuristics.cpp
 * @brief Methods of MachOHeuristics class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/cpdetect/compiler_detector/heuristics/macho_heuristics.h"

using namespace retdec::fileformat;

namespace retdec {
namespace cpdetect {

/**
 * Constructor
 * @param parser Parser of input file
 * @param searcher Signature search engine
 * @param toolInfo Structure for information about detected tools
 */
MachOHeuristics::MachOHeuristics(
		MachOFormat &parser, Search &searcher, ToolInformation &toolInfo)
	: Heuristics(parser, searcher, toolInfo)
{

}

/**
 * Destructor
 */
MachOHeuristics::~MachOHeuristics()
{

}

/**
 * Try to detect UPX
 */
void MachOHeuristics::getUpxHeuristic()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	if (search.hasString("UPX!", 0, 0x400))
	{
		addPacker(source, strength, "UPX", getUpxVersion());
	}
}

/**
 * Try to detect Go compiler
 */
void MachOHeuristics::getGoHeuristic()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	const Section* section = fileParser.getSection("__debug_info");
	if (!section)
	{
		return;
	}

	std::string content;
	if (section->getString(content))
	{
		const auto offset = content.find("Go cmd/compile go");
		if (offset != std::string::npos)
		{
			const auto start = offset + 17;
			const auto end = content.find_first_of('\0', offset);

			std::string version = content.substr(start, end - start);
			if (!version.empty())
			{
				addCompiler(source, strength, "gc", version);
				addLanguage("Go");
			}
		}
	}
}

/**
 * Try to detect tools by section table
 */
void MachOHeuristics::getSectionTableHeuristic()
{
	auto source = DetectionMethod::SECTION_TABLE_H;
	auto strength = DetectionStrength::MEDIUM;

	if (findSectionNameStart("__swift"))
	{
		addCompiler(source, strength, "swiftc");
		addLanguage("Swift");
	}

	if (findSectionName("__gosymtab") || findSectionName("__gopclntab"))
	{
		addCompiler(source, strength, "gc");
		addLanguage("Go");
	}

	if (findSectionName("__dof_HaskellEv"))
	{
		addCompiler(source, strength, "GHC");
		addLanguage("Haskell");
	}
}

/**
 * Try to detect tools by import table
 */
void MachOHeuristics::getImportTableHeuristic()
{
	auto source = DetectionMethod::IMPORT_TABLE_H;
	auto strength = DetectionStrength::MEDIUM;

	const auto* imports = fileParser.getImportTable();
	if (!imports)
	{
		return;
	}

	if (imports->hasLibraryCaseInsensitive("libswiftCore"))
	{
		addCompiler(source, strength, "swiftc");
		addLanguage("Swift");
	}
}

void MachOHeuristics::getFormatSpecificCompilerHeuristics()
{
	getUpxHeuristic();
	getGoHeuristic();
	getImportTableHeuristic();
	getSectionTableHeuristic();
}

} // namespace cpdetect
} // namespace retdec
