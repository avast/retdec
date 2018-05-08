/**
 * @file src/cpdetect/compiler_detector/heuristics/elf_heuristics.cpp
 * @brief Methods of ElfHeuristics class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <map>
#include <set>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/cpdetect/compiler_detector/heuristics/elf_heuristics.h"
#include "retdec/fileformat/utils/file_io.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace
{

const std::map<std::string, std::set<std::string>> dynamicLanguagesMap =
{
	{"libgo.so", {"Go"}},
	{"libsupc++.so", {"C++"}},
	{"libstdc++.so", {"C++"}},
	{"libmpi.so", {"Open MPI"}},
	{"libmpi_mt.so", {"Open MPI (thread safe)"}},
	{"libmpi_cxx.so", {"Open MPI", "C++"}},
	{"libgfortran.so", {"Fortran"}}
};

} // anonymous namespace

namespace retdec {
namespace cpdetect {

/**
 * Constructor
 * @param parser Parser of input file
 * @param searcher Signature search engine
 * @param toolInfo Structure for information about detected tools
 */
ElfHeuristics::ElfHeuristics(
		ElfFormat &parser, Search &searcher, ToolInformation &toolInfo)
	: Heuristics(parser, searcher, toolInfo), elfParser(parser)
{

}

/**
 * Destructor
 */
ElfHeuristics::~ElfHeuristics()
{

}

/**
 * Try to detect UPX
 */
void ElfHeuristics::getUpxHeuristics()
{
	auto source = DetectionMethod::STRING_SEARCH_H;
	auto strength = DetectionStrength::MEDIUM;

	const auto fileLen = fileParser.getLoadedFileLength();
	if (search.hasString("UPX!", 0, 0xFF)
			|| search.hasString("UPX!", fileLen - 0x40, fileLen - 1))
	{
		addPacker(source, strength, "UPX", getUpxVersion());
	}
}

/**
 * Try to detect tools from note section
 */
void ElfHeuristics::getNoteHeuristics()
{
	auto source = DetectionMethod::NOTE_H;
	auto strength = DetectionStrength::MEDIUM;

	for (const auto& noteSecSeg : elfParser.getElfNoteSecSegs())
	{
		if (noteSecSeg.isMalformed())
		{
			continue;
		}

		for (const auto& note : noteSecSeg.getNotes())
		{
			if (note.name == "GNU" && note.type == 0x004)
			{
				std::string res;
				elfParser.getString(res, note.dataOffset, note.dataLength);

				if (startsWith(res, "gold"))
				{
					const auto pos = res.find(' ');
					addLinker(source, strength, "gold", res.substr(pos + 1));
				}
			}

			if (note.name == "HP" && note.type == 0x001)
			{
				addCompiler(source, strength, "HP C++");
				addLanguage("C++");
			}
		}
	}
}

/**
 * Try to detect Borland Kylix
 */
void ElfHeuristics::getBorlandKylixHeuristics()
{
	auto source = DetectionMethod::SECTION_TABLE_H;
	auto strength = DetectionStrength::MEDIUM;

	if (findSectionName("borland.ressym") == 1
			|| findSectionName("borland.reshash") == 1
			|| findSectionName("borland.resdata") == 1
			|| findSectionName("borland.resspare") == 1)
	{
		addCompiler(source, strength, "Borland Kylix");
	}
}

/**
 * Try to detect used languages from dynamic records
 */
void ElfHeuristics::getDynamicEntriesHeuristics()
{
	auto source = DetectionMethod::DYNAMIC_ENTRIES_H;
	auto strength = DetectionStrength::MEDIUM;

	for (const auto *table : elfParser.getDynamicTables())
	{
		if (!table)
		{
			continue;
		}

		for (const auto &record : *table)
		{
			if (record.getType() != DT_NEEDED)
			{
				continue;
			}

			const auto desc = record.getDescription();
			for (const auto &item : dynamicLanguagesMap)
			{
				if (!startsWith(desc, item.first))
				{
					continue;
				}

				if (item.first == "libgo.so")
				{
					addCompiler(source, strength, "gccgo");
				}

				for (const auto &language : item.second)
				{
					addLanguage(language);
				}
			}
		} // records loop
	} // dynamic tables loop
}

void ElfHeuristics::getFormatSpecificCompilerHeuristics()
{
	getUpxHeuristics();
	getNoteHeuristics();
	getBorlandKylixHeuristics();
	getDynamicEntriesHeuristics();
}

} // namespace cpdetect
} // namespace retdec
