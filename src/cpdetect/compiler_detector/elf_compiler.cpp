/**
 * @file src/cpdetect/compiler_detector/elf_compiler.cpp
 * @brief Methods of ElfCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/cpdetect/compiler_detector/elf_compiler.h"
#include "retdec/cpdetect/compiler_detector/heuristics/elf_heuristics.h"
#include "retdec/cpdetect/settings.h"
#include "retdec/cpdetect/signatures/yara/database/database.h"

using namespace fileformat;

namespace cpdetect {

/**
 * Constructor
 */
ElfCompiler::ElfCompiler(fileformat::ElfFormat &parser, DetectParams &params, ToolInformation &tools) : CompilerDetector(parser, params, tools)
{
	heuristics = new ElfHeuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;
	switch(targetArchitecture)
	{
		case Architecture::X86:
		case Architecture::X86_64:
			internalDatabase = getX86ElfDatabase();
			break;
		case Architecture::ARM:
			internalDatabase = getArmElfDatabase();
			break;
		case Architecture::POWERPC:
			internalDatabase = getPowerPcElfDatabase();
			break;
		case Architecture::MIPS:
			internalDatabase = getMipsElfDatabase();
			break;
		default:
			internalDatabase = nullptr;
	}
}

} // namespace cpdetect
