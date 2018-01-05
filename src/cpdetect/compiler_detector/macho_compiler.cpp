/**
 * @file src/cpdetect/compiler_detector/macho_compiler.cpp
 * @brief Methods of MachOCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "cpdetect/compiler_detector/heuristics/macho_heuristics.h"
#include "cpdetect/compiler_detector/macho_compiler.h"
#include "cpdetect/settings.h"
#include "cpdetect/signatures/yara/database/database.h"

using namespace fileformat;

namespace cpdetect {

/**
 * Constructor
 */
MachOCompiler::MachOCompiler(fileformat::MachOFormat &parser, DetectParams &params, ToolInformation &tools) : CompilerDetector(parser, params, tools)
{
	heuristics = new MachOHeuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;
	if(parser.isFatBinary())
	{
		internalDatabase = getFatMachoDatabase();
		return;
	}
	switch(targetArchitecture)
	{
		case Architecture::X86:
		case Architecture::X86_64:
			internalDatabase = getX86MachODatabase();
			break;
		case Architecture::ARM:
			internalDatabase = getArmMachODatabase();
			break;
		case Architecture::POWERPC:
			internalDatabase = getPowerPcMachODatabase();
			break;
		case Architecture::MIPS:
			internalDatabase = getMipsMachODatabase();
			break;
		default:
			internalDatabase = nullptr;
	}
}

} // namespace cpdetect
