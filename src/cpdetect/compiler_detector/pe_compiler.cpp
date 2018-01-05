/**
 * @file src/cpdetect/compiler_detector/pe_compiler.cpp
 * @brief Methods of PeCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "cpdetect/compiler_detector/heuristics/pe_heuristics.h"
#include "cpdetect/compiler_detector/pe_compiler.h"
#include "cpdetect/settings.h"
#include "cpdetect/signatures/yara/database/database.h"

using namespace fileformat;

namespace cpdetect {

/**
 * Constructor
 */
PeCompiler::PeCompiler(fileformat::PeFormat &parser, DetectParams &params, ToolInformation &tools) : CompilerDetector(parser, params, tools)
{
	heuristics = new PeHeuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;
	switch(targetArchitecture)
	{
		case Architecture::X86:
		case Architecture::X86_64:
			internalDatabase = getX86PeDatabase();
			break;
		case Architecture::ARM:
			internalDatabase = getArmPeDatabase();
			break;
		case Architecture::POWERPC:
			internalDatabase = getPowerPcPeDatabase();
			break;
		case Architecture::MIPS:
			internalDatabase = getMipsPeDatabase();
			break;
		default:
			internalDatabase = nullptr;
	}
}

} // namespace cpdetect
