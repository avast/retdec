/**
 * @file src/cpdetect/compiler_detector/raw_data_compiler.cpp
 * @brief Methods of RawDataCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/cpdetect/compiler_detector/heuristics/heuristics.h"
#include "retdec/cpdetect/compiler_detector/raw_data_compiler.h"
#include "retdec/cpdetect/settings.h"
#include "retdec/cpdetect/signatures/yara/database/database.h"

using namespace retdec::fileformat;

namespace retdec {
namespace cpdetect {

/**
 * Constructor
 */
RawDataCompiler::RawDataCompiler(retdec::fileformat::RawDataFormat &parser, DetectParams &params, ToolInformation &tools) : CompilerDetector(parser, params, tools)
{
	heuristics = new Heuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;
	switch(targetArchitecture)
	{
		case Architecture::X86:
		case Architecture::X86_64:
			internalDatabase = getX86Database();
			break;
		case Architecture::ARM:
			internalDatabase = getArmDatabase();
			break;
		case Architecture::POWERPC:
			internalDatabase = getPowerPcDatabase();
			break;
		case Architecture::MIPS:
			internalDatabase = getMipsDatabase();
			break;
		default:
			internalDatabase = nullptr;
	}
}

} // namespace cpdetect
} // namespace retdec
