/**
 * @file src/cpdetect/compiler_detector/intel_hex_compiler.cpp
 * @brief Methods of IntelHexCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "cpdetect/compiler_detector/heuristics/heuristics.h"
#include "cpdetect/compiler_detector/intel_hex_compiler.h"
#include "cpdetect/settings.h"

namespace cpdetect {

/**
 * Constructor
 */
IntelHexCompiler::IntelHexCompiler(fileformat::IntelHexFormat &parser, DetectParams &params, ToolInformation &tools) : CompilerDetector(parser, params, tools)
{
	heuristics = new Heuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;
	internalDatabase = nullptr;
}

} // namespace cpdetect
