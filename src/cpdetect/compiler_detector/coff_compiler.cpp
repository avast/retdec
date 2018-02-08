/**
 * @file src/cpdetect/compiler_detector/coff_compiler.cpp
 * @brief Methods of CoffCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/cpdetect/compiler_detector/coff_compiler.h"
#include "retdec/cpdetect/compiler_detector/heuristics/heuristics.h"
#include "retdec/cpdetect/settings.h"

namespace retdec {
namespace cpdetect {

/**
 * Constructor
 */
CoffCompiler::CoffCompiler(
		retdec::fileformat::CoffFormat &parser, DetectParams &params, ToolInformation &tools)
	: CompilerDetector(parser, params, tools)
{
	heuristics = new Heuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;
}

} // namespace cpdetect
} // namespace retdec
