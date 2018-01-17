/**
 * @file src/cpdetect/compiler_detector/intel_hex_compiler.cpp
 * @brief Methods of IntelHexCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/cpdetect/compiler_detector/heuristics/heuristics.h"
#include "retdec/cpdetect/compiler_detector/intel_hex_compiler.h"
#include "retdec/cpdetect/settings.h"

namespace retdec {
namespace cpdetect {

/**
 * Constructor
 */
IntelHexCompiler::IntelHexCompiler(
		fileformat::IntelHexFormat &parser, DetectParams &params, ToolInformation &tools)
	: CompilerDetector(parser, params, tools)
{
	heuristics = new Heuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;

	/// @todo We should probably use same aproach as in raw data decompilation.
}

} // namespace cpdetect
} // namespace retdec
