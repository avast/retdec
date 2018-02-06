/**
 * @file src/cpdetect/compiler_detector/pe_compiler.cpp
 * @brief Methods of PeCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/cpdetect/compiler_detector/heuristics/pe_heuristics.h"
#include "retdec/cpdetect/compiler_detector/pe_compiler.h"
#include "retdec/cpdetect/settings.h"

using namespace retdec::fileformat;

namespace retdec {
namespace cpdetect {

/**
 * Constructor
 */
PeCompiler::PeCompiler(
		fileformat::PeFormat &parser, DetectParams &params, ToolInformation &tools)
	: CompilerDetector(parser, params, tools)
{
	heuristics = new PeHeuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;

	retdec::utils::FilesystemPath path(pathToShared);
	path.append(YARA_RULES_PATH + "pe/");
	auto bitWidth = parser.getWordLength();

	switch(targetArchitecture)
	{
		case Architecture::X86:
			path.append("x86.yarac");
			break;

		case Architecture::X86_64:
			path.append("x64.yarac");
			break;

		case Architecture::ARM:
			if (bitWidth == 32)
			{
				path.append("arm.yarac");
			}
			else
			{
				// There are no 64-bit ARM signatures for now.
			}
			break;

		default:
			break;
	}

	if (path.isFile())
	{
		internalPaths.emplace_back(path.getPath());
	}
}

} // namespace cpdetect
} // namespace retdec
