/**
 * @file src/cpdetect/compiler_detector/raw_data_compiler.cpp
 * @brief Methods of RawDataCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/cpdetect/compiler_detector/heuristics/heuristics.h"
#include "retdec/cpdetect/compiler_detector/raw_data_compiler.h"
#include "retdec/cpdetect/settings.h"

using namespace retdec::fileformat;

namespace retdec {
namespace cpdetect {

/**
 * Constructor
 */
RawDataCompiler::RawDataCompiler(
		fileformat::RawDataFormat &parser, DetectParams &params, ToolInformation &tools)
	: CompilerDetector(parser, params, tools)
{
	heuristics = new Heuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;

	retdec::utils::FilesystemPath pathPe(pathToShared);
	pathPe.append(YARA_RULES_PATH + "pe/");
	retdec::utils::FilesystemPath pathElf(pathToShared);
	pathElf.append(YARA_RULES_PATH + "elf/");
	retdec::utils::FilesystemPath pathMacho(pathToShared);
	pathMacho.append(YARA_RULES_PATH + "macho/");
	auto bitWidth = parser.getWordLength();

	switch(targetArchitecture)
	{
		case Architecture::X86:
			pathPe.append("x86.yarac");
			pathElf.append("x86.yarac");
			pathMacho.append("x86.yarac");
			break;

		case Architecture::X86_64:
			pathPe.append("x64.yarac");
			pathElf.append("x64.yarac");
			pathMacho.append("x64.yarac");
			break;

		case Architecture::ARM:
			if (bitWidth == 32)
			{
				pathPe.append("arm.yarac");
				pathElf.append("arm.yarac");
				pathMacho.append("arm.yarac");
			}
			else
			{
				pathElf.append("arm64.yarac");
			}
			break;

		case Architecture::POWERPC:
			if (bitWidth == 32)
			{
				pathElf.append("ppc.yarac");
				pathMacho.append("ppc.yarac");
			}
			else
			{
				pathElf.append("ppc64.yarac");
				pathMacho.append("ppc64.yarac");
			}
			break;

		case Architecture::MIPS:
			if (bitWidth == 32)
			{
				pathElf.append("mips.yarac");
			}
			else
			{
				pathElf.append("mips64.yarac");
			}
			break;

		default:
			break;
	}

	if (pathPe.isFile())
	{
		internalPaths.emplace_back(pathPe.getPath());
	}
	if (pathElf.isFile())
	{
		internalPaths.emplace_back(pathElf.getPath());
	}
	if (pathMacho.isFile())
	{
		internalPaths.emplace_back(pathMacho.getPath());
	}
}

} // namespace cpdetect
} // namespace retdec

