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
			pathPe.append("x86");
			pathElf.append("x86c");
			pathMacho.append("x86");
			break;

		case Architecture::X86_64:
			pathPe.append("x64");
			pathElf.append("x64");
			pathMacho.append("x64");
			break;

		case Architecture::ARM:
			if (bitWidth == 32)
			{
				pathPe.append("arm");
				pathElf.append("arm");
				pathMacho.append("arm");
			}
			else
			{
				pathElf.append("arm64");
			}
			break;

		case Architecture::POWERPC:
			if (bitWidth == 32)
			{
				pathElf.append("ppc");
				pathMacho.append("ppc");
			}
			else
			{
				pathElf.append("ppc64");
				pathMacho.append("ppc64");
			}
			break;

		case Architecture::MIPS:
			if (bitWidth == 32)
			{
				pathElf.append("mips");
			}
			else
			{
				pathElf.append("mips64");
			}
			break;

		default:
			break;
	}

	populateInternalPaths(pathPe);
	populateInternalPaths(pathElf);
	populateInternalPaths(pathMacho);
}

} // namespace cpdetect
} // namespace retdec
