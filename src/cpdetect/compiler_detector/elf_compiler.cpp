/**
 * @file src/cpdetect/compiler_detector/elf_compiler.cpp
 * @brief Methods of ElfCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/cpdetect/compiler_detector/elf_compiler.h"
#include "retdec/cpdetect/compiler_detector/heuristics/elf_heuristics.h"
#include "retdec/cpdetect/settings.h"

using namespace retdec::fileformat;

namespace retdec {
namespace cpdetect {

/**
 * Constructor
 */
ElfCompiler::ElfCompiler(
		fileformat::ElfFormat &parser, DetectParams &params, ToolInformation &tools)
	: CompilerDetector(parser, params, tools)
{
	heuristics = new ElfHeuristics(parser, *search, toolInfo);
	externalSuffixes = EXTERNAL_DATABASE_SUFFIXES;

	retdec::utils::FilesystemPath path(pathToShared);
	path.append(YARA_RULES_PATH + "elf/");
	auto bitWidth = parser.getWordLength();

	switch(targetArchitecture)
	{
		case Architecture::X86:
			path.append("x86");
			break;

		case Architecture::X86_64:
			path.append("x64");
			break;

		case Architecture::ARM:
			if (bitWidth == 32) {
				path.append("arm");
			}
			else {
				path.append("arm64");
			}
			break;

		case Architecture::MIPS:
			if (bitWidth == 32) {
				path.append("mips");
			}
			else {
				path.append("mips64");
			}
			break;

		case Architecture::POWERPC:
			if (bitWidth == 32) {
				path.append("ppc");
			}
			else {
				path.append("ppc64");
			}
			break;

		default:
			break;
	}

	populateInternalPaths(path);
}

} // namespace cpdetect
} // namespace retdec
