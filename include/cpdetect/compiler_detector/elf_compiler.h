/**
 * @file include/cpdetec/compiler_detector/elf_compiler.h
 * @brief Definition of ElfCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_DETECTOR_ELF_COMPILER_H
#define CPDETECT_COMPILER_DETECTOR_ELF_COMPILER_H

#include "cpdetect/compiler_detector/compiler_detector.h"
#include "fileformat/file_format/elf/elf_format.h"

namespace cpdetect {

/**
 * ElfCompiler - class for detect compiler of ELF binary file
 */
class ElfCompiler : public CompilerDetector
{
	public:
		ElfCompiler(fileformat::ElfFormat &parser, DetectParams &params, ToolInformation &tools);
};

} // namespace cpdetect

#endif
