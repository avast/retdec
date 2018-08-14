/**
 * @file include/retdec/cpdetect/compiler_detector/elf_compiler.h
 * @brief Definition of ElfCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_COMPILER_DETECTOR_ELF_COMPILER_H
#define RETDEC_CPDETECT_COMPILER_DETECTOR_ELF_COMPILER_H

#include "retdec/cpdetect/compiler_detector/compiler_detector.h"
#include "retdec/fileformat/file_format/elf/elf_format.h"

namespace retdec {
namespace cpdetect {

/**
 * ElfCompiler - class for detect compiler of ELF binary file
 */
class ElfCompiler : public CompilerDetector
{
	public:
		ElfCompiler(retdec::fileformat::ElfFormat &parser, DetectParams &params, ToolInformation &tools);
};

} // namespace cpdetect
} // namespace retdec

#endif
