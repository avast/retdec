/**
 * @file include/retdec/cpdetect/compiler_detector/macho_compiler.h
 * @brief Definition of MachOCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_COMPILER_DETECTOR_MACHO_COMPILER_H
#define RETDEC_CPDETECT_COMPILER_DETECTOR_MACHO_COMPILER_H

#include "retdec/cpdetect/compiler_detector/compiler_detector.h"
#include "retdec/fileformat/file_format/macho/macho_format.h"

namespace retdec {
namespace cpdetect {

/**
 * MachOCompiler - class for detect compiler of Mach-O binary file
 */
class MachOCompiler : public CompilerDetector
{
	public:
		MachOCompiler(retdec::fileformat::MachOFormat &parser, DetectParams &params, ToolInformation &tools);
};

} // namespace cpdetect
} // namespace retdec

#endif
