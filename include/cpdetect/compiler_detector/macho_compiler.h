/**
 * @file include/cpdetec/compiler_detector/macho_compiler.h
 * @brief Definition of MachOCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_DETECTOR_MACHO_COMPILER_H
#define CPDETECT_COMPILER_DETECTOR_MACHO_COMPILER_H

#include "cpdetect/compiler_detector/compiler_detector.h"
#include "fileformat/file_format/macho/macho_format.h"

namespace cpdetect {

/**
 * MachOCompiler - class for detect compiler of Mach-O binary file
 */
class MachOCompiler : public CompilerDetector
{
	public:
		MachOCompiler(fileformat::MachOFormat &parser, DetectParams &params, ToolInformation &tools);
};

} // namespace cpdetect

#endif
