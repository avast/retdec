/**
 * @file include/cpdetec/compiler_detector/coff_compiler.h
 * @brief Definition of CoffCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_DETECTOR_COFF_COMPILER_H
#define CPDETECT_COMPILER_DETECTOR_COFF_COMPILER_H

#include "cpdetect/compiler_detector/compiler_detector.h"
#include "fileformat/file_format/coff/coff_format.h"

namespace cpdetect {

/**
 * CoffCompiler - class for detect compiler of COFF binary file
 */
class CoffCompiler : public CompilerDetector
{
	public:
		CoffCompiler(fileformat::CoffFormat &parser, DetectParams &params, ToolInformation &tools);
};

} // namespace cpdetect

#endif
