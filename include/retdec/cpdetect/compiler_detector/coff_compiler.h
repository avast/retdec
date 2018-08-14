/**
 * @file include/retdec/cpdetect/compiler_detector/coff_compiler.h
 * @brief Definition of CoffCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_COMPILER_DETECTOR_COFF_COMPILER_H
#define RETDEC_CPDETECT_COMPILER_DETECTOR_COFF_COMPILER_H

#include "retdec/cpdetect/compiler_detector/compiler_detector.h"
#include "retdec/fileformat/file_format/coff/coff_format.h"

namespace retdec {
namespace cpdetect {

/**
 * CoffCompiler - class for detect compiler of COFF binary file
 */
class CoffCompiler : public CompilerDetector
{
	public:
		CoffCompiler(retdec::fileformat::CoffFormat &parser, DetectParams &params, ToolInformation &tools);
};

} // namespace cpdetect
} // namespace retdec

#endif
