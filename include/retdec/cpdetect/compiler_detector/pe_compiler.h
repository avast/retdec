/**
 * @file include/retdec/cpdetect/compiler_detector/pe_compiler.h
 * @brief Definition of PeCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_COMPILER_DETECTOR_PE_COMPILER_H
#define RETDEC_CPDETECT_COMPILER_DETECTOR_PE_COMPILER_H

#include "retdec/cpdetect/compiler_detector/compiler_detector.h"
#include "retdec/fileformat/file_format/pe/pe_format.h"

namespace retdec {
namespace cpdetect {

/**
 * PeCompiler - class for detect compiler of PE binary file
 */
class PeCompiler : public CompilerDetector
{
	public:
		PeCompiler(retdec::fileformat::PeFormat &parser, DetectParams &params, ToolInformation &tools);
};

} // namespace cpdetect
} // namespace retdec

#endif
