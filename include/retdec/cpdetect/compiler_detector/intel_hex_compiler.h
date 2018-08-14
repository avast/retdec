/**
 * @file include/retdec/cpdetect/compiler_detector/intel_hex_compiler.h
 * @brief Definition of IntelHexCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_COMPILER_DETECTOR_INTEL_HEX_COMPILER_H
#define RETDEC_CPDETECT_COMPILER_DETECTOR_INTEL_HEX_COMPILER_H

#include "retdec/cpdetect/compiler_detector/compiler_detector.h"
#include "retdec/fileformat/file_format/intel_hex/intel_hex_format.h"

namespace retdec {
namespace cpdetect {

/**
 * IntelHexCompiler - class for detect compiler of Intel HEX binary file
 */
class IntelHexCompiler : public CompilerDetector
{
	public:
		IntelHexCompiler(retdec::fileformat::IntelHexFormat &parser, DetectParams &params, ToolInformation &tools);
};

} // namespace cpdetect
} // namespace retdec

#endif
