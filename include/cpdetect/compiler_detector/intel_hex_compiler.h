/**
 * @file include/cpdetec/compiler_detector/intel_hex_compiler.h
 * @brief Definition of IntelHexCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_DETECTOR_INTEL_HEX_COMPILER_H
#define CPDETECT_COMPILER_DETECTOR_INTEL_HEX_COMPILER_H

#include "cpdetect/compiler_detector/compiler_detector.h"
#include "fileformat/file_format/intel_hex/intel_hex_format.h"

namespace cpdetect {

/**
 * IntelHexCompiler - class for detect compiler of Intel HEX binary file
 */
class IntelHexCompiler : public CompilerDetector
{
	public:
		IntelHexCompiler(fileformat::IntelHexFormat &parser, DetectParams &params, ToolInformation &tools);
};

} // namespace cpdetect

#endif
