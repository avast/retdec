/**
 * @file include/cpdetec/compiler_detector/pe_compiler.h
 * @brief Definition of PeCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_DETECTOR_PE_COMPILER_H
#define CPDETECT_COMPILER_DETECTOR_PE_COMPILER_H

#include "cpdetect/compiler_detector/compiler_detector.h"
#include "fileformat/file_format/pe/pe_format.h"

namespace cpdetect {

/**
 * PeCompiler - class for detect compiler of PE binary file
 */
class PeCompiler : public CompilerDetector
{
	public:
		PeCompiler(fileformat::PeFormat &parser, DetectParams &params, ToolInformation &tools);
};

} // namespace cpdetect

#endif
