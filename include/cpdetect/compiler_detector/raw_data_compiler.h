/**
 * @file include/cpdetec/compiler_detector/raw_data_compiler.h
 * @brief Definition of RawDataCompiler class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_DETECTOR_RAW_DATA_COMPILER_H
#define CPDETECT_COMPILER_DETECTOR_RAW_DATA_COMPILER_H

#include "cpdetect/compiler_detector/compiler_detector.h"
#include "fileformat/file_format/raw_data/raw_data_format.h"

namespace cpdetect {

/**
 * RawDataCompiler - class for detect compiler of raw data binary file
 */
class RawDataCompiler : public CompilerDetector
{
	public:
		RawDataCompiler(fileformat::RawDataFormat &parser, DetectParams &params, ToolInformation &tools);
};

} // namespace cpdetect

#endif
