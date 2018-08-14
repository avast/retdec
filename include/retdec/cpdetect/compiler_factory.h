/**
 * @file include/retdec/cpdetect/compiler_factory.h
 * @brief Factory for creating compiler detectors.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_COMPILER_FACTORY_H
#define RETDEC_CPDETECT_COMPILER_FACTORY_H

#include <memory>

#include "retdec/cpdetect/compiler_detector/compiler_detector.h"

namespace retdec {
namespace cpdetect {

std::unique_ptr<CompilerDetector> createCompilerDetector(
        retdec::fileformat::FileFormat &parser, DetectParams &params, ToolInformation &toolInfo);

} // namespace cpdetect
} // namespace retdec

#endif
