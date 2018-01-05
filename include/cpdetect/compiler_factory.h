/**
 * @file include/cpdetec/compiler_factory.h
 * @brief Factory for creating compiler detectors.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_FACTORY_H
#define CPDETECT_COMPILER_FACTORY_H

#include <memory>

#include "cpdetect/compiler_detector/compiler_detector.h"

namespace cpdetect {

std::unique_ptr<CompilerDetector> createCompilerDetector(fileformat::FileFormat &parser,
		DetectParams &params, ToolInformation &toolInfo);

} // namespace cpdetect

#endif
