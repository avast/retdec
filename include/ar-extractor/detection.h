/**
 * @file include/ar-extractor/detection.h
 * @brief Detection methods.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef AR_EXTRACTOR_DETECTION_H
#define AR_EXTRACTOR_DETECTION_H

#include <string>

namespace ar_extractor {

bool isArchive(const std::string &path);

bool isThinArchive(const std::string &path);

bool isNormalArchive(const std::string &path);

bool isFatMachOArchive(const std::string &path);

} // namespace ar_extractor

#endif
