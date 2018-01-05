/**
 * @file include/fileformat/utils/other.h
 * @brief Simple utilities.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_UTILS_OTHER_H
#define FILEFORMAT_UTILS_OTHER_H

#include <string>
#include <vector>

#include "fileformat/fftypes.h"

namespace fileformat {

std::size_t getRealSizeInRegion(std::size_t offset, std::size_t requestedSize, std::size_t regionSize);
std::string getFileFormatNameFromEnum(Format format);
std::vector<std::string> getSupportedFileFormats();
std::vector<std::string> getSupportedArchitectures();

} // namespace fileformat

#endif
