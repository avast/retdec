/**
 * @file include/fileformat/utils/format_detection.h
 * @brief File format detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_UTILS_FORMAT_DETECTION_H
#define FILEFORMAT_UTILS_FORMAT_DETECTION_H

#include "retdec-config/config.h"
#include "fileformat/fftypes.h"

namespace fileformat {

Format detectFileFormat(const std::string &filePath, retdec_config::Config *config = nullptr);

} // namespace fileformat

#endif
