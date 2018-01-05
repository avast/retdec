/**
 * @file include/retdec/fileformat/utils/format_detection.h
 * @brief File format detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_UTILS_FORMAT_DETECTION_H
#define RETDEC_FILEFORMAT_UTILS_FORMAT_DETECTION_H

#include "retdec/config/config.h"
#include "retdec/fileformat/fftypes.h"

namespace retdec {
namespace fileformat {

Format detectFileFormat(const std::string &filePath, retdec::config::Config *config = nullptr);

} // namespace fileformat
} // namespace retdec

#endif
