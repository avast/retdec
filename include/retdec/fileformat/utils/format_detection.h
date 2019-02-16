/**
 * @file include/retdec/fileformat/utils/format_detection.h
 * @brief File format detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_UTILS_FORMAT_DETECTION_H
#define RETDEC_FILEFORMAT_UTILS_FORMAT_DETECTION_H

#include "retdec/fileformat/fftypes.h"

namespace retdec {
namespace fileformat {

Format detectFileFormat(
		const std::string& filePath,
		bool isRaw = false);

Format detectFileFormat(
		std::istream &inputStream,
		bool isRaw = false);

Format detectFileFormat(
		const std::uint8_t* data,
		std::size_t size,
		bool isRaw = false);

} // namespace fileformat
} // namespace retdec

#endif
