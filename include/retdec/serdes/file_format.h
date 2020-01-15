/**
 * @file include/retdec/serdes/file_format.h
 * @brief File format (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_FILE_FORMAT_H
#define RETDEC_SERDES_FILE_FORMAT_H

#include <rapidjson/document.h>

namespace retdec {

namespace common {
class FileFormat;
} // namespace common

namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::FileFormat& ff);
void deserialize(const rapidjson::Value& val, common::FileFormat& ff);

} // namespace serdes
} // namespace retdec

#endif