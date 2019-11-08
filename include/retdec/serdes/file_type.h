/**
 * @file include/retdec/serdes/file_type.h
 * @brief File type (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_FILE_TYPE_H
#define RETDEC_SERDES_FILE_TYPE_H

#include <json/json.h>

namespace retdec {

namespace common {
class FileType;
} // namespace common

namespace serdes {

Json::Value serialize(const common::FileType& ft);
void deserialize(const Json::Value& val, common::FileType& ft);

} // namespace serdes
} // namespace retdec

#endif