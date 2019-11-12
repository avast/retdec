/**
 * @file include/retdec/serdes/storage.h
 * @brief Storage (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_STORAGE_H
#define RETDEC_SERDES_STORAGE_H

#include <json/json.h>

namespace retdec {

namespace common {
class Storage;
} // namespace common

namespace serdes {

Json::Value serialize(const common::Storage& s);
void deserialize(const Json::Value& val, common::Storage& s);

} // namespace serdes
} // namespace retdec

#endif