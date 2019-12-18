/**
 * @file include/retdec/serdes/type.h
 * @brief Data type (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_TYPE_H
#define RETDEC_SERDES_TYPE_H

#include <json/json.h>

namespace retdec {

namespace common {
class Type;
} // namespace common

namespace serdes {

Json::Value serialize(const common::Type& t);
void deserialize(const Json::Value& val, common::Type& t);

} // namespace serdes
} // namespace retdec

#endif