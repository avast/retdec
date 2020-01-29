/**
 * @file include/retdec/serdes/type.h
 * @brief Data type (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_TYPE_H
#define RETDEC_SERDES_TYPE_H

#include <rapidjson/document.h>

namespace retdec {

namespace common {
class Type;
} // namespace common

namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::Type& t);
void deserialize(const rapidjson::Value& val, common::Type& t);

} // namespace serdes
} // namespace retdec

#endif