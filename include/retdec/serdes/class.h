/**
 * @file include/retdec/serdes/class.h
 * @brief Class (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_CLASS_H
#define RETDEC_SERDES_CLASS_H

#include <json/json.h>

namespace retdec {

namespace common {
class Class;
} // namespace common

namespace serdes {

Json::Value serialize(const common::Class& c);
void deserialize(const Json::Value& val, common::Class& c);

} // namespace serdes
} // namespace retdec

#endif