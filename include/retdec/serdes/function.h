/**
 * @file include/retdec/serdes/function.h
 * @brief Function (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_FUNCTION_H
#define RETDEC_SERDES_FUNCTION_H

#include <json/json.h>

namespace retdec {

namespace common {
class Function;
} // namespace common

namespace serdes {

Json::Value serialize(const common::Function& f);
void deserialize(const Json::Value& val, common::Function& f);

} // namespace serdes
} // namespace retdec

#endif