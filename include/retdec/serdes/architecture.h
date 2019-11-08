/**
 * @file include/retdec/serdes/architecture.h
 * @brief Architecture (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_ARCHITECTURE_H
#define RETDEC_SERDES_ARCHITECTURE_H

#include <json/json.h>

namespace retdec {

namespace common {
class Architecture;
} // namespace common

namespace serdes {

Json::Value serialize(const common::Architecture& a);
void deserialize(const Json::Value& val, common::Architecture& a);

} // namespace serdes
} // namespace retdec

#endif