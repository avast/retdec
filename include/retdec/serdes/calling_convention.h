/**
 * @file include/retdec/serdes/calling_convention.h
 * @brief Calling convention (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_CALLING_CONVENTION_H
#define RETDEC_SERDES_CALLING_CONVENTION_H

#include <json/json.h>

namespace retdec {

namespace common {
class CallingConvention;
} // namespace common

namespace serdes {

Json::Value serialize(const common::CallingConvention& cc);
void deserialize(const Json::Value& val, common::CallingConvention& cc);

} // namespace serdes
} // namespace retdec

#endif