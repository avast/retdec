/**
 * @file include/retdec/serdes/calling_convention.h
 * @brief Calling convention (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_CALLING_CONVENTION_H
#define RETDEC_SERDES_CALLING_CONVENTION_H

#include <rapidjson/document.h>

namespace retdec {

namespace common {
class CallingConvention;
} // namespace common

namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::CallingConvention& cc);
void deserialize(const rapidjson::Value& val, common::CallingConvention& cc);

} // namespace serdes
} // namespace retdec

#endif