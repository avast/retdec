/**
 * @file include/retdec/serdes/address.h
 * @brief Address (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_ADDRESS_H
#define RETDEC_SERDES_ADDRESS_H

#include <rapidjson/document.h>

#include "retdec/common/address.h"

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::Address& a);
void deserialize(const rapidjson::Value& val, common::Address& a);

template <typename Writer>
void serialize(Writer& writer, const common::AddressRange& r);
void deserialize(const rapidjson::Value& val, common::AddressRange& r);

} // namespace serdes
} // namespace retdec

#endif