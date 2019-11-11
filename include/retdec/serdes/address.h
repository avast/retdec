/**
 * @file include/retdec/serdes/address.h
 * @brief Address (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_ADDRESS_H
#define RETDEC_SERDES_ADDRESS_H

#include <json/json.h>

#include "retdec/common/address.h"

namespace retdec {
namespace serdes {

Json::Value serialize(const common::Address& a);
void deserialize(const Json::Value& val, common::Address& a);

Json::Value serialize(const common::AddressRange& r);
void deserialize(const Json::Value& val, common::AddressRange& r);

} // namespace serdes
} // namespace retdec

#endif