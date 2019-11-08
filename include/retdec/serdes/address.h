/**
 * @file include/retdec/serdes/address.h
 * @brief Address (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_ADDRESS_H
#define RETDEC_SERDES_ADDRESS_H

#include <json/json.h>

namespace retdec {

namespace common {
class Address;
} // namespace common

namespace serdes {

Json::Value serialize(const common::Address& a);
void deserialize(const Json::Value& val, common::Address& a);

} // namespace serdes
} // namespace retdec

#endif