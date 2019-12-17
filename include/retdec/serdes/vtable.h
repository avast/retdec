/**
 * @file include/retdec/serdes/vtable.h
 * @brief Vtable (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_VTABLE_H
#define RETDEC_SERDES_VTABLE_H

#include <json/json.h>

namespace retdec {

namespace common {
class VtableItem;
class Vtable;
} // namespace common

namespace serdes {

Json::Value serialize(const common::VtableItem& vti);
void deserialize(const Json::Value& val, common::VtableItem& vti);

Json::Value serialize(const common::Vtable& vt);
void deserialize(const Json::Value& val, common::Vtable& vt);

} // namespace serdes
} // namespace retdec

#endif