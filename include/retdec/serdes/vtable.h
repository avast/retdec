/**
 * @file include/retdec/serdes/vtable.h
 * @brief Vtable (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_VTABLE_H
#define RETDEC_SERDES_VTABLE_H

#include <rapidjson/document.h>

namespace retdec {

namespace common {
class VtableItem;
class Vtable;
} // namespace common

namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::VtableItem& vti);
void deserialize(const rapidjson::Value& val, common::VtableItem& vti);

template <typename Writer>
void serialize(Writer& writer, const common::Vtable& vt);
void deserialize(const rapidjson::Value& val, common::Vtable& vt);

} // namespace serdes
} // namespace retdec

#endif