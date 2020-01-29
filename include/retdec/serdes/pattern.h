/**
 * @file include/retdec/serdes/pattern.h
 * @brief Pattern (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_PATTERN_H
#define RETDEC_SERDES_PATTERN_H

#include <rapidjson/document.h>

#include "retdec/common/pattern.h"

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::Pattern::Match& pm);
void deserialize(const rapidjson::Value& val, common::Pattern::Match& pm);

template <typename Writer>
void serialize(Writer& writer, const common::Pattern& p);
void deserialize(const rapidjson::Value& val, common::Pattern& p);

} // namespace serdes
} // namespace retdec

#endif