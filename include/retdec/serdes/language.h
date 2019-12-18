/**
 * @file include/retdec/serdes/language.h
 * @brief Language (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_LANGUAGE_H
#define RETDEC_SERDES_LANGUAGE_H

#include <json/json.h>

namespace retdec {

namespace common {
class Language;
} // namespace common

namespace serdes {

Json::Value serialize(const common::Language& l);
void deserialize(const Json::Value& val, common::Language& l);

} // namespace serdes
} // namespace retdec

#endif