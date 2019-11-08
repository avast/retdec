/**
 * @file src/serdes/address.h
 * @brief Address (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/common/address.h"
#include "retdec/serdes/address.h"

#include "serdes/utils.h"

namespace retdec {
namespace serdes {

Json::Value serialize(const common::Address& a)
{
	return a.isDefined() ? a.toHexPrefixString() : std::string();
}

void deserialize(const Json::Value& val, common::Address& a)
{
	if (val.isNull() || !val.isString())
	{
		return;
	}

	a = common::Address(val.asString());
}

} // namespace serdes
} // namespace retdec
