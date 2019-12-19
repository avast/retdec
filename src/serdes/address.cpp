/**
 * @file src/serdes/address.cpp
 * @brief Address (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

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

Json::Value serialize(const common::AddressRange& r)
{
	Json::Value pair;

	if (r.getStart().isDefined() && r.getEnd().isDefined())
	{
		pair["start"] = serialize(r.getStart());
		pair["end"] = serialize(r.getEnd());
	}

	return pair;
}

void deserialize(const Json::Value& val, common::AddressRange& r)
{
	if (val.isNull())
	{
		return;
	}

	common::Address s, e;
	deserialize(val["start"], s);
	deserialize(val["end"], e);
	r.setStartEnd(s, e);
}

} // namespace serdes
} // namespace retdec
