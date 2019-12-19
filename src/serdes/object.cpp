/**
 * @file src/serdes/object.cpp
 * @brief Object (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include "retdec/common/object.h"
#include "retdec/serdes/object.h"
#include "retdec/serdes/storage.h"
#include "retdec/serdes/type.h"

#include "serdes/utils.h"

namespace {

const std::string JSON_name       = "name";
const std::string JSON_realName   = "realName";
const std::string JSON_storage    = "storage";
const std::string JSON_type       = "type";
const std::string JSON_fromDebug  = "isFromDebug";
const std::string JSON_cryptoDesc = "cryptoDescription";

} // anonymous namespace

namespace retdec {
namespace serdes {

Json::Value serialize(const common::Object& o)
{
	Json::Value obj;

	if (!o.getName().empty())
	{
		obj[JSON_name] = o.getName();
	}
	if (!o.getRealName().empty())
	{
		obj[JSON_realName] = o.getRealName();
	}
	if (!o.getCryptoDescription().empty())
	{
		obj[JSON_cryptoDesc] = o.getCryptoDescription();
	}
	if (o.isFromDebug())
	{
		obj[JSON_fromDebug] = o.isFromDebug();
	}

	if (o.type.isDefined())
	{
		obj[JSON_type] = serdes::serialize(o.type);
	}
	if (o.getStorage().isDefined())
	{
		obj[JSON_storage] = serdes::serialize(o.getStorage());
	}

	return obj;
}

void deserialize(const Json::Value& val, common::Object& o)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	common::Storage storage;
	serdes::deserialize(val[JSON_storage], storage);

	o = common::Object(safeGetString(val, JSON_name), storage);

	o.setRealName( safeGetString(val, JSON_realName) );
	o.setCryptoDescription( safeGetString(val, JSON_cryptoDesc) );
	o.setIsFromDebug( safeGetBool(val, JSON_fromDebug) );
	serdes::deserialize(val[JSON_type], o.type);
}

} // namespace serdes
} // namespace retdec
