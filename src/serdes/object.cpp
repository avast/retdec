/**
 * @file src/serdes/object.cpp
 * @brief Object (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/object.h"
#include "retdec/serdes/object.h"
#include "retdec/serdes/storage.h"
#include "retdec/serdes/type.h"

#include "retdec/serdes/std.h"

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

template <typename Writer>
void serialize(Writer& writer, const common::Object& o)
{
	writer.StartObject();

	serializeString(writer, JSON_name, o.getName());
	serializeString(writer, JSON_realName, o.getRealName());
	serializeString(writer, JSON_cryptoDesc, o.getCryptoDescription());
	serializeBool(writer, JSON_fromDebug, o.isFromDebug(), false);

	serialize(writer, JSON_type, o.type, o.type.isDefined());
	serialize(writer, JSON_storage, o.getStorage(), o.getStorage().isDefined());

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::Object)

void deserialize(const rapidjson::Value& val, common::Object& o)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	common::Storage storage;
	deserialize(val, JSON_storage, storage);

	o = common::Object(deserializeString(val, JSON_name), storage);

	o.setRealName( deserializeString(val, JSON_realName) );
	o.setCryptoDescription( deserializeString(val, JSON_cryptoDesc) );
	o.setIsFromDebug( deserializeBool(val, JSON_fromDebug) );
	deserialize(val, JSON_type, o.type);
}

} // namespace serdes
} // namespace retdec
