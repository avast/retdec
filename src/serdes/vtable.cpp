/**
 * @file src/serdes/vtable.cpp
 * @brief Address (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/vtable.h"
#include "retdec/serdes/address.h"
#include "retdec/serdes/vtable.h"
#include "retdec/serdes/std.h"

namespace {

const std::string JSON_name          = "name";
const std::string JSON_address       = "address";
const std::string JSON_targetAddress = "targetAddress";
const std::string JSON_targetName    = "targetName";
const std::string JSON_isThumb       = "isThumb";
const std::string JSON_items         = "items";

} // anonymous namespace

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::VtableItem& vti)
{
	writer.StartObject();

	serialize(
			writer,
			JSON_address,
			vti.getAddress(),
			vti.getAddress().isDefined());
	serialize(
			writer,
			JSON_targetAddress,
			vti.getTargetFunctionAddress(),
			vti.getTargetFunctionAddress().isDefined());
	serializeString(writer, JSON_targetName, vti.getTargetFunctionName());
	serializeBool(writer, JSON_isThumb, vti.isThumb(), false);

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::VtableItem)

void deserialize(const rapidjson::Value& val, common::VtableItem& vti)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	common::Address a;
	deserialize(val, JSON_address, a);
	vti.setAddress(a);

	common::Address ta;
	deserialize(val, JSON_targetAddress, ta);
	vti.setTargetFunctionAddress(ta);

	vti.setTargetFunctionName(deserializeString(val, JSON_targetName));
	vti.setIsThumb(deserializeBool(val, JSON_isThumb));
}

template <typename Writer>
void serialize(Writer& writer, const common::Vtable& vt)
{
	writer.StartObject();

	serializeString(writer, JSON_name, vt.getName());
	serialize(writer, JSON_address, vt.getAddress(), vt.getAddress().isDefined());
	serializeContainer(writer, JSON_items, vt.items);

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::Vtable)

void deserialize(const rapidjson::Value& val, common::Vtable& vt)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	common::Address a;
	deserialize(val, JSON_address, a);
	vt.setAddress(a);

	vt.setName(deserializeString(val, JSON_name));
	deserializeContainer(val, JSON_items, vt.items);
}

} // namespace serdes
} // namespace retdec
