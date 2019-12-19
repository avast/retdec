/**
 * @file src/serdes/vtable.cpp
 * @brief Address (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/common/vtable.h"
#include "retdec/serdes/address.h"
#include "retdec/serdes/vtable.h"
#include "retdec/serdes/std.h"

#include "serdes/utils.h"

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

Json::Value serialize(const common::VtableItem& vti)
{
	Json::Value val;

	if (vti.getAddress().isDefined())
	{
		val[JSON_address] = serialize(vti.getAddress());
	}
	if (vti.getTargetFunctionAddress().isDefined())
	{
		val[JSON_targetAddress] = serialize(
				vti.getTargetFunctionAddress());
	}
	if (!vti.getTargetFunctionName().empty())
	{
		val[JSON_targetName] = vti.getTargetFunctionName();
	}
	if (vti.isThumb())
	{
		val[JSON_isThumb] = vti.isThumb();
	}

	return val;
}

void deserialize(const Json::Value& val, common::VtableItem& vti)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	common::Address a;
	deserialize(val[JSON_address], a);
	vti.setAddress(a);

	common::Address ta;
	deserialize(val[JSON_targetAddress], ta);
	vti.setTargetFunctionAddress(ta);

	vti.setTargetFunctionName(safeGetString(val, JSON_targetName));
	vti.setIsThumb(safeGetBool(val, JSON_isThumb, false));
}

Json::Value serialize(const common::Vtable& vt)
{
	Json::Value val;

	if (!vt.getName().empty())
	{
		val[JSON_name] = vt.getName();
	}
	if (vt.getAddress().isDefined())
	{
		val[JSON_address] = serialize(vt.getAddress());
	}
	if (!vt.items.empty())
	{
		val[JSON_items] = serialize(vt.items);
	}

	return val;
}

void deserialize(const Json::Value& val, common::Vtable& vt)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	common::Address a;
	deserialize(val[JSON_address], a);
	vt.setAddress(a);

	vt.setName(safeGetString(val, JSON_name));
	deserialize(val[JSON_items], vt.items);
}

} // namespace serdes
} // namespace retdec
