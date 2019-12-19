/**
 * @file src/serdes/class.cpp
 * @brief Class (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include "retdec/common/class.h"
#include "retdec/serdes/class.h"
#include "retdec/serdes/std.h"

#include "serdes/utils.h"

namespace {

const std::string JSON_name           = "name";
const std::string JSON_demangledName  = "demangledName";
const std::string JSON_superClasses   = "superClasses";
const std::string JSON_virtualMethods = "virtualMethods";
const std::string JSON_constructors   = "constructors";
const std::string JSON_destructors    = "destructors";
const std::string JSON_methods        = "methods";
const std::string JSON_vtables        = "virtualTables";

} // anonymous namespace

namespace retdec {
namespace serdes {

Json::Value serialize(const common::Class& c)
{
	Json::Value val;

	if (!c.getName().empty())
	{
		val[JSON_name] = c.getName();
	}
	if (!c.getDemangledName().empty())
	{
		val[JSON_demangledName] = c.getDemangledName();
	}

	val[JSON_superClasses]   = serdes::serialize(c.getSuperClasses());
	val[JSON_virtualMethods] = serdes::serialize(c.virtualMethods);
	val[JSON_constructors]   = serdes::serialize(c.constructors);
	val[JSON_destructors]    = serdes::serialize(c.destructors);
	val[JSON_methods]        = serdes::serialize(c.methods);
	val[JSON_vtables]        = serdes::serialize(c.virtualTables);

	return val;
}

void deserialize(const Json::Value& val, common::Class& c)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	c.setName(safeGetString(val, JSON_name));
	c.setDemangledName(safeGetString(val, JSON_demangledName));

	serdes::deserialize(val[JSON_virtualMethods], c.virtualMethods);
	serdes::deserialize(val[JSON_constructors], c.constructors);
	serdes::deserialize(val[JSON_destructors], c.destructors);
	serdes::deserialize(val[JSON_methods], c.methods);
	serdes::deserialize(val[JSON_vtables], c.virtualTables);

	std::vector<std::string> superClasses;
	serdes::deserialize(val[JSON_superClasses], superClasses);
	for (auto& s : superClasses)
	{
		c.addSuperClass(s);
	}
}

} // namespace serdes
} // namespace retdec
