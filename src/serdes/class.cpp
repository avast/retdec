/**
 * @file src/serdes/class.cpp
 * @brief Class (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/class.h"
#include "retdec/serdes/class.h"
#include "retdec/serdes/std.h"

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

template <typename Writer>
void serialize(Writer& writer, const common::Class& c)
{
	writer.StartObject();

	serializeString(writer, JSON_name, c.getName());
	serializeString(writer, JSON_demangledName, c.getDemangledName());

	serializeContainer(writer, JSON_superClasses, c.getSuperClasses());
	serializeContainer(writer, JSON_virtualMethods, c.virtualMethods);
	serializeContainer(writer, JSON_constructors, c.constructors);
	serializeContainer(writer, JSON_destructors, c.destructors);
	serializeContainer(writer, JSON_methods, c.methods);
	serializeContainer(writer, JSON_vtables, c.virtualTables);

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::Class)

void deserialize(const rapidjson::Value& val, common::Class& c)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	c.setName(deserializeString(val, JSON_name));
	c.setDemangledName(deserializeString(val, JSON_demangledName));

	deserializeContainer(val, JSON_virtualMethods, c.virtualMethods);
	deserializeContainer(val, JSON_constructors, c.constructors);
	deserializeContainer(val, JSON_destructors, c.destructors);
	deserializeContainer(val, JSON_methods, c.methods);
	deserializeContainer(val, JSON_vtables, c.virtualTables);

	std::vector<std::string> superClasses;
	deserializeContainer(val, JSON_superClasses, superClasses);
	for (auto& s : superClasses)
	{
		c.addSuperClass(s);
	}
}

} // namespace serdes
} // namespace retdec
