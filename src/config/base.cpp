/**
 * @file src/config/base.cpp
 * @brief Decompilation configuration manipulation: base.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/config/base.h"

//
//=============================================================================
// Safe (check type and throw exception) JSON value loading methods
//=============================================================================
//

#define SAFE_TEMPLATE(val, name, defaultValue, isF, asF, valStr)      \
	auto x = (name.empty()) ? (val) : (val.get(name, defaultValue));  \
	if (x.isF())                                                      \
	{                                                                 \
		return x.asF();                                               \
	}                                                                 \
	else                                                              \
	{                                                                 \
		std::string n = (name.empty()) ? ("property") : (name);       \
		std::string throwMsg = n + " must be " + valStr + " value";   \
		throw InternalException(throwMsg, x.getOffsetStart());        \
	}

namespace retdec {
namespace config {

/**
 * If JSON value is not an object value, throw an internal exception.
 * @param val Value to check.
 * @param name Name of the value to check that will be used in a throw message.
 */
void checkJsonValueIsObject(const Json::Value& val, const std::string& name)
{
	if ( val.isNull() || !val.isObject() )
	{
		std::string throwMsg = name + " must be an object value";
		throw InternalException(throwMsg, val.getOffsetStart());
	}
}

Json::Value::Int safeGetInt(
		const Json::Value& val,
		const std::string& name,
		Json::Value::Int defaultValue)
{
	SAFE_TEMPLATE(val, name, defaultValue, isInt, asInt, "an int");
}

Json::Value::UInt safeGetUint(
		const Json::Value& val,
		const std::string& name,
		Json::Value::UInt defaultValue)
{
	SAFE_TEMPLATE(val, name, defaultValue, isUInt, asUInt, "an uint");
}

retdec::utils::Address safeGetAddress(
		const Json::Value& val,
		const std::string& name)
{
	std::string strVal = safeGetString(val, name, "");
	return retdec::utils::Address(strVal);
}

Json::Value::UInt64 safeGetUint64(
		const Json::Value& val,
		const std::string& name,
		Json::Value::UInt64 defaultValue)
{
	SAFE_TEMPLATE(val, name, defaultValue, isUInt64, asUInt64, "an uint64");
}

double safeGetDouble(
		const Json::Value& val,
		const std::string& name,
		double defaultValue)
{
	SAFE_TEMPLATE(val, name, defaultValue, isDouble, asDouble, "a double");
}

std::string safeGetString(
		const Json::Value& val,
		const std::string& name,
		const std::string& defaultValue)
{
	SAFE_TEMPLATE(val, name, defaultValue, isString, asString, "a string");
}

bool safeGetBool(
		const Json::Value& val,
		const std::string& name,
		bool defaultValue)
{
	SAFE_TEMPLATE(val, name, defaultValue, isBool, asBool, "a bool");
}

//
//=============================================================================
// Conversions to JSON values.
//=============================================================================
//

std::string toJsonValue(retdec::utils::Address a)
{
	return a.isDefined() ? a.toHexPrefixString() : std::string();
}

//
//=============================================================================
// Helper methods
//=============================================================================
//

/**
 * Reads array of JSON objects into elements of the provided string container.
 * Container is cleared before parsing - it contains only new objects afterwards.
 * @param data String set.
 * @param node JSON object.
 */
void readJsonStringValueVisit(std::set<std::string>& data, const Json::Value& node)
{
	data.clear();

	for (auto& elem : node)
	{
		if ( ! elem.isNull() )
		{
			data.insert( safeGetString(elem) );
		}
	}
}

/**
 * Reads array of JSON objects into elements of the provided string container.
 * Container is cleared before parsing - it contains only new objects afterwards.
 * @param data String vector.
 * @param node JSON object.
 */
void readJsonStringValueVisit(std::vector<std::string>& data, const Json::Value& node)
{
	data.clear();

	for (auto& elem : node)
	{
		if ( ! elem.isNull() )
		{
			data.push_back( safeGetString(elem) );
		}
	}
}

} // namespace config
} // namespace retdec
