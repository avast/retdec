/**
 * @file src/serdes/std.cpp
 * @brief C++ standard types (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/serdes/std.h"

#include "serdes/utils.h"

namespace retdec {
namespace serdes {

Json::Value serialize(const char*& str)
{
	return str;
}

Json::Value serialize(const std::string& s)
{
	return s;
}

void deserialize(const Json::Value& val, const char*& str)
{
	str = val.asCString();
}

void deserialize(const Json::Value& val, std::string& s)
{
	s = val.asString();
}

} // namespace serdes
} // namespace retdec
