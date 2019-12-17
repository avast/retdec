/**
 * @file include/retdec/serdes/address.h
 * @brief C++ standard types (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_STD_H
#define RETDEC_SERDES_STD_H

#include <map>
#include <type_traits>

#include <json/json.h>

#include "retdec/serdes/language.h"

namespace retdec {
namespace serdes {

Json::Value serialize(const char*& str);
Json::Value serialize(const std::string& s);

template <typename T,
typename std::enable_if<std::is_integral<T>::value, int>::type* = nullptr>
Json::Value serialize(const T& val)
{
	return val;
}

template <typename T,
typename std::enable_if<std::is_floating_point<T>::value, int>::type* = nullptr>
Json::Value serialize(const T& val)
{
	return val;
}

template<typename Container>
Json::Value serialize(const Container& data)
{
	Json::Value array(Json::arrayValue);
	for (auto& elem : data)
	{
		array.append(serialize(elem));
	}
	return array;
}

void deserialize(const Json::Value& val, const char*& str);
void deserialize(const Json::Value& val, std::string& s);

template <typename T,
typename std::enable_if<std::is_floating_point<T>::value, int>::type* = nullptr>
void deserialize(const Json::Value& val, const T& v)
{
	v = val.asDouble();
}

template <typename T,
typename std::enable_if<std::is_signed<T>::value, int>::type* = nullptr>
void deserialize(const Json::Value& val, const T& v)
{
	v = val.asLargestInt();
}

template <typename T,
typename std::enable_if<std::is_unsigned<T>::value, int>::type* = nullptr>
void deserialize(const Json::Value& val, const T& v)
{
	v = val.asLargestUInt();
}

template<typename Container>
void deserialize(const Json::Value& val, Container& data)
{
	data.clear();

	for (auto& elem : val)
	{
		if (!elem.isNull())
		{
			typename Container::value_type v;
			deserialize(elem, v);
			data.insert(data.end(), v);
		}
	}
}

} // namespace serdes
} // namespace retdec

#endif