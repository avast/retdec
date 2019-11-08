/**
 * @file include/retdec/serdes/address.h
 * @brief C++ standard types (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_STD_H
#define RETDEC_SERDES_STD_H

#include <json/json.h>

namespace retdec {
namespace serdes {

template<typename Container>
Json::Value serialize(const Container& data)
{
	Json::Value array(Json::arrayValue);
	for (auto& elem : data)
	{
		array.append(elem);
	}
	return array;
}

template<typename Container>
void deserialize(const Json::Value& val, Container& data)
{
	data.clear();

	for (auto& elem : val)
	{
		if (!elem.isNull())
		{
			data.insert(data.end(), elem.asString());
		}
	}
}

} // namespace serdes
} // namespace retdec

#endif