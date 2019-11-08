/**
 * @file include/retdec/serdes/range.h
 * @brief Range (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_ADDRESS_H
#define RETDEC_SERDES_ADDRESS_H

#include <json/json.h>

namespace retdec {

namespace common {
template <typename T> class Range;
} // namespace common

namespace serdes {

template <typename T>
Json::Value serialize(const common::Range<T>& r)
{
	Json::Value ret;

	if (getStart().isDefined() && getEnd().isDefined())
	{
		ret["start"] = getStart();
		ret["end"] = getEnd();
	}

	return ret;
}

template <typename T>
common::Range<T> deserialize(const Json::Value& val)
{
	common::Range<T> ret;

	if (val.isNull())
	{
		return ret;
	}

	// std::string enumStr = safeGetString(val);
	// auto it = std::find(ccStrings.begin(), ccStrings.end(), enumStr);
	// if (it == ccStrings.end())
	// {
	// 	ret.setIsUnknown();
	// }
	// else
	// {
	// 	ret.set(static_cast<common::CallingConvention::eCC>(
	// 			std::distance(ccStrings.begin(), it)));
	// }

	return ret;
}

} // namespace serdes
} // namespace retdec

#endif