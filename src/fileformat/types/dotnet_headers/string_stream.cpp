/**
 * @file src/fileformat/types/dotnet_headers/string_stream.cpp
 * @brief Class for \#Strings Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/dotnet_headers/string_stream.h"

namespace retdec {
namespace fileformat {

StringStream::StringStream(std::uint64_t streamOffset, std::uint64_t streamSize) : Stream(StreamType::String, streamOffset, streamSize)
{
	strings.emplace(0, std::string{});
}

bool StringStream::getString(std::size_t offset, std::string& result) const
{
	if (offset >= getSize())
		return false;

	auto itr = strings.lower_bound(offset);
	if (itr == strings.begin())
	{
		result.clear();
		return true;
	}

	// User can also request string at the offset in the middle of another string
	// We need to find if there is a difference between string's offset and requested offset
	if (itr != strings.end() && offset == itr->first)
	{
		result = itr->second;
		return true;
	}

	// If so, move backwards by one element (lower bound returns the first element that is not greater than searched element)
	--itr;
	std::size_t substrOffset = offset - itr->first;
	if (substrOffset >= itr->second.length())
		return false;

	result = itr->second.substr(offset - itr->first);
	return true;
}

void StringStream::addString(std::size_t offset, const std::string& string)
{
	strings.emplace(offset, string);
}

} // namespace fileformat
} // namespace retdec
