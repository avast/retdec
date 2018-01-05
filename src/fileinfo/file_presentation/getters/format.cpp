/**
 * @file src/fileinfo/file_presentation/getters/format.cpp
 * @brief Functions for formatting of strings.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "retdec/utils/string.h"
#include "fileinfo/file_presentation/getters/format.h"

using namespace retdec::utils;

namespace fileinfo {

/**
 * Serialization of abbreviations
 * @param abbv Vector of abbreviations
 * @return Serialized abbreviations
 *
 * Abbreviations are sorted in order of their storage in @a abbv
 */
std::string abbvSerialization(const std::vector<std::string> &abbv)
{
	std::string result;

	for(const auto &item : abbv)
	{
		result += item;
	}

	return result;
}

/**
 * Shrink @a str to max @a maxLength characters and replace nonprintable
 *    characters in @a str
 */
void shrinkAndReplaceNonprintable(std::string &str, std::size_t maxLength)
{
	if(str.length() > maxLength)
	{
		str.resize(maxLength);
		str += " [...]";
	}

	str = replaceNonprintableChars(str);
}

/**
 * To @a currentVal add values from @a newVal, which are not stored in
 *    @a currentVal before calling of this function
 */
void addUniqueValues(std::vector<std::string> &currentVal, const std::vector<std::string> &newVal)
{
	for(std::size_t i = 0, e = newVal.size(); i < e; ++i)
	{
		if(find(currentVal.begin(), currentVal.end(), newVal[i]) == currentVal.end())
		{
			currentVal.push_back(newVal[i]);
		}
	}
}

} // namespace fileinfo
