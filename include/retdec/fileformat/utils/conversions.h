/**
 * @file include/retdec/fileformat/utils/conversions.h
 * @brief Simple string conversions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_UTILS_CONVERSIONS_H
#define RETDEC_FILEFORMAT_UTILS_CONVERSIONS_H

#include <iomanip>
#include <sstream>
#include <vector>

#include "retdec/fileformat/utils/other.h"

namespace retdec {
namespace fileformat {

/**
 * Add @a newVal to @a currentValues, if @a newVal is not stored in @a currentValues before calling of this function
 * @param currentValues Vector of current values
 * @param newVal New value
 * @param newIndex Into this parameter is stored index (indexed from 0) of @a currentValues at which is @a newVal
 * @return @c true if @a newVal was added to @a currentValues, @c false otherwise
 */
template<typename N> bool addUniqueValue(std::vector<N> &currentValues, N newVal, std::size_t &newIndex)
{
	const auto curSize = currentValues.size();

	for(std::size_t i = 0; i < curSize; ++i)
	{
		if(currentValues[i] == newVal)
		{
			newIndex = i;
			return false;
		}
	}

	currentValues.push_back(newVal);
	newIndex = curSize;
	return true;
}

std::ios_base& hexWithPrefix(std::ios_base &str);
void separateStrings(std::string &str, std::vector<std::string> &words);

} // namespace fileformat
} // namespace retdec

#endif
