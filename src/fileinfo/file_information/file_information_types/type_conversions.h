/**
 * @file src/fileinfo/file_information/file_information_types/type_conversions.h
 * @brief Type conversions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_TYPE_CONVERSIONS_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_TYPE_CONVERSIONS_H

#include <limits>
#include <vector>

#include "retdec/utils/conversion.h"

namespace fileinfo {

std::string getBinaryRepresentation(unsigned long long number, unsigned long long numberOfBits);

/**
 * Get number as string
 * @param number Number for conversion
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Number in string representation or empty string if number value is incorrect
 *
 * For signed numeric types is incorrect value their minimal value (e.g. INT_MIN).
 * For unsigned numeric types is incorrect value their maximal value (e.g. UINT_MAX).
 */
template<typename N> std::string getNumberAsString(N number, std::ios_base &(* format)(std::ios_base &) = std::dec)
{
	if(!std::numeric_limits<N>::is_signed && number != std::numeric_limits<N>::max())
	{
		return retdec::utils::numToStr(number, format);
	}
	else if(std::numeric_limits<N>::is_signed && number != std::numeric_limits<N>::min())
	{
		return retdec::utils::numToStr(number, format);
	}

	return "";
}

/**
 * Check vector size
 * @param list Vector for check
 * @param index Index of element in vector
 * @return @c true if index is correct in context of vector, @c false otherwise
 */
template<typename N> inline bool indexIsValid(const std::vector<N> &list, std::size_t index)
{
	return index < list.size();
}

} // namespace fileinfo

#endif
