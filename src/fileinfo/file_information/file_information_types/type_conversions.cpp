/**
 * @file src/fileinfo/file_information/file_information_types/type_conversions.cpp
 * @brief Type conversions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <string>

namespace fileinfo {

/**
 * Get binary composition of number
 * @param number Number for conversion
 * @param numberOfBits Required number of bits in result
 * @return String representation of binary number
 */
std::string getBinaryRepresentation(unsigned long long number, unsigned long long numberOfBits)
{
	std::string result;

	for(unsigned long long i = 0, mask = 1; i < numberOfBits; ++i, number >>= 1)
	{
		result = ((number & mask) ? "1" : "0") + result;
	}

	return result;
}

} // namespace fileinfo
