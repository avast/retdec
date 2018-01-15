/**
 * @file src/loader/utils/range.cpp
 * @brief Definition of operations over ranges.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>

#include "retdec/loader/utils/range.h"

namespace retdec {
namespace loader {

/**
 * Returns the distance between two values. The distance is absolute value of their subtraction.
 *
 * @param value1 First value.
 * @param value2 Second value.
 *
 * @return The distance between the values.
 */
std::uint64_t distanceBetween(std::uint64_t value1, std::uint64_t value2)
{
	if (value1 > value2)
		return value1 - value2;

	return value2 - value1;
}

} // namespace loader
} // namespace retdec
