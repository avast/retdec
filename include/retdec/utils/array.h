/**
* @file include/retdec/utils/array.h
* @brief Array utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_ARRAY_H
#define RETDEC_UTILS_ARRAY_H

#include <cstddef>

namespace retdec {
namespace utils {

/**
* @brief Returns the number of elements of the given array as a compile-time
*        constant.
*
* Usage example:
* @code
* int array[10];
* int other_array[arraySize(array)]; // will have 10 elements
* @endcode
*/
// The array parameter has no name because we care only about the number of
// elements it contains.
template<typename T, std::size_t N>
constexpr std::size_t arraySize(T (&)[N]) noexcept {
	return N;
}

} // namespace utils
} // namespace retdec

#endif
