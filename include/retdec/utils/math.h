/**
* @file include/retdec/utils/math.h
* @brief Mathematical utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_MATH_H
#define RETDEC_UTILS_MATH_H

namespace retdec {
namespace utils {

/**
* @brief Check if @a number is power of two.
*
* @param[in] number Value which will be checked.
*
* @tparam N Type of @a number.
*/
template<typename N>
bool isPowerOfTwo(N number) {
	return number && !(number & (number - 1));
}

/**
* @brief Check if @a number is power of two or zero.
*
* @param[in] number Value which will be checked.
*
* @tparam N Type of @a number.
*/
template<typename N>
bool isPowerOfTwoOrZero(N number) {
	return !number || isPowerOfTwo(number);
}

unsigned countBits(unsigned long long n);
unsigned bitSizeOfNumber(unsigned long long v);

} // namespace utils
} // namespace retdec

#endif
