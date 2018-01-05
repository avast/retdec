/**
* @file include/tl-cpputils/math.h
* @brief Mathematical utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef TL_CPPUTILS_MATH_H
#define TL_CPPUTILS_MATH_H

namespace tl_cpputils {

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

} // namespace tl_cpputils

#endif
