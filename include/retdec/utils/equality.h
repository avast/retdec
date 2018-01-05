/**
* @file include/retdec/utils/equality.h
* @brief Equality-related utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_EQUALITY_H
#define RETDEC_UTILS_EQUALITY_H

#include <cmath>

namespace retdec {
namespace utils {

namespace {

/**
* @brief Checks if @a x is equal to @a y (differing only by @a epsilon).
*
* This function is meant to be used ONLY in floating-point specializations of
* areEqual<> below.
*
* The used solution is not completely symmetric, meaning that it is possible
* that <tt>areEqual(x, y)</tt> returns a different value from <tt>areEqual(y,
* x)</tt>.
*/
template<typename T>
inline bool areEqualFPWithEpsilon(const T &x, const T &y, const T &epsilon) {
	// Implementation notes:
	// - Inspiration was taken from
	//   http://www.parashift.com/c++-faq-lite/newbie.html#faq-29.17. See also
	//   Section 4.2 in [D. Knuth, The Art of Computer Programming, Volume II].
	// - std::{abs,isnan,isinf}() in cmath are overloaded for floats, doubles, and
	//   long doubles.
	if (std::isnan(x)) {
		return std::isnan(y);
	} else if (std::isnan(y)) {
		return false;
	} else if (std::isinf(x)) {
		return std::isinf(x) == std::isinf(y);
	} else if (std::isinf(y)) {
		return false;
	}
	return std::abs(x - y) <= epsilon * std::abs(x);
}

} // anonymous namespace

/// @name Equality of Values
/// @{

/**
* @brief Returns @c true if @a x is equal to @a y, @c false otherwise.
*
* @tparam T Type of @a x and @a y.
*
* By default, it returns <tt>x == y</tt>.
*/
template<typename T>
inline bool areEqual(const T &x, const T &y) {
	return x == y;
}

// Specialization for floats.
template<>
inline bool areEqual<float>(const float &x, const float &y) {
	return areEqualFPWithEpsilon(x, y, 1e-5f);
}

// Specialization for doubles.
template<>
inline bool areEqual<double>(const double &x, const double &y) {
	return areEqualFPWithEpsilon(x, y, 1e-10);
}

// Specialization for long doubles.
template<>
inline bool areEqual<long double>(const long double &x, const long double &y) {
	return areEqualFPWithEpsilon(x, y, 1e-15L);
}

/// @}

} // namespace utils
} // namespace retdec

#endif
