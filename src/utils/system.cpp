/**
* @file src/utils/system.cpp
* @brief Implementation of the portable system utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/utils/os.h"
#include "retdec/utils/system.h"

namespace retdec {
namespace utils {

/**
* @brief Finds out if the runtime architecture is little endian.
*/
bool isLittleEndian() {
	// We use static variables to compute the endianess only once.
	static const short endian_test_pattern = 0x00ff;
	static const bool little_endian =
		*(reinterpret_cast<const char*>(&endian_test_pattern)) == '\xff';
	return little_endian;
}

/**
* @brief Finds out if the runtime system supports <tt>long double</tt> (at least
*        10 bytes long).
*/
bool systemHasLongDouble() {
	return sizeof(long double) >= 10;
}

} // namespace utils
} // namespace retdec
