/**
* @file src/utils/system.cpp
* @brief Implementation of the portable system utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/utils/os.h"
#include "retdec/utils/system.h"

// sleep()
#ifdef OS_WINDOWS
	#include <windows.h>
#else
	#include <unistd.h>
#endif

namespace retdec {
namespace utils {

/**
* @brief Sleeps for the given number of seconds.
*/
void sleep(unsigned seconds) {
	#ifdef OS_WINDOWS
		// The Windows version expects the number in milliseconds.
		::Sleep(seconds * 1000);
	#else
		::sleep(seconds);
	#endif
}

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
