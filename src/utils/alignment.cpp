/**
 * @file src/utils/alignment.cpp
 * @brief Definition of aligning operations.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/alignment.h"

namespace retdec {
namespace utils {

/**
 * Checks whether given value is aligned based on alignment value. Alignment must be power of 2.
 *
 * @param value Value to be checked.
 * @param alignment Alignment to check. Must be power of 2.
 * @param remainder Output value that is non-zero if value is not aligned and zero if it is aligned.
 *   It contains @c value modulo @c alignment. Contains undefined value if alignment is not power of 2.
 *
 * @return True if value is aligned to given alignment, false otherwise. If alignment is not power of 2
 *   the return value is undefined.
 */
bool isAligned(std::uint64_t value, std::uint64_t alignment, std::uint64_t& remainder)
{
	return (remainder = (value & (alignment - 1))) == 0;
}

/**
 * Aligns given value down by specified alignment. Alignment must be power of 2.
 *
 * @param value Value to align.
 * @param alignment Alignment to use.
 *
 * @return Value aligned down. If alignment is not power of 2, return value is undefined.
 */
std::uint64_t alignDown(std::uint64_t value, std::uint64_t alignment)
{
	return value & ~(alignment - 1);
}

/**
 * Aligns given value up by specified alignment. Alignment must be power of 2.
 *
 * @param value Value to align.
 * @param alignment Alignment to use.
 *
 * @return Value aligned up. If alignment is not power of 2, return value is undefined.
 */
std::uint64_t alignUp(std::uint64_t value, std::uint64_t alignment)
{
	return alignDown(value + (alignment - 1), alignment);
}

} // namespace utils
} // namespace retdec
