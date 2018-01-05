/**
 * @file include/tl-cpputils/alignment.h
 * @brief Declaration of aligning operations.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef TL_CPPUTILS_ALIGNMENT_H
#define TL_CPPUTILS_ALIGNMENT_H

#include <cstdint>

namespace tl_cpputils {

bool isAligned(std::uint64_t value, std::uint64_t alignment, std::uint64_t& remainder);
std::uint64_t alignDown(std::uint64_t value, std::uint64_t alignment);
std::uint64_t alignUp(std::uint64_t value, std::uint64_t alignment);

} // namespace tl_cpputils

#endif
