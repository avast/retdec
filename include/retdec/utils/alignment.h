/**
 * @file include/retdec/utils/alignment.h
 * @brief Declaration of aligning operations.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UTILS_ALIGNMENT_H
#define RETDEC_UTILS_ALIGNMENT_H

#include <cstdint>

namespace retdec {
namespace utils {

bool isAligned(std::uint64_t value, std::uint64_t alignment, std::uint64_t& remainder);
std::uint64_t alignDown(std::uint64_t value, std::uint64_t alignment);
std::uint64_t alignUp(std::uint64_t value, std::uint64_t alignment);

} // namespace utils
} // namespace retdec

#endif
