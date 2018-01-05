/**
 * @file include/loader/utils/range.h
 * @brief Declaration of operations over ranges.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef LOADER_UTILS_RANGE_H
#define LOADER_UTILS_RANGE_H

#include <cstdint>

namespace loader {

std::uint64_t distanceBetween(std::uint64_t value1, std::uint64_t value2);

} // namespace loader

#endif
