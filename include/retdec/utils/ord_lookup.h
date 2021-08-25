/**
 * @file include/retdec/utils/ord_lookup.h
 * @brief Converts well-known ordinals to function names
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UTILS_ORD_LOOKUP_H
#define RETDEC_UTILS_ORD_LOOKUP_H

namespace retdec {
namespace utils {

std::string ordLookUp(const std::string& libName, const std::size_t& ordNum, bool forceNameFromOrdinal);

} // namespace utils
} // namespace retdec

#endif
