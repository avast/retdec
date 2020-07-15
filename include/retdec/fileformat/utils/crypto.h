/**
 * @file include/retdec/fileformat/utils/crypto.h
 * @brief Crypto functions.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_UTILS_CRYPTO_H
#define RETDEC_FILEFORMAT_UTILS_CRYPTO_H

#include <cstdint>
#include <string>

namespace retdec {
namespace fileformat {

std::string getCrc32(const unsigned char *data, std::uint64_t length);
std::string getMd5(const unsigned char *data, std::uint64_t length);
std::string getSha1(const unsigned char *data, std::uint64_t length);
std::string getSha256(const unsigned char *data, std::uint64_t length);

} // namespace fileformat
} // namespace retdec

#endif