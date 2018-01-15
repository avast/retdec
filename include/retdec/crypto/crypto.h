/**
* @file include/retdec/crypto/crypto.h
* @brief Cryptography-related functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CRYPTO_CRYPTO_H
#define RETDEC_CRYPTO_CRYPTO_H

#include <cstdint>
#include <string>

namespace retdec {
namespace crypto {

std::uint64_t getCrc16(const unsigned char *data, std::uint64_t length);
std::string getCrc32(const unsigned char *data, std::uint64_t length);
std::string getMd5(const unsigned char *data, std::uint64_t length);
std::string getSha1(const unsigned char *data, std::uint64_t length);
std::string getSha256(const unsigned char *data, std::uint64_t length);

} // namespace crypto
} // namespace retdec

#endif
