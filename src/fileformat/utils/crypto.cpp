/**
 * @file src/fileformat/utils/crypto.cpp
 * @brief Crypto functions.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include <climits>
#include <cmath>
#include <vector>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include "retdec/fileformat/utils/crypto.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/crc32.h"

namespace retdec {
namespace fileformat {

/**
 * @brief Count CRC32 of @a data.
 * @param[in] data Input data.
 * @param[in] length Length of input data.
 * @return CRC32 of input data.
 */
std::string getCrc32(const unsigned char *data, std::uint64_t length)
{
	retdec::utils::CRC32 crc;
	return crc(data, length);
}

/**
 * @brief Count MD5 of @a data.
 * @param[in] data Input data.
 * @param[in] length Length of input data.
 * @return MD5 of input data.
 */
std::string getMd5(const unsigned char *data, std::uint64_t length)
{
	std::vector<unsigned char> digest(MD5_DIGEST_LENGTH);
	MD5(data, length, digest.data());

	std::string md5;
	retdec::utils::bytesToHexString(digest, md5, 0, 0, false);
	return md5;
}

/**
 * @brief Count SHA1 of @a data.
 * @param[in] data Input data.
 * @param[in] length Length of input data.
 * @return SHA256 of input data.
 */
std::string getSha1(const unsigned char *data, std::uint64_t length)
{
	std::vector<unsigned char> digest(SHA_DIGEST_LENGTH);
	SHA1(data, length, digest.data());

	std::string sha;
	retdec::utils::bytesToHexString(digest, sha, 0, 0, false);
	return sha;
}

/**
 * @brief Count SHA256 of @a data.
 * @param[in] data Input data.
 * @param[in] length Length of input data.
 * @return SHA256 of input data.
 */
std::string getSha256(const unsigned char *data, std::uint64_t length)
{
	std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
	SHA256(data, length, digest.data());

	std::string sha;
	retdec::utils::bytesToHexString(digest, sha, 0, 0, false);
	return sha;
}

} // namespace fileformat
} // namespace retdec
