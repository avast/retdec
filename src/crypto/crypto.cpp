/**
* @file src/crypto/crypto.cpp
* @brief Implementation of the cryptography-related functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <climits>
#include <cmath>
#include <vector>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include "retdec/crypto/crc32.h"
#include "retdec/crypto/crypto.h"
#include "retdec/utils/conversion.h"

namespace retdec {
namespace crypto {

namespace {

constexpr auto CRC16_POLY = 0x8408U;

} // anonymous namespace

/**
 * @brief This is the CCITT CRC 16 CRC16_POLYnomial X^16 + X^12 + X^5 + 1.
 * This works out to be 0x1021, but the way the algorithm works lets us use
 * 0x8408 (the reverse of the bit pattern). The high bit is always assumed to
 * be set, thus we only use 16 bits to represent the 17 bit value.
 * @param[in] data Data to calculate the CRC checksum for.
 * @param[in] length Length of the input data.
 * @return CRC16 checksum.
 */
std::uint64_t getCrc16(const unsigned char *data, std::uint64_t length)
{
	if (!data || !length) {
		return 0;
	}

	unsigned int actData;
	unsigned int crc = 0xFFFF;

	do
	{
		actData = *data++;
		for (auto i = 0; i < 8; ++i)
		{
			if ((crc ^ actData) & 1)
			{
				crc = (crc >> 1) ^ CRC16_POLY;
			}
			else
			{
				crc >>= 1;
			}
			actData >>= 1;
		}
	} while (--length);

	crc = ~crc;
	actData = crc;
	crc = (crc << 8) | ((actData >> 8) & 0xff);
	const std::uint64_t max = std::pow(2, 16) - 1;
	return crc & max;
}

/**
 * @brief Count CRC32 of @a data.
 * @param[in] data Input data.
 * @param[in] length Length of input data.
 * @return CRC32 of input data.
 */
std::string getCrc32(const unsigned char *data, std::uint64_t length)
{
	CRC32 crc;
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

} // namespace crypto
} // namespace retdec
