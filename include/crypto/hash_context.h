/**
* @file include/crypto/hash_context.h
* @brief Declaration of class HashContext.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef CRYPTO_HASH_CONTEXT_H
#define CRYPTO_HASH_CONTEXT_H

#include <cstdint>
#include <string>
#include <vector>

#include <openssl/evp.h>

namespace crypto {

enum class HashAlgorithm
{
	Sha1,
	Sha256,
	Md5
};

/**
 * This class represents continuous hashing of data from multiple sources.
 */
class HashContext
{
public:
	HashContext();
	~HashContext();

	bool init(HashAlgorithm algorithm);
	bool addData(const std::uint8_t* data, std::size_t size);
	bool addData(const std::vector<std::uint8_t>& data);
	std::string getHash();

private:
	EVP_MD_CTX* _ctx; ///< OpenSSL envelope message digest context.

	const EVP_MD* _currentAlgo; ///< Internal. Currently used message digest algorithm.
};

}

#endif
