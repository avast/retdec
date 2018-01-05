/**
* @file src/crypto/hash_context.cpp
* @brief Implementation of class HashContext.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <unordered_map>

#include "retdec/crypto/hash_context.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"

namespace retdec {
namespace crypto {

namespace {

const std::unordered_map<HashAlgorithm, const EVP_MD*, retdec::utils::EnumClassKeyHash> opensslAlgos =
{
	{ HashAlgorithm::Sha1,   EVP_sha1()   },
	{ HashAlgorithm::Sha256, EVP_sha256() },
	{ HashAlgorithm::Md5,    EVP_md5()    }
};

}

/**
 * Constructor.
 */
HashContext::HashContext() : _ctx(EVP_MD_CTX_create()), _currentAlgo(nullptr)
{
}

/**
 * Destructor.
 */
HashContext::~HashContext()
{
	EVP_MD_CTX_destroy(_ctx);
}

/**
 * Initializes hashing context with specified algorithm.
 * This method should be called whenever we start to hash
 * new set of data.
 *
 * @param algorithm Hashing algorithm to use.
 *
 * @return @c true if success, otherwise @c false.
 */
bool HashContext::init(HashAlgorithm algorithm)
{
	auto itr = opensslAlgos.find(algorithm);
	if (itr == opensslAlgos.end())
		return false;

	_currentAlgo = itr->second;
	return EVP_DigestInit(_ctx, _currentAlgo) == 1;
}

/**
 * Adds the new data to hash.
 *
 * @param data Pointer to the start of data.
 * @param size Size of data.
 *
 * @return @c true if success, otherwise @c false.
 */
bool HashContext::addData(const std::uint8_t* data, std::size_t size)
{
	return EVP_DigestUpdate(_ctx, data, size) == 1;
}

/**
 * Adds the new data to hash.
 *
 * @param data Data to hash.
 *
 * @return @c true if success, otherwise @c false.
 */
bool HashContext::addData(const std::vector<std::uint8_t>& data)
{
	return addData(data.data(), data.size());
}

/**
 * Gets the final hash of all added data.
 *
 * @return The final hash of the algorithm. Empty string in case of an error.
 */
std::string HashContext::getHash()
{
	if (_currentAlgo == nullptr)
		return {};

	std::vector<std::uint8_t> hash(EVP_MD_size(_currentAlgo));
	if (EVP_DigestFinal(_ctx, hash.data(), nullptr) != 1)
		return {};

	std::string ret;
	retdec::utils::bytesToHexString(hash, ret);
	return ret;
}

} // namespace crypto
} // namespace retdec
