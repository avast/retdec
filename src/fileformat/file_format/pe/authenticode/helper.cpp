/**
 * @file src/fileformat/file_format/pe/authenticode/helper.cpp
 * @brief Helper functions used for Authenticode components
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#include "helper.h"

namespace authenticode {

std::string parsePublicKey(BIO* bio)
{
	std::string key;
	std::vector<char> tmp(100);

	BIO_gets(bio, tmp.data(), 100);
	if (std::string(tmp.data()) != "-----BEGIN PUBLIC KEY-----\n") {
		return key;
	}

	while (true) {
		BIO_gets(bio, tmp.data(), 100);
		if (std::string(tmp.data()) == "-----END PUBLIC KEY-----\n") {
			break;
		}

		key += tmp.data();
		key.erase(key.length() - 1, 1); // Remove last character (whitespace)
	}

	return key;
}

/* Calculates md digest type from data, result is a written into 
   digest that has to be large enough to accomodate whole digest */
void calculateDigest(const EVP_MD* md, std::uint8_t* data, int len, std::uint8_t* digest)
{
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, data, len);
	EVP_DigestFinal_ex(mdctx, digest, NULL);
	EVP_MD_CTX_free(mdctx);
}

std::string bytesToHexString(const std::uint8_t* in, int len)
{
	const std::uint8_t* end = in + len;
	std::ostringstream oss;
	for (; in != end; ++in)
		oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*in);
	return oss.str();
}

std::string parseDateTime(const ASN1_TIME* dateTime)
{
	if (ASN1_TIME_check(dateTime) == 0)
		return {};

	BIO* memBio = BIO_new(BIO_s_mem());
	ASN1_TIME_print(memBio, dateTime);

	BUF_MEM* bioMemPtr;
	BIO_ctrl(memBio, BIO_C_GET_BUF_MEM_PTR, 0, reinterpret_cast<char*>(&bioMemPtr));

	std::string result(bioMemPtr->data, bioMemPtr->length);
	BIO_free_all(memBio);
	return result;
}
std::string serialToString(ASN1_INTEGER* serial)
{
	BIGNUM* bignum = ASN1_INTEGER_to_BN(serial, nullptr);

	BIO* bio = BIO_new(BIO_s_mem());
	BN_print(bio, bignum);
	auto data_len = BIO_number_written(bio);

	std::vector<char> result(data_len);
	BIO_read(bio, static_cast<void*>(result.data()), data_len);

	BIO_free_all(bio);
	BN_free(bignum);
	return { result.begin(), result.end() };
}

std::string X509NameToString(X509_NAME* name)
{
	BIO* bio = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
	auto str_size = BIO_number_written(bio);

	std::string result(str_size, '\0');
	BIO_read(bio, (void*)result.data(), result.size());
	BIO_free_all(bio);
	return result;
}

/* This translating functions could be replaced by OBJ_nid2ln() ? */
std::string algorithmToString(Algorithms alg)
{
	switch (alg) {
	case Algorithms::MD5:
		return LN_md5;
	case Algorithms::SHA1:
		return LN_sha1;
	case Algorithms::SHA224:
		return LN_sha224;
	case Algorithms::SHA256:
		return LN_sha256;
	case Algorithms::SHA384:
		return LN_sha384;
	case Algorithms::SHA512:
		return LN_sha512;
	case Algorithms::MD5_RSA:
		return LN_md5WithRSAEncryption;
	case Algorithms::SHA1_RSA:
		return LN_sha1WithRSAEncryption;
	case Algorithms::SHA224_RSA:
		return LN_sha224WithRSAEncryption;
	case Algorithms::SHA256_RSA:
		return LN_sha256WithRSAEncryption;
	case Algorithms::SHA384_RSA:
		return LN_sha384WithRSAEncryption;
	case Algorithms::SHA512_RSA:
		return LN_sha512WithRSAEncryption;
	case Algorithms::RSA:
		return LN_rsaEncryption;
	case Algorithms::DSA:
		return LN_dsa;
	default:
		return "";
	}
}

Algorithms asn1ToAlgorithm(ASN1_OBJECT* obj)
{
	/* maybe just have Algorithms as a typedef to nid ? */
	int nid = OBJ_obj2nid(obj);
	return static_cast<Algorithms>(nid);
}

/* If PKCS7 cannot be created it throws otherwise returns valid pointer */
PKCS7* getPkcs7(const std::vector<unsigned char>& input)
{
	BIO* bio = BIO_new(BIO_s_mem());
	if (!bio || BIO_reset(bio) != 1 ||
			BIO_write(bio, input.data(), static_cast<int>(input.size())) != static_cast<std::int64_t>(input.size())) {
		BIO_free(bio);
		return NULL;
	}

	PKCS7* pkcs7 = d2i_PKCS7_bio(bio, nullptr);
	if (!pkcs7) {
		BIO_free(bio);
		return NULL;
	}
	BIO_free(bio);

	return pkcs7;
}

} // namespace authenticode