/**
 * @file src/fileformat/types/certificate_table/certificate.cpp
 * @brief Class for one certificate.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <unordered_map>
#include <vector>

#include <openssl/pem.h>

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/types/certificate_table/certificate.h"
#include "retdec/fileformat/utils/conversions.h"

namespace retdec {
namespace fileformat {

namespace
{

enum : std::uint8_t
{
	ATTRIBUTE_COUNTRY = 0,
	ATTRIBUTE_ORGANIZATION,
	ATTRIBUTE_ORGANIZATIONAL_UNIT,
	ATTRIBUTE_NAME_QUALIFIER,
	ATTRIBUTE_STATE,
	ATTRIBUTE_COMMON_NAME,
	ATTRIBUTE_SERIAL_NUMBER,
	ATTRIBUTE_LOCALITY,
	ATTRIBUTE_TITLE,
	ATTRIBUTE_SURNAME,
	ATTRIBUTE_GIVEN_NAME,
	ATTRIBUTE_INITIALS,
	ATTRIBUTE_PSEUDONYM,
	ATTRIBUTE_GENERATION_QUALIFIER,
	ATTRIBUTE_EMAIL_ADDRESS
};

static const std::unordered_map<std::string, std::uint8_t> attrTable =
{
	{ "C",                   ATTRIBUTE_COUNTRY },
	{ "O",                   ATTRIBUTE_ORGANIZATION },
	{ "OU",                  ATTRIBUTE_ORGANIZATIONAL_UNIT },
	{ "dnQualifier",         ATTRIBUTE_NAME_QUALIFIER },
	{ "ST",                  ATTRIBUTE_STATE },
	{ "CN",                  ATTRIBUTE_COMMON_NAME },
	{ "serialNumber",        ATTRIBUTE_SERIAL_NUMBER },
	{ "L",                   ATTRIBUTE_LOCALITY },
	{ "title",               ATTRIBUTE_TITLE },
	{ "SN",                  ATTRIBUTE_SURNAME },
	{ "GN",                  ATTRIBUTE_GIVEN_NAME },
	{ "initials",            ATTRIBUTE_INITIALS },
	{ "pseudonym",           ATTRIBUTE_PSEUDONYM },
	{ "generationQualifier", ATTRIBUTE_GENERATION_QUALIFIER },
	{ "emailAddress",        ATTRIBUTE_EMAIL_ADDRESS },
};

template <typename T, typename Deleter>
decltype(auto) managedPtr(T* ptr, Deleter deleter)
{
	return std::unique_ptr<T, Deleter>(ptr, deleter);
}

void assignAttribute(Certificate::Attributes *attributes, const std::string &key, const std::string &value)
{
	auto itr = attrTable.find(key);
	if(itr == attrTable.end())
	{
		return;
	}

	switch(itr->second)
	{
		case ATTRIBUTE_COUNTRY:
			attributes->country = value;
			break;
		case ATTRIBUTE_ORGANIZATION:
			attributes->organization = value;
			break;
		case ATTRIBUTE_ORGANIZATIONAL_UNIT:
			attributes->organizationalUnit = value;
			break;
		case ATTRIBUTE_NAME_QUALIFIER:
			attributes->nameQualifier = value;
			break;
		case ATTRIBUTE_STATE:
			attributes->state = value;
			break;
		case ATTRIBUTE_COMMON_NAME:
			attributes->commonName = value;
			break;
		case ATTRIBUTE_SERIAL_NUMBER:
			attributes->serialNumber = value;
			break;
		case ATTRIBUTE_LOCALITY:
			attributes->locality = value;
			break;
		case ATTRIBUTE_TITLE:
			attributes->title = value;
			break;
		case ATTRIBUTE_SURNAME:
			attributes->surname = value;
			break;
		case ATTRIBUTE_GIVEN_NAME:
			attributes->givenName = value;
			break;
		case ATTRIBUTE_INITIALS:
			attributes->initials = value;
			break;
		case ATTRIBUTE_PSEUDONYM:
			attributes->pseudonym = value;
			break;
		case ATTRIBUTE_GENERATION_QUALIFIER:
			attributes->generationQualifier = value;
			break;
		case ATTRIBUTE_EMAIL_ADDRESS:
			attributes->emailAddress = value;
			break;
		default:
			break;
	}
}

void parseAttributes(Certificate::Attributes *attributes, X509_NAME *raw)
{
	std::size_t numEntries = X509_NAME_entry_count(raw);
	for(std::size_t i = 0; i < numEntries; ++i)
	{
		auto nameEntry = X509_NAME_get_entry(raw, int(i));
		auto valueObj = X509_NAME_ENTRY_get_data(nameEntry);

		std::string key = OBJ_nid2sn(OBJ_obj2nid(X509_NAME_ENTRY_get_object(nameEntry)));
		std::string value = std::string(reinterpret_cast<const char*>(valueObj->data), valueObj->length);

		assignAttribute(attributes, key, value);
	}
}

std::string parsePublicKey(BIO *bio)
{
	std::string key;
	std::vector<char> tmp(100);

	BIO_gets(bio, tmp.data(), 100);
	if(std::string(tmp.data()) != "-----BEGIN PUBLIC KEY-----\n")
	{
		return key;
	}

	while(true)
	{
		BIO_gets(bio, tmp.data(), 100);
		if(std::string(tmp.data()) == "-----END PUBLIC KEY-----\n")
		{
			break;
		}

		key += tmp.data();
		key.erase(key.length() - 1, 1); // Remove last character (whitespace)
	}

	return key;
}

std::string parseDateTime(ASN1_TIME* dateTime)
{
	if (ASN1_TIME_check(dateTime) == 0)
		return {};

	auto memBio = managedPtr(BIO_new(BIO_s_mem()), &BIO_free);
	ASN1_TIME_print(memBio.get(), dateTime);

	BUF_MEM* bioMemPtr;
	BIO_ctrl(memBio.get(), BIO_C_GET_BUF_MEM_PTR, 0, reinterpret_cast<char*>(&bioMemPtr));

	return std::string(bioMemPtr->data, bioMemPtr->length);
}

} // anonymous namespace

/**
 * Constructor
 */
Certificate::Certificate(X509* cert) : certImpl(cert)
{
	load();
}

/**
 * Destructor
 */
Certificate::~Certificate()
{
}

void Certificate::load()
{
	loadValidity();
	loadPublicKey();
	loadSignatureAlgorithm();
	loadSerialNumber();
	loadIssuerAndSubject();
	calculateHashes();
}

void Certificate::loadValidity()
{
	validSince = parseDateTime(X509_get_notBefore(certImpl));
	validUntil = parseDateTime(X509_get_notAfter(certImpl));
}

void Certificate::loadPublicKey()
{
	publicKey.clear();
	publicKeyAlgo.clear();

	auto pubKey = managedPtr(X509_get_pubkey(certImpl), &EVP_PKEY_free);
	if(!pubKey)
		return;

	auto memBio = managedPtr(BIO_new(BIO_s_mem()), &BIO_free);

	PEM_write_bio_PUBKEY(memBio.get(), pubKey.get());
	publicKey = parsePublicKey(memBio.get());

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	publicKeyAlgo = OBJ_nid2sn(EVP_PKEY_base_id(pubKey.get()));
#else
	publicKeyAlgo = OBJ_nid2sn(OBJ_obj2nid(certImpl->cert_info->key->algor->algorithm));
#endif
}

void Certificate::loadSignatureAlgorithm()
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	signatureAlgo = OBJ_nid2sn(X509_get_signature_nid(certImpl));
#else
	signatureAlgo = OBJ_nid2sn(OBJ_obj2nid(certImpl->sig_alg->algorithm));
#endif
}

void Certificate::loadSerialNumber()
{
	if (auto sn = X509_get_serialNumber(certImpl))
		retdec::utils::bytesToHexString(sn->data, sn->length, serialNumber);
}

void Certificate::loadIssuerAndSubject()
{
	if (auto subjectName = X509_get_subject_name(certImpl))
	{
		auto subjectNameOneline = managedPtr(X509_NAME_oneline(subjectName, nullptr, 0), &free);
		subjectRaw = subjectNameOneline.get();

		parseAttributes(&subject, subjectName);
	}

	if (auto issuerName = X509_get_issuer_name(certImpl))
	{
		auto issuerNameOneline = managedPtr(X509_NAME_oneline(issuerName, nullptr, 0), &free);
		issuerRaw = issuerNameOneline.get();

		parseAttributes(&issuer, issuerName);
	}
}

void Certificate::calculateHashes()
{
	std::vector<char> tmp(0x2000);
	auto memBio = managedPtr(BIO_new(BIO_s_mem()), &BIO_free);

	i2d_X509_bio(memBio.get(), certImpl);
	std::size_t certLen = BIO_read(memBio.get(), tmp.data(), int(tmp.size()));
	tmp.resize(certLen);

	std::vector<std::uint8_t> sha1Bytes(SHA_DIGEST_LENGTH), sha256Bytes(SHA256_DIGEST_LENGTH);
	SHA1(reinterpret_cast<const unsigned char*>(tmp.data()), tmp.size(), sha1Bytes.data());
	SHA256(reinterpret_cast<const unsigned char*>(tmp.data()), tmp.size(), sha256Bytes.data());

	retdec::utils::bytesToHexString(sha1Bytes, sha1Digest);
	retdec::utils::bytesToHexString(sha256Bytes, sha256Digest);
}

/**
 * Get date since when is certificate valid
 * @return Date since when is certificate valid
 */
const std::string& Certificate::getValidSince() const
{
	return validSince;
}

/**
 * Get date until when is certificate valid
 * @return Date until when is certificate valid
 */
const std::string& Certificate::getValidUntil() const
{
	return validUntil;
}

/**
 * Get public key of the certificate
 * @return Public key
 */
const std::string& Certificate::getPublicKey() const
{
	return publicKey;
}

/**
 * Get algorithm of public key of the certificate
 * @return Public key algorithm
 */
const std::string& Certificate::getPublicKeyAlgorithm() const
{
	return publicKeyAlgo;
}

/**
 * Get signature algorithm of the certificate
 * @return Signature algorithm
 */
const std::string& Certificate::getSignatureAlgorithm() const
{
	return signatureAlgo;
}

/**
 * Get serial number of the certificate
 * @return Serial number
 */
const std::string& Certificate::getSerialNumber() const
{
	return serialNumber;
}

/**
 * Get SHA1 digest of the certificate
 * @return SHA1 digest
 */
const std::string& Certificate::getSha1Digest() const
{
	return sha1Digest;
}

/**
 * Get SHA256 digest of the certificate
 * @return SHA256 digest
 */
const std::string& Certificate::getSha256Digest() const
{
	return sha256Digest;
}

/**
 * Get subject of certificate in form of raw string
 * @return Subject of certificate
 */
const std::string& Certificate::getRawSubject() const
{
	return subjectRaw;
}

/**
 * Get issuer of certificate in form of raw string
 * @return Issuer of certificate
 */
const std::string& Certificate::getRawIssuer() const
{
	return issuerRaw;
}

/**
 * Get subject of certificate in form of attributes
 * @return Subject of certificate
 */
const Certificate::Attributes& Certificate::getSubject() const
{
	return subject;
}

/**
 * Get issuer of certificate in form of attributes
 * @return Issuer of certificate
 */
const Certificate::Attributes& Certificate::getIssuer() const
{
	return issuer;
}

} // namespace fileformat
} // namespace retdec
