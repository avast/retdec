/**
 * @file src/fileformat/types/certificate_table/certificate.cpp
 * @brief Class for one certificate.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include <unordered_map>
#include <vector>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/types/certificate_table/certificate.h"
#include "retdec/fileformat/utils/conversions.h"

namespace retdec {
namespace fileformat {

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

const std::string& Certificate::getOnelineSubject() const
{
	return subjectOneline;
}
const std::string& Certificate::getOnelineIssuer() const
{
	return issuerOneline;
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
