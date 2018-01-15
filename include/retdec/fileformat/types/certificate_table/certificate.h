/**
 * @file include/retdec/fileformat/types/certificate_table/certificate.h
 * @brief Class for one certificate.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_CERTIFICATE_TABLE_CERTIFICATE_H
#define RETDEC_FILEFORMAT_TYPES_CERTIFICATE_TABLE_CERTIFICATE_H

#include <string>

#include <openssl/x509.h>

namespace retdec {
namespace fileformat {

/**
 * One certificate
 */
class Certificate
{
	public:
		struct Attributes
		{
			std::string country;
			std::string organization;
			std::string organizationalUnit;
			std::string nameQualifier;
			std::string state;
			std::string commonName;
			std::string serialNumber;
			std::string locality;
			std::string title;
			std::string surname;
			std::string givenName;
			std::string initials;
			std::string pseudonym;
			std::string generationQualifier;
			std::string emailAddress;
		};
	private:
		X509 *certImpl;
		std::string validSince;
		std::string validUntil;
		std::string publicKey;
		std::string publicKeyAlgo;
		std::string signatureAlgo;
		std::string serialNumber;
		std::string sha1Digest;
		std::string sha256Digest;
		std::string subjectRaw;
		std::string issuerRaw;
		Attributes subject;
		Attributes issuer;

		void load();
		void loadValidity();
		void loadPublicKey();
		void loadSignatureAlgorithm();
		void loadSerialNumber();
		void loadIssuerAndSubject();
		void calculateHashes();
	public:
		Certificate(X509 *cert);
		~Certificate();

		/// @name Getters
		/// @{
		const std::string& getValidSince() const;
		const std::string& getValidUntil() const;
		const std::string& getPublicKey() const;
		const std::string& getPublicKeyAlgorithm() const;
		const std::string& getSignatureAlgorithm() const;
		const std::string& getSerialNumber() const;
		const std::string& getSha1Digest() const;
		const std::string& getSha256Digest() const;
		const std::string& getRawSubject() const;
		const std::string& getRawIssuer() const;
		const Certificate::Attributes& getSubject() const;
		const Certificate::Attributes& getIssuer() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
