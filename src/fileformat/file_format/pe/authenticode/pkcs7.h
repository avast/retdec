/**
 * @file src/fileformat/file_format/pe/authenticode/pkcs7.h
 * @brief Class wrapper above openssl Pkcs7
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#pragma once

#include "authenticode_structs.h"
#include "x509_certificate.h"
#include "pkcs9.h"

#include "retdec/fileformat/types/certificate_table/certificate_table.h"

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>

#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <ctime>
#include <optional>
#include <cstdint>
#include <exception>

namespace authenticode {

class Pkcs7
{
private:
	PKCS7* pkcs7;
	SpcIndirectDataContent* spcContent;
	std::uint64_t version;
	void parseSignerInfo(PKCS7_SIGNER_INFO* si_info);
	void parseCertificates(PKCS7_SIGNER_INFO* info);
	STACK_OF(X509)* getCertificates() const;
	STACK_OF(X509)* getSigners();
public:
	std::optional<X509Certificate> signer;
	std::vector<X509Certificate> certificates;
	std::vector<Pkcs7> nestedSignatures;
	/* add ms counter signetures TODO */
	std::vector<Pkcs9> counterSignatures;

	std::uint64_t getVersion() const;
	std::string getDigestAlgorithm() const;
	std::vector<std::uint8_t> getSignedDigest() const;
	std::vector<retdec::fileformat::DigitalSignature> getSignatures() const;

	Pkcs7(std::vector<unsigned char> input);
	~Pkcs7();
};

} // namespace authenticode