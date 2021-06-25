/**
 * @file src/fileformat/file_format/pe/authenticode/x509_certificate.h
 * @brief Class that wraps openssl x509 certificate information.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#pragma once

#include "retdec/fileformat/types/certificate_table/certificate.h"
#include "retdec/fileformat/types/certificate_table/certificate_table.h"
#include "helper.h"

#include <memory>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <openssl/x509_vfy.h>
#include <string>
#include <vector>
#include <ctime>
#include <iomanip>

using retdec::fileformat::Certificate;

namespace authenticode {

class X509Certificate
{ /* Can't name it X509 due to the collisions with openssl*/
private:
	const X509* cert = nullptr;

public:
	X509Certificate(const X509* cert);
	X509Certificate() = default;

	int getVersion() const;
	std::string getValidUntil() const;
	std::string getValidSince() const;
	std::string getRawSubject() const;
	std::string getRawIssuer() const;
	std::string getOnelineSubject() const;
	std::string getOnelineIssuer() const;
	std::string getSerialNumber() const;
	std::string getSignatureAlgorithm() const;
	std::string getPublicKey() const;
	std::string getPublicKeyAlgorithm() const;
	std::string getPem() const;
	std::string getSignature() const;
	std::string getSha1() const;
	std::string getSha256() const;
	Certificate::Attributes getSubject() const;
	Certificate::Attributes getIssuer() const;
	Certificate createCertificate() const;
};

class CertificateProcessor
{
private:
	std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> trust_store;
	std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx;

public:
	std::vector<X509Certificate> chain;

	CertificateProcessor();

	std::vector<X509Certificate> getChain(const X509* cert, const STACK_OF(X509)* all_certs);
	const X509_STORE* getStore() const;
};

} // namespace authenticode
