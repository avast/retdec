/**
 * @file src/fileformat/file_format/pe/authenticode/x509_certificate.h
 * @brief Class that wraps openssl x509 certificate information.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#pragma once

#include "retdec/fileformat/types/certificate_table/certificate.h"
#include "retdec/fileformat/types/certificate_table/certificate_table.h"

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <string>
#include <vector>
#include <ctime>
#include <iomanip>

using retdec::fileformat::Certificate;

namespace authenticode {

class X509Certificate
{ /* Can't name it X509 due to the collisions with openssl*/
private:
	X509* cert;
	std::string getX509Name(X509_NAME* name) const;

public:
	X509Certificate(X509* cert);
	X509Certificate() = default;

	X509* getX509() const;
	int getVersion() const;
	std::string getValidUntil() const;
	std::string getValidSince() const;
	std::string getRawSubject() const;
	std::string getRawIssuer() const;
	std::string getSerialNumber() const;
	std::string getSignatureAlgorithm() const;
	std::string getPublicKey() const;
	std::string getPublicKeyAlgorithm() const;
	std::string getPem() const;
	std::string getSignature() const;
	std::string getSha1() const; /* returns thumbprint of the complete certificate data */
	std::string getSha256() const;
	Certificate::Attributes getSubject() const;
	Certificate::Attributes getIssuer() const;
	Certificate createCertificate() const;
};

class CertificateProcessor
{
private:
	X509_STORE* trust_store;
	X509_STORE_CTX* ctx;

public:
	std::vector<X509Certificate> chain;

	CertificateProcessor();
	~CertificateProcessor();
	
	std::vector<X509Certificate> getChain(X509* cert, STACK_OF(X509)* all_certs);
};

} // namespace authenticode