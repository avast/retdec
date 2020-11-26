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
#include <iostream>
#include <filesystem>

using retdec::fileformat::Certificate;

namespace authenticode {

class X509Certificate
{ /* X509, can't name it X509 due to the collisions */
private:
	X509* cert;
	std::string get_x509_name(X509_NAME* name) const;

public:
	X509Certificate(X509* cert);
	EVP_PKEY* get_public_key() const;
	ASN1_INTEGER* get_serial_number_asn1() const;

	std::string getValidUntil() const;
	std::string getValidSince() const;
	std::string getRawSubject() const;
	std::string getRawIssuer() const;
	std::string getSerialNumber() const;
	std::string getSignatureAlgorithm() const;
	std::string getPublicKey() const;
	std::string getPublicKeyAlgorithm() const;
	std::string getPem() const;
	Certificate::Attributes getSubject() const;
	Certificate::Attributes getIssuer() const;
	Certificate createCertificate() const;
	X509* get_x509() const;
};

class CertificateProcessor
{
private:
	X509_STORE* trust_store;
	X509_STORE_CTX* ctx;

public:
	std::vector<X509Certificate> chain;
	CertificateProcessor();
	std::vector<X509Certificate> get_chain(X509* cert, STACK_OF(X509)* all_certs);
};

} // namespace authenticode