#pragma once

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

namespace authenticode {

class Certificate { /* X509, can't name it X509 due to the collisions */
private:
	X509 *cert;
	std::string get_x509_name(X509_NAME *name) const;
public:
	Certificate (X509 *cert);
	std::string get_subject_string() const;
	std::string get_issuer_string() const;
	std::string get_serial_number() const;
	std::string get_signature_algorithm() const;
	std::string get_pem() const;
	EVP_PKEY *get_public_key() const;
	std::time_t get_not_before() const;
	std::time_t get_not_after() const;
	ASN1_INTEGER* get_serial_number_asn1() const;
	X509* get_x509() const;
	void print();
};

class CertificateProcessor {
private:
	X509_STORE *trust_store;
	X509_STORE_CTX *ctx;
public:
	std::vector<Certificate> chain;
	CertificateProcessor();
	std::vector<Certificate> get_chain(X509 *cert, STACK_OF(X509) *all_certs);
};

}