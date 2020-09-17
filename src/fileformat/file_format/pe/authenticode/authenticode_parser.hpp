#ifndef SIG_PARSER_H
#define SIG_PARSER_H

#include "authenticode_structs.hpp"
#include "certificate.hpp"

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <vector>
#include <string>
#include <cstdint>
#include <iostream> /* remove */
#include <ctime>

enum class HashType
{
	MD5,
	SHA1,
	SHA256,
	SHA384,
	SHA512
};

class Pkcs9
{
public:
	Pkcs9(std::vector<unsigned char> data, STACK_OF(X509) *certificates);
	void print();
	X509 *certificate;
private:
	PKCS7_SIGNER_INFO *countersign_info;
};

class Pkcs7 {
private:
	PKCS7 *pkcs7;
	SpcIndirectDataContent *spc_content;
	std::vector<unsigned char> bytes;
	void parse_signer_info (PKCS7_SIGNER_INFO *si_info, STACK_OF(X509 *) certs);
	void parse_certificates (PKCS7_SIGNER_INFO *info);
public:
	Pkcs7 (std::vector<unsigned char> input);
	const char *get_digest_algorithm() const;
	STACK_OF(X509) *get_certificates() const;
	STACK_OF(X509) *get_signers();
	std::string get_signed_digest() const;
	void print();

	std::uint64_t version;
	// STACK_OF(X509) *certificates; useless because get_certificates()
	STACK_OF(PKCS7_SIGNER_INFO) *signer_infos;

	std::vector<Certificate> signers;
	std::vector<Certificate> certificates;
	std::vector<Pkcs7> nested_signatures;
	std::vector<Pkcs9> counter_signatures;
	// std::vector<MsCounterSignature> ms_counter_signatures;
	
};


#endif