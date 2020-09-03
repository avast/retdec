#ifndef SIG_PARSER_H
#define SIG_PARSER_H

#include "authenticode_structs.hpp"

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>
#include <openssl/x509.h>

#include <vector>
#include <string>
#include <cstdint>
#include <iostream> /* remove */

enum class HashType
{
	MD5,
	SHA1,
	SHA256,
	SHA384,
	SHA512
};

// class Authenticode {
// private:
// 	PKCS7 *pkcs7;
// 	std::vector<unsigned char> bytes;
// 	void parse_signer_info (PKCS7_SIGNER_INFO *info);
// 	void parse_certificates (PKCS7_SIGNER_INFO *info);
// public:
// 	Authenticode (std::vector<unsigned char> input);
// 	HashType get_digest_algorithm() const;
// };

class Pkcs9
{
public:
	Pkcs9(std::vector<unsigned char> data);
private:
	PKCS7_SIGNER_INFO *countersign_info;
};

class Pkcs7 {
private:
	PKCS7 *pkcs7;
	SpcIndirectDataContent *spc_content;
	std::vector<unsigned char> bytes;
	void parse_signer_info (PKCS7_SIGNER_INFO *info);
	void parse_certificates (PKCS7_SIGNER_INFO *info);
public:
	Pkcs7 (std::vector<unsigned char> input);
	HashType get_digest_algorithm() const;
	void print();
	STACK_OF(X509) *certificates;
	STACK_OF(X509) *signers;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_infos;
	std::uint64_t version;

	std::vector<Pkcs7> nested_signatures;
	std::vector<Pkcs9> counter_signatures;
	// std::vector<MsCounterSignature> ms_counter_signatures;
};


class Certificate {
private:
	X509 *cert;
public:
	std::string issuer_name();
	std::string serial();
	std::string signature_algorithm();
	std::string subject_name();
};

#endif