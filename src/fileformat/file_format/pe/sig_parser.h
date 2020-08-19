#ifndef SIG_PARSER_H
#define SIG_PARSER_H

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>

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

class Pkcs7 {
private:
	PKCS7 *pkcs7;
	std::vector<unsigned char> bytes;
	void parse_signer_info (PKCS7_SIGNER_INFO *info);
	void parse_certificates (PKCS7_SIGNER_INFO *info);
public:
	Pkcs7 (std::vector<unsigned char> input);
	HashType get_digest_algorithm() const;

	STACK_OF(X509) *certificates;
	STACK_OF(X509) *signers;
	STACK_OF(PKCS7_SIGNER_INFO) *signer_infos;
	std::uint64_t version;
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