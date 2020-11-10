#pragma once

#include "authenticode_structs.h"
#include "certificate.h"
#include "signature.h"
#include "pkcs9.h"

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <iostream> /* remove */
#include <ctime>
#include <optional>

namespace authenticode {

class Pkcs7 {
private:
	PKCS7 *pkcs7;
	SpcIndirectDataContent *spc_content;
	std::uint64_t version;
	void parse_signer_info(PKCS7_SIGNER_INFO *si_info);
	void parse_certificates(PKCS7_SIGNER_INFO *info);
	STACK_OF(X509) *get_certificates() const;
	STACK_OF(X509) *get_signers();
	PKCS7_SIGNED *get_signed_data() const;
public:
	std::optional<Certificate> signer;
	std::vector<Certificate> certificates;
	std::vector<Pkcs7> nested_signatures;
	std::vector<Pkcs9> counter_signatures;

	Pkcs7(std::vector<unsigned char> input);
	~Pkcs7();
	const char *get_digest_algorithm() const;
	std::vector<std::uint8_t> get_signed_digest() const;
	std::uint64_t get_version() const;
	std::vector<Signature> get_signatures();
	// std::vector<MsCounterSignature> ms_counter_signatures;
};

}