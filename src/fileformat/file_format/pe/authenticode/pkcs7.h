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
#include <iostream> /* remove */
#include <ctime>
#include <optional>
#include <cstdint>
#include <exception>

namespace authenticode {

/* Idea to name this Authenticode as Authenticode itself seems useless
	and Authenticode really is just Pkcs7 will specific constraints */
class Pkcs7
{
private:
	PKCS7* pkcs7;
	SpcIndirectDataContent* spc_content;
	std::uint64_t version;
	void parse_signer_info(PKCS7_SIGNER_INFO* si_info);
	void parse_certificates(PKCS7_SIGNER_INFO* info);
	STACK_OF(X509)* get_certificates() const;
	STACK_OF(X509)* get_signers();
	PKCS7_SIGNED* get_signed_data() const;
	retdec::fileformat::Certificate convert_certificate(X509Certificate cert);

public:
	std::optional<X509Certificate> signer;
	std::vector<X509Certificate> certificates;
	std::vector<Pkcs7> nested_signatures;
	std::vector<Pkcs9> counter_signatures;

	Pkcs7(std::vector<unsigned char> input);
	~Pkcs7();
	const char* get_digest_algorithm() const;
	std::vector<std::uint8_t> get_signed_digest() const;
	std::uint64_t get_version() const;
	std::vector<retdec::fileformat::DigitalSignature> get_signatures() const;
	// std::vector<MsCounterSignature> ms_counter_signatures;
};

} // namespace authenticode