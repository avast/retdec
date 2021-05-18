/**
 * @file src/fileformat/file_format/pe/authenticode/pkcs9_counter_signature.h
 * @brief Class that wraps openssl pkcs9 information.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#pragma once

#include "authenticode_structs.h"
#include "x509_certificate.h"
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

#include <vector>
#include <string>
#include <cstdint>
#include <ctime>
#include <cstring>

namespace authenticode {

class Pkcs9CounterSignature
{
private:
	std::unique_ptr<PKCS7_SIGNER_INFO, decltype(&PKCS7_SIGNER_INFO_free)> sinfo;

public:
	const X509* signerCert = nullptr;

	std::string contentType;
	std::string signTime;
	std::vector<std::uint8_t> messageDigest;
	int digestAlgorithm = 0;
	std::vector<Pkcs9CounterSignature> counterSignatures;

	std::vector<std::string> verify(const std::vector<uint8_t>& sig_enc_content) const;
	Pkcs9CounterSignature(std::vector<std::uint8_t>& data, const STACK_OF(X509)* certificates);
};

} // namespace authenticode
