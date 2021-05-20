/**
 * @file src/fileformat/file_format/pe/authenticode/ms_counter_signature.h
 * @brief Representation of MsCounterSignature
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#pragma once

#include "helper.h"

#include <memory>
#include <openssl/bio.h>
#include <openssl/pkcs7.h>

#include <cstdint>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <string>
#include <vector>
#include <cstring>

namespace authenticode {

class MsCounterSignature
{
	std::unique_ptr<PKCS7, decltype(&PKCS7_free)> pkcs7;
	std::unique_ptr<TS_TST_INFO, decltype(&TS_TST_INFO_free)> tstInfo;
	std::unique_ptr<STACK_OF(X509), decltype(&sk_X509_free)> signers;
	TS_MSG_IMPRINT* imprint = nullptr;

public:
	const X509* signCert = nullptr;
	const STACK_OF(X509)* certs = nullptr;

	std::string signTime;
	std::vector<std::uint8_t> messageDigest;
	int digestAlgorithm = 0;

	std::vector<std::string> verify(const std::vector<std::uint8_t>& sig_enc_content) const;
	MsCounterSignature(const std::vector<std::uint8_t>& data);
};

} // namespace authenticode
