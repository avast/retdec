/**
 * @file src/fileformat/file_format/pe/authenticode/ms_nested_signature.cpp
 * @brief Representation of MsCounterSignature
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "ms_counter_signature.h"

namespace authenticode {

MsCounterSignature::MsCounterSignature(const std::vector<std::uint8_t>& data)
	: pkcs7(nullptr, PKCS7_free), tstInfo(nullptr, TS_TST_INFO_free), signers(nullptr, sk_X509_free)
{
	pkcs7.reset(getPkcs7(data));
	if (!pkcs7) {
		return;
	}

	tstInfo.reset(PKCS7_to_TS_TST_INFO(pkcs7.get()));
	if (!tstInfo) {
		return;
	}

	const ASN1_TIME* raw_time = TS_TST_INFO_get_time(tstInfo.get());

	if (raw_time) {
		signTime = parseDateTime(raw_time);
	}
	signers.reset(PKCS7_get0_signers(pkcs7.get(), pkcs7->d.sign->cert, 0));
	auto signerCount = sk_X509_num(signers.get());
	if (signerCount != 1) {
		throw std::runtime_error("Incorrect amount of signers, expected 1, has : " + std::to_string(signerCount));
	}

	signCert = sk_X509_value(signers.get(), 0);
	certs = pkcs7->d.sign->cert;
	TS_MSG_IMPRINT* imprint = TS_TST_INFO_get_msg_imprint(tstInfo.get());
	ASN1_STRING* raw_digest = TS_MSG_IMPRINT_get_msg(imprint);
	digest = bytesToHexString(raw_digest->data, raw_digest->length);
}

std::vector<std::string> MsCounterSignature::verify() const {
	std::vector<std::string> warnings;


	return warnings;
}

} // namespace authenticode