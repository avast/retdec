/**
 * @file src/fileformat/file_format/pe/authenticode/ms_nested_signature.cpp
 * @brief Representation of MsCounterSignature
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "ms_counter_signature.h"
#include <openssl/ossl_typ.h>
#include <openssl/x509_vfy.h>

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
		return;
	}
	certs = pkcs7->d.sign->cert;
	signCert = sk_X509_value(signers.get(), 0);
	imprint = TS_TST_INFO_get_msg_imprint(tstInfo.get());

	ASN1_STRING* raw_digest = TS_MSG_IMPRINT_get_msg(imprint);
	messageDigest = std::vector<std::uint8_t>(raw_digest->data, raw_digest->data + raw_digest->length);
}

std::vector<std::string> MsCounterSignature::verify(std::vector<std::uint8_t> sig_enc_content) const
{
	std::vector<std::string> warnings;

	X509_ALGOR* digest_algo = TS_MSG_IMPRINT_get_algo(imprint);
	const EVP_MD* md = EVP_get_digestbyobj(digest_algo->algorithm);
	if (!md) {
		warnings.emplace_back("Unknown digest algorithm");
		return warnings;
	}

	if (messageDigest.empty()) {
		warnings.emplace_back("Failed to verify the counter-signature, no message digest.");
	}

	std::uint8_t digest[EVP_MAX_MD_SIZE] = { 0 };
	calculateDigest(md, sig_enc_content.data(), sig_enc_content.size(), digest);

	int md_len = EVP_MD_size(md);
	if (std::memcmp(digest, messageDigest.data(), md_len)) {
		warnings.emplace_back("Failed to verify the counter-signature");
	}

	TS_VERIFY_CTX* ctx = TS_VERIFY_CTX_new();
	TS_VERIFY_CTX_init(ctx);
	TS_VERIFY_CTX_set_flags(ctx, TS_VFY_SIGNATURE | TS_VFY_VERSION | TS_VFY_IMPRINT);

	X509_STORE* store = X509_STORE_new();
	TS_VERIFY_CTX_set_store(ctx, store);
	TS_VERIFY_CTS_set_certs(ctx, pkcs7->d.sign->cert);
	TS_VERIFY_CTX_set_imprint(ctx, digest, md_len);
	bool is_valid = TS_RESP_verify_token(ctx, pkcs7.get()) == 1;
	if (!is_valid) {
		warnings.emplace_back("Failed to verify the counter-signature");
	}

	/* Remove these members as the free function wants to deallocate them also, better than to dup them */
	TS_VERIFY_CTX_set_imprint(ctx, nullptr, 0);
	TS_VERIFY_CTS_set_certs(ctx, nullptr);

	TS_VERIFY_CTX_free(ctx);

	return warnings;
}

} // namespace authenticode