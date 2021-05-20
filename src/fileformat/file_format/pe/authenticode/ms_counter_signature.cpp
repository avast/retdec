/**
 * @file src/fileformat/file_format/pe/authenticode/ms_counter_signature.cpp
 * @brief Representation of MsCounterSignature
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#include "ms_counter_signature.h"
#include "x509_certificate.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
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

	X509_ALGOR* digest_algo = TS_MSG_IMPRINT_get_algo(imprint);
	digestAlgorithm = OBJ_obj2nid(digest_algo->algorithm);

	ASN1_STRING* raw_digest = TS_MSG_IMPRINT_get_msg(imprint);
	messageDigest = std::vector<std::uint8_t>(raw_digest->data, raw_digest->data + raw_digest->length);
}

std::vector<std::string> MsCounterSignature::verify(const std::vector<std::uint8_t>& sig_enc_content) const
{
	std::vector<std::string> warnings;

	if (!pkcs7) {
		warnings.emplace_back("Couldn't parse signature");
		return warnings;
	}

	if (messageDigest.empty()) {
		warnings.emplace_back("Failed to verify the counter-signature, no message digest");
		return warnings;
	}

	const EVP_MD* md = EVP_get_digestbynid(digestAlgorithm);
	if (!md) {
		warnings.emplace_back("Unknown digest algorithm");
		return warnings;
	}
	std::uint8_t digest[EVP_MAX_MD_SIZE] = { 0 };
	calculateDigest(md, sig_enc_content.data(), sig_enc_content.size(), digest);

	int md_len = EVP_MD_size(md);
	if (std::memcmp(digest, messageDigest.data(), md_len)) {
		warnings.emplace_back("Failed to verify the signature with counter-signature");
	}

	TS_VERIFY_CTX* ctx = TS_VERIFY_CTX_new();
	X509_STORE* store = X509_STORE_new();
	TS_VERIFY_CTX_init(ctx);

	TS_VERIFY_CTX_set_flags(ctx, TS_VFY_VERSION | TS_VFY_IMPRINT);
	TS_VERIFY_CTX_set_store(ctx, store);
	TS_VERIFY_CTS_set_certs(ctx, pkcs7->d.sign->cert);
	TS_VERIFY_CTX_set_imprint(ctx, digest, md_len);

	bool is_valid = TS_RESP_verify_token(ctx, pkcs7.get()) == 1;

	/* VERIFY_CTX_free tries to free these, we don't want that */
	TS_VERIFY_CTX_set_imprint(ctx, nullptr, 0);
	TS_VERIFY_CTS_set_certs(ctx, nullptr);

	TS_VERIFY_CTX_free(ctx);

	if (!is_valid) {
		warnings.emplace_back("Failed to verify the counter-signature");
	}

	/* Verify signature with PKCS7_signatureVerify
	   because TS_RESP_verify_token tries to verify
	   chain and without trust anchors it fails */
	BIO* p7bio = PKCS7_dataInit(pkcs7.get(), NULL);

	char buf[4096];
	/* We now have to 'read' from p7bio to calculate digests etc. */
	while (BIO_read(p7bio, buf, sizeof(buf)) > 0)
		continue;

	STACK_OF(PKCS7_SIGNER_INFO)* sinfos = PKCS7_get_signer_info(pkcs7.get());
	PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(sinfos, 0);

	is_valid = PKCS7_signatureVerify(p7bio, pkcs7.get(), si, const_cast<X509*>(signCert)) == 1;
	if (!is_valid) {
		warnings.emplace_back("Failed to verify the counter-signature");
	}

	BIO_free_all(p7bio);
	return warnings;
}

} // namespace authenticode
