/**
 * @file src/fileformat/file_format/pe/authenticode/pkcs9_counter_signature.cpp
 * @brief Class that wraps openssl pkcs9 information.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "pkcs9_counter_signature.h"
#include "authenticode_structs.h"
#include <openssl/objects.h>
namespace authenticode {

/* PKCS7 stores all certificates for the signer and counter signers, we need to pass the certs */
Pkcs9CounterSignature::Pkcs9CounterSignature(std::vector<std::uint8_t>& data, const STACK_OF(X509)* certificates)
	: sinfo(nullptr, PKCS7_SIGNER_INFO_free)
{
	/*
		counterSignature ATTRIBUTE ::= {
		  WITH SYNTAX SignerInfo
		  ID pkcs-9-at-counterSignature
		}
	*/
	const unsigned char* data_ptr = data.data();
	sinfo.reset(d2i_PKCS7_SIGNER_INFO(nullptr, &data_ptr, data.size()));
	if (!sinfo) {
		return;
	}

	digestAlgorithm = OBJ_obj2nid(sinfo->digest_alg->algorithm);

	/* get the signer certificate of this counter signatures */
	signerCert = X509_find_by_issuer_and_serial(const_cast<STACK_OF(X509)*>(certificates),
			sinfo->issuer_and_serial->issuer, sinfo->issuer_and_serial->serial);

	if (!signerCert) {
		return;
	}

	for (int i = 0; i < sk_X509_ATTRIBUTE_num(sinfo->auth_attr); ++i) {
		X509_ATTRIBUTE* attribute = sk_X509_ATTRIBUTE_value(sinfo->auth_attr, i);
		ASN1_OBJECT* attribute_object = X509_ATTRIBUTE_get0_object(attribute);
		ASN1_TYPE* attr_type = X509_ATTRIBUTE_get0_type(attribute, 0);
		/* 
			Note 2 - A countersignature, since it has type SignerInfo, can itself
			contain a countersignature attribute.  Thus it is possible to
			construct arbitrarily long series of countersignatures.
		*/
		if (OBJ_obj2nid(attribute_object) == NID_pkcs9_countersignature) {
			auto data = std::vector<std::uint8_t>(attr_type->value.octet_string->data,
					attr_type->value.octet_string->data + attr_type->value.octet_string->length);
			counterSignatures.emplace_back(data, certificates);
		}
		else if (OBJ_obj2nid(attribute_object) == NID_pkcs9_contentType) {
			contentType = OBJ_nid2sn(NID_pkcs9_contentType);
		}

		/* Signing Time (1.2.840.113549.1.9.5) is set to the UTC time of timestamp generation time. */
		else if (OBJ_obj2nid(attribute_object) == NID_pkcs9_signingTime) {
			signTime = parseDateTime(attr_type->value.utctime);
		}
		/* 
			Message Digest (1.2.840.113549.1.9.4) is set to the hash value of the SignerInfo structure's
			encryptedDigest value. The hash algorithm that is used to calculate the hash value is the same
			as that specified in the SignerInfo structure’s digestAlgorithm value of the timestamp.

			MessageDigest ::= OCTET STRING
		*/
		else if (OBJ_obj2nid(attribute_object) == NID_pkcs9_messageDigest) {
			messageDigest = std::vector<std::uint8_t>(attr_type->value.octet_string->data,
					attr_type->value.octet_string->data + attr_type->value.octet_string->length);
		}
	}
}

std::vector<std::string> Pkcs9CounterSignature::verify(const std::vector<uint8_t>&  sig_enc_content) const
{
	std::vector<std::string> warnings;
	if (!sinfo) {
		warnings.emplace_back("Couldn't parse counter-signature.");
		return warnings;
	}

	if (!signerCert) {
		warnings.emplace_back("No counter-signature certificate");
		return warnings;
	}

	if (contentType.empty()) {
		warnings.emplace_back("Missing pkcs9 contentType");
	}

	std::uint8_t* data = nullptr;
	auto len = ASN1_item_i2d((ASN1_VALUE*)sinfo->auth_attr, &data, ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));

	const EVP_MD* md = EVP_get_digestbyobj(sinfo->digest_alg->algorithm);
	if (!md) {
		warnings.emplace_back("Unknown digest algorithm");
		return warnings;
	}
	std::uint8_t digest[EVP_MAX_MD_SIZE] = { 0 };
	calculateDigest(md, data, len, digest);
	free(data);

	std::uint8_t* enc_data = sinfo->enc_digest->data;
	int enc_len = sinfo->enc_digest->length;

	auto pkey = X509_get0_pubkey(signerCert);
	auto ctx = EVP_PKEY_CTX_new(pkey, nullptr);

	std::size_t dec_len = 65536;
	std::vector<std::uint8_t> dec_data(dec_len);

	EVP_PKEY_verify_recover_init(ctx);
	bool is_recovered = EVP_PKEY_verify_recover(ctx, dec_data.data(), &dec_len, enc_data, enc_len) == 1;
	EVP_PKEY_CTX_free(ctx);

	if (is_recovered) {
		int md_len = EVP_MD_size(md);
		/* compare the encrypted digest and calculated digest */
		bool is_valid = false;

		/* Sometimes signed data contains DER encoded DigestInfo structure which 
		contains hash of authenticated attributes but other times it is just purely 
		hash and I don't think there's other way to distinguish it but only based on 
		the length of data we get */

		if (md_len == dec_len) {
			is_valid = !std::memcmp(digest, dec_data.data(), md_len);
		}
		else {
			const std::uint8_t* data_ptr = dec_data.data();
			DigestInfo* digest_info = d2i_DigestInfo(nullptr, &data_ptr, dec_len);
			is_valid = !std::memcmp(digest_info->digest->data, digest, md_len);
			DigestInfo_free(digest_info);
		}
		if (!is_valid) {
			warnings.emplace_back("Failed to verify the counter-signature");
		}
	} else {
		warnings.emplace_back("Couldn't decrypt the digest");
	}

	/* compare the saved, now verified digest attribute with the signature that it counter signs */
	if (messageDigest.empty()) {
		warnings.emplace_back("Message digest is missing");
	}
	else {
		std::memset(digest, 0, EVP_MAX_MD_SIZE);

		calculateDigest(md, sig_enc_content.data(), sig_enc_content.size(), digest);
		if (std::memcmp(digest, messageDigest.data(), messageDigest.size())) {
			warnings.emplace_back("Failed to verify the signature with counter-signature");
		}
	}

	return warnings;
}

} // namespace authenticode
