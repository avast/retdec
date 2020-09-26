#include "pkcs7.hpp"

static const char *hash_name_from_asn1(ASN1_OBJECT *obj) {
	switch (OBJ_obj2nid(obj)) {
	case NID_md5:
		return "MD5";
	case NID_md5WithRSAEncryption:
		return "MD5WithRSA";
	case NID_sha1:
		return "SHA1";
	case NID_sha1WithRSAEncryption:
		return "SHA1WithRSA";
	case NID_sha256:
		return "SHA256";
	case NID_sha256WithRSAEncryption:
		return "SHA256WithRSA";
	case NID_sha384:
		return "SHA384";
	case NID_sha384WithRSAEncryption:
		return "SHA384WithRSA";
	case NID_sha512:
		return "SHA512";
	case NID_sha512WithRSAEncryption:
		return "SHA512WithRSA";
	default:
		throw std::runtime_error("Invalid digest algorithm in indirect data content");
	}
}

static PKCS7 *get_pkcs7_from_bytes(std::vector<unsigned char> input) {
	/* Wrap the input for B I/O for openssl */
	BIO *bio = BIO_new(BIO_s_mem());
	if(!bio || BIO_reset(bio) != 1 || BIO_write(bio, input.data(), static_cast<int>(input.size())) != static_cast<std::int64_t>(input.size()) )	{
		BIO_free(bio);
		/* Throw what if error?*/
		throw std::exception();
	}

	PKCS7 *pkcs7 = d2i_PKCS7_bio(bio, nullptr);
	if(!pkcs7) {
		BIO_free(bio);
		throw std::exception();
	}
	return pkcs7;
}


/**
 * @brief Parses out bytes into a PKCS7 and other objects that are stored inside (countersignatures etc.)
 * 
 * @param input 
 */
Pkcs7::Pkcs7(std::vector<unsigned char> input) {
	/*
		For Authenticode:
		Signed data (Pkcs7):
		- version must be set to 1:
		- DigestAlgorithms must have only 1 digestAlgorithmsIdentifier and must match the value in SignedInfos structure's digestAlgorithm member (otherwise tampered)
		- Content info:
			- contentType must be SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4).
			- content must be set to SpcIndirectDataContent
		- Certificates:
			- contains signed certificate and any intermediate certificates, typically no root certificate
			- If the Authenticode signature is timestamped, certificates contains certificates that verify the timestamp, might include root certificate
		- Crls is unused
		SignerInfos:
		- Signerinfos has only single SignerInfo structure
		SignedInfo:
		- Version is set to 1
		- IssuerAndSerial contains issuerAndSerialNumber structure (issuer name and serial of signing certificate)
		- digestAlgorithm must match the parent SignedData digestAlgorithm, authenticode supports:
			- SHA1 (1.3.14.3.2.26)
			- MD5 (1.2.840.113549.2.5) - for backwards compatibility
		- AuthenticodeAttributes:
			- contenType (1.2.840.113549.1.9.3) contains messageDigest OID
			- MessageDigest contains octet string with hash value
			- SPC_SP_OPUS_INFO_OBJID (1.3.6.1.4.1.311.2.1.12)
		- digestEncryptionAlgorithm OID that specifies the signature algorithm (RSA || DSA)
		- encryptedDigest - signature by the signing certificate private key
		- unauthenticatedAttributes
	*/
	pkcs7 = get_pkcs7_from_bytes (input);

	size_t signed_data_len = pkcs7->d.sign->contents->d.other->value.sequence->length;
	const unsigned char *signed_data_raw = pkcs7->d.sign->contents->d.other->value.sequence->data;

	spc_content = d2i_SpcIndirectDataContent(nullptr, &signed_data_raw, signed_data_len);
	if (!spc_content) {
		throw std::exception(); 
	} 

	signer_infos = PKCS7_get_signer_info (pkcs7);

	/* Must be 1 by the specification */
	if (!signer_infos || sk_PKCS7_SIGNER_INFO_num (signer_infos) != 1) {
		throw std::exception(); 
	}

	STACK_OF(X509) *certs = get_certificates ();
 
	/* Parse the signer info part */
	parse_signer_info (sk_PKCS7_SIGNER_INFO_value (signer_infos, 0), certs);
	/* Process certificates now */
	int cert_count = sk_X509_num (certs);
	for (size_t i = 0; i < cert_count; i++) {
		Certificate cert (sk_X509_value (certs, i));
		certificates.push_back (cert);
	}
	/*  */
	STACK_OF(X509) *raw_signers = PKCS7_get0_signers (pkcs7, certs, 0);
	if (raw_signers) {
		int signers_count = sk_X509_num (raw_signers);
		for (size_t i = 0; i < signers_count; i++) {
			Certificate cert (sk_X509_value (raw_signers, i));
			signers.push_back (cert);
		}
	}
}

#define SPC_NESTED_SIGNATURE_OBJID  "1.3.6.1.4.1.311.2.4.1"
#define SPC_NESTED_SIGNATURE_NAME "spcNestedSignature"

void Pkcs7::parse_signer_info (PKCS7_SIGNER_INFO *si_info, STACK_OF(X509) *certs) {
	/* SignerInfo contains
	- Signed hash of contentInfo
	- Publisher description and URL (optional)
	- Timestamp (optional)
		- If timestamp exists it needs to have counter-signer to confirm */
	for (int j = 0; j < sk_X509_ATTRIBUTE_num(si_info->unauth_attr); ++j)
	{
		X509_ATTRIBUTE *attr = sk_X509_ATTRIBUTE_value (si_info->unauth_attr, j);
		ASN1_TYPE *attr_type = X509_ATTRIBUTE_get0_type (attr, 0);
		ASN1_OBJECT *attr_object = X509_ATTRIBUTE_get0_object (attr);
		if (!attr_object) {
			continue;
		}
		
		auto attr_object_nid = OBJ_obj2nid(attr_object);

		static const int NID_spc_nested_signature =  OBJ_create ("1.3.6.1.4.1.311.2.4.1",
			SPC_NESTED_SIGNATURE_NAME, "SPC_NESTED_SIGNATURE (Authenticode)");
		static const int NID_spc_ms_countersignature = OBJ_create("1.3.6.1.4.1.311.3.3.1",
			"spcMsCountersignature", "SPC_MICROSOFT_COUNTERSIGNATURE (Authenticode)");

		if (attr_object_nid == NID_spc_nested_signature) {
			std::vector<unsigned char> nested_sig_data (attr_type->value.sequence->data,
				attr_type->value.sequence->data + attr_type->value.sequence->length);
			nested_signatures.push_back (Pkcs7 (nested_sig_data));
		} else if (attr_object_nid == NID_pkcs9_countersignature /* ||
			/* attr_object_nid == NID_spc_ms_countersignature TODO */ ) {
			std::vector<unsigned char> countersig_data (attr_type->value.sequence->data,
				attr_type->value.sequence->data + attr_type->value.sequence->length);
			counter_signatures.push_back (Pkcs9 (countersig_data, certs));
		}
	}
}

STACK_OF(X509) *Pkcs7::get_signers() {
	return PKCS7_get0_signers (pkcs7, pkcs7->d.sign->cert, 0);
}

STACK_OF(X509) *Pkcs7::get_certificates() const
{
	return pkcs7->d.sign->cert;
}


const char *Pkcs7::get_digest_algorithm() const {
	return hash_name_from_asn1 (spc_content->messageDigest->digestAlgorithm->algorithm);
}

std::string Pkcs7::get_signed_digest() const {
	return std::string ((char *)spc_content->messageDigest->digest->data, spc_content->messageDigest->digest->length);
}

void Pkcs7::print() {
	std::cout << "** Signature: **\n " << std::endl;
	std::cout << "File hash algoritm :" << get_digest_algorithm () << std::endl;
	std::cout << "Signed hash        : " << get_signed_digest () << std::endl; /* fix - TODO decode*/

	for (auto &&cert : signers) {
		std::cout << "   Signature:" << std::endl;
		CertificateProcessor processor;
		auto chain = processor.get_chain (cert.get_x509 (), get_certificates ());
		for (auto &&c : chain) {
			c.print();
		}
	}

	for (auto &&sig : counter_signatures) {
		std::cout << "   Counter Signature " << std::endl;
		CertificateProcessor processor;
		auto chain = processor.get_chain (sig.certificate, get_certificates ());
		for (auto &&c : chain) {
			c.print();
		}
	}
	
	for (auto &&nested_sig : nested_signatures) {
		nested_sig.print();
	}
}