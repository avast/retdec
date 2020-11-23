#include "pkcs7.h"
#include "retdec/fileformat/types/certificate_table/certificate_table.h"
#include <openssl/safestack.h>

using namespace retdec::fileformat;

namespace authenticode {

static const int NID_spc_nested_signature = 
	OBJ_create ("1.3.6.1.4.1.311.2.4.1", "spcNestedSignature", "SPC_NESTED_SIGNATURE (Authenticode)");
static const int NID_spc_ms_countersignature = 
	OBJ_create ("1.3.6.1.4.1.311.3.3.1", "spcMsCountersignature", "SPC_MICROSOFT_COUNTERSIGNATURE (Authenticode)");

static const char *hash_name_from_asn1(ASN1_OBJECT *obj) {
	switch (OBJ_obj2nid(obj)) {
	case NID_md5:                     return "MD5";
	case NID_md5WithRSAEncryption:    return "MD5WithRSA";
	case NID_sha1:                    return "SHA1";
	case NID_sha1WithRSAEncryption:   return "SHA1WithRSA";
	case NID_sha256:                  return "SHA256";
	case NID_sha256WithRSAEncryption: return "SHA256WithRSA";
	case NID_sha384:                  return "SHA384";
	case NID_sha384WithRSAEncryption: return "SHA384WithRSA";
	case NID_sha512:                  return "SHA512";
	case NID_sha512WithRSAEncryption: return "SHA512WithRSA";
	default:
		throw std::runtime_error("Invalid digest algorithm in indirect data content");
	}
}

/* If PKCS7 cannot be create throws otherwise returns valid pointer */
static PKCS7 *get_pkcs7_from_bytes(std::vector<unsigned char> input) {
	BIO *bio = BIO_new (BIO_s_mem ());
	if (!bio || BIO_reset (bio) != 1 ||
		BIO_write (bio, input.data (), static_cast<int> (input.size ())) != static_cast<std::int64_t> (input.size ())) {
		BIO_free (bio);
		throw std::exception ();
	}

	PKCS7 *pkcs7 = d2i_PKCS7_bio (bio, nullptr);
	if (!pkcs7) {
		BIO_free (bio);
		throw std::exception ();
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

	/* Authenticode specific PKCS #7 contentInfo member content 
	   contains file's hash avalue, page hash values, file description and
	   optional + legacy ASN.1 fields */
	spc_content = d2i_SpcIndirectDataContent (nullptr, &signed_data_raw, signed_data_len);
	if (!spc_content) {
		throw std::exception ();
	}

	STACK_OF(PKCS7_SIGNER_INFO) *signer_infos = PKCS7_get_signer_info (pkcs7);
	if (!signer_infos) {
		throw std::exception ();
	}

	/* Must contains single signerInfo by the specification, don't validate, just store for now*/
	if (sk_PKCS7_SIGNER_INFO_num (signer_infos) != 1) {
		throw std::exception ();
	}

	/* Version has to be equal to 1, but don't validate for now? */
	ASN1_INTEGER_get_uint64(&version, pkcs7->d.sign->version);

	STACK_OF (X509) *certs = get_certificates ();

	/* Parse the signer info part */
	parse_signer_info (sk_PKCS7_SIGNER_INFO_value (signer_infos, 0));

	/* Process certificates now */
	int cert_count = sk_X509_num (certs);
	for (size_t i = 0; i < cert_count; i++) {
		X509Certificate cert (sk_X509_value (certs, i));
		certificates.push_back (cert);
	}


	STACK_OF (X509) *raw_signers = PKCS7_get0_signers (pkcs7, certs, 0);
	if (raw_signers) {
		int signers_count = sk_X509_num (raw_signers);
		/* "Because Authenticode signatures support only one signer,"
		https://www.symbolcrash.com/wp-content/uploads/2019/02/Authenticode_PE-1.pdf page 7 */
		if (signers_count != 1) {
			throw std::exception();
		}
		signer = X509Certificate (sk_X509_value (raw_signers, 0));
	} else {
		throw std::exception(); // ??
	}
}

void Pkcs7::parse_signer_info (PKCS7_SIGNER_INFO *si_info) {
	/* SignerInfo contains
	* version == 1
	* IssuerAndSerialNumber
	* digestAlgorithm
	* authenticatedAttributes
	* digestEncryptionALgorithm
	* encryptedDigest
	* unauthenticatedAttributes */

	for (int j = 0; j < sk_X509_ATTRIBUTE_num (si_info->unauth_attr); ++j) {
		X509_ATTRIBUTE *attr = sk_X509_ATTRIBUTE_value (si_info->unauth_attr, j);
		ASN1_TYPE *attr_type = X509_ATTRIBUTE_get0_type (attr, 0);
		ASN1_OBJECT *attr_object = X509_ATTRIBUTE_get0_object (attr);
		if (!attr_object) {
			continue;
		}

		auto attr_object_nid = OBJ_obj2nid (attr_object);

		if (attr_object_nid == NID_spc_nested_signature) {
			std::vector<unsigned char> nested_sig_data (attr_type->value.sequence->data,
				attr_type->value.sequence->data + attr_type->value.sequence->length);
			nested_signatures.push_back (Pkcs7 (nested_sig_data));
		} else if (attr_object_nid == NID_pkcs9_countersignature /* ||
			/* attr_object_nid == NID_spc_ms_countersignature TODO */
		) {
			std::vector<unsigned char> countersig_data (attr_type->value.sequence->data,
				attr_type->value.sequence->data + attr_type->value.sequence->length);
			counter_signatures.push_back (Pkcs9 (countersig_data, get_certificates ()));
		}
	}
}

STACK_OF(X509) *Pkcs7::get_signers() {
	return PKCS7_get0_signers (pkcs7, pkcs7->d.sign->cert, 0);
}

STACK_OF (X509) *Pkcs7::get_certificates() const {
	return pkcs7->d.sign->cert;
}

const char *Pkcs7::get_digest_algorithm() const {
	return hash_name_from_asn1 (spc_content->messageDigest->digestAlgorithm->algorithm);
}

std::vector<std::uint8_t> Pkcs7::get_signed_digest() const {
	return std::vector<std::uint8_t> (spc_content->messageDigest->digest->data, spc_content->messageDigest->digest->data + spc_content->messageDigest->digest->length);
}

PKCS7_SIGNED *Pkcs7::get_signed_data() const {
	return pkcs7->d.sign;
}

std::uint64_t Pkcs7::get_version() const {
	return version;
}


std::vector<Certificate> create_fileformat_chain(std::vector<X509Certificate> chain) {
	std::vector<Certificate> fileformat_chain;
	for (auto &&cert : chain) {
		fileformat_chain.push_back (cert.createCertificate());
	}
	return fileformat_chain;
}

std::vector<DigitalSignature> Pkcs7::get_signatures() const 
{
	std::vector<DigitalSignature> signatures;

	CertificateProcessor processor;

	DigitalSignature signature {
		.signed_digest = get_signed_digest (),
		.digest_algorithm = get_digest_algorithm (),
	};
	/* X
	DANGER! nested signatures doesn't have to have their own certificates,
	I didn't know how to figure out if nested signatures can have their own 
	certificates, because I didn't know how to get the information thatD
	the pkcs7 has no certificates as pkcs7->d.sign->cert doesn't have to be NULL
	probably just gonna check openssl source?
	*/
	STACK_OF (X509) *certs = get_certificates();

	std::vector<X509Certificate> chain = processor.get_chain (signer.value().get_x509 (), certs);
	auto fileformat_chain = create_fileformat_chain(chain);

	/* Authenticode has a single signer */
	signature.signers.push_back(Signer {
		.chain = fileformat_chain
	});

	/* Are further counter signers signers of the previous counter signer????? */
	for (auto &&counter_sig : counter_signatures) {
		CertificateProcessor processor;
		auto chain = processor.get_chain (counter_sig.certificate, certs);
		auto fileformat_chain = create_fileformat_chain(chain);
		signature.signers[0].counter_signers.push_back(Signer {.chain = fileformat_chain});
	}
	signatures.push_back(signature);

	/* TODO deal with the naming weird stuff when we have pkcs7 and signatures as separate interfaces */
	for (auto &&nested_pkcs7 : nested_signatures) {
		auto nested_sigs = nested_pkcs7.get_signatures ();
		signatures.insert (signatures.end (), nested_sigs.begin (), nested_sigs.end ());
	}

	return signatures;
}

Pkcs7::~Pkcs7() {
	// you can't free it as the data is used outside and is not copied ?
	// figure how to handle it (probably just copy it)
	// PKCS7_free(pkcs7);
}

}