/**
 * @file src/fileformat/file_format/pe/authenticode/pkcs7.cpp
 * @brief Class wrapper above openssl Pkcs7
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "pkcs7.h"
#include "authenticode_structs.h"
#include "retdec/fileformat/types/certificate_table/certificate_table.h"
#include <exception>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/pkcs7.h>
#include <openssl/safestack.h>
#include <openssl/ts.h>
#include <stdexcept>
#include <cstring>

using namespace retdec::fileformat;

static const int NID_spc_nested_signature =
		OBJ_create("1.3.6.1.4.1.311.2.4.1", "spcNestedSignature", "SPC_NESTED_SIGNATURE (Authenticode)");
static const int NID_spc_ms_countersignature =
		OBJ_create("1.3.6.1.4.1.311.3.3.1", "spcMsCountersignature", "SPC_MICROSOFT_COUNTERSIGNATURE (Authenticode)");
static const int NID_spc_indirect_data =
		OBJ_create("1.3.6.1.4.1.311.2.1.4", "spcIndirectData", "SPC_INDIRECT_DATA (Authenticode)");
static const int NID_spc_sp_opus_info_objid =
		OBJ_create("1.3.6.1.4.1.311.2.1.12)", "SPC_SP_OPUS_INFO_OBJID", "SPC_SP_OPUS_INFO_OBJID (Authenticode)");

namespace authenticode {

/* This translating functions could be replaced by OBJ_nid2ln() ? */
static std::string algorithmToString(Algorithms alg)
{
	switch (alg) {
	case Algorithms::MD5:
		return LN_md5;
	case Algorithms::SHA1:
		return LN_sha1;
	case Algorithms::SHA224:
		return LN_sha224;
	case Algorithms::SHA256:
		return LN_sha256;
	case Algorithms::SHA384:
		return LN_sha384;
	case Algorithms::SHA512:
		return LN_sha512;
	case Algorithms::MD5_RSA:
		return LN_md5WithRSAEncryption;
	case Algorithms::SHA1_RSA:
		return LN_sha1WithRSAEncryption;
	case Algorithms::SHA224_RSA:
		return LN_sha224WithRSAEncryption;
	case Algorithms::SHA256_RSA:
		return LN_sha256WithRSAEncryption;
	case Algorithms::SHA384_RSA:
		return LN_sha384WithRSAEncryption;
	case Algorithms::SHA512_RSA:
		return LN_sha512WithRSAEncryption;
	case Algorithms::RSA:
		return LN_rsaEncryption;
	case Algorithms::DSA:
		return LN_dsa;
	default:
		throw std::runtime_error("Unsupported algorithm");
	}
}

static Algorithms asn1ToAlgorithm(ASN1_OBJECT* obj)
{
	int nid = OBJ_obj2nid(obj);
	switch (nid) {
	case static_cast<int>(Algorithms::MD5):
	case static_cast<int>(Algorithms::SHA1):
	case static_cast<int>(Algorithms::SHA224):
	case static_cast<int>(Algorithms::SHA256):
	case static_cast<int>(Algorithms::SHA384):
	case static_cast<int>(Algorithms::SHA512):
	case static_cast<int>(Algorithms::MD5_RSA):
	case static_cast<int>(Algorithms::SHA1_RSA):
	case static_cast<int>(Algorithms::SHA224_RSA):
	case static_cast<int>(Algorithms::SHA256_RSA):
	case static_cast<int>(Algorithms::SHA384_RSA):
	case static_cast<int>(Algorithms::SHA512_RSA):
	case static_cast<int>(Algorithms::RSA):
	case static_cast<int>(Algorithms::DSA):
		return static_cast<Algorithms>(nid);
	default:
		throw std::runtime_error("Unsupported digest algorithm in indirect data content");
	}
}

/* If PKCS7 cannot be created it throws otherwise returns valid pointer */
static PKCS7* getPkcs7(std::vector<unsigned char> input)
{
	BIO* bio = BIO_new(BIO_s_mem());
	if (!bio || BIO_reset(bio) != 1 ||
			BIO_write(bio, input.data(), static_cast<int>(input.size())) != static_cast<std::int64_t>(input.size())) {
		BIO_free(bio);
		return NULL;
	}

	PKCS7* pkcs7 = d2i_PKCS7_bio(bio, nullptr);
	if (!pkcs7) {
		BIO_free(bio);
		return NULL;
	}
	return pkcs7;
}

static std::vector<Certificate> createFileformatChain(std::vector<X509Certificate> chain)
{
	std::vector<Certificate> fileformat_chain;
	for (auto&& cert : chain) {
		fileformat_chain.push_back(cert.createCertificate());
	}
	return fileformat_chain;
}

Pkcs7::ContentInfo::ContentInfo(const PKCS7* pkcs7)
	: contentType("SpcIndirectDataContent")
{
	/* SignedData contentType must be set to SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4) */
	if (OBJ_obj2nid(pkcs7->d.sign->contents->type) != NID_spc_indirect_data) {
		throw std::runtime_error("Invalid Authenticode Content Info type");
	}

	size_t len = pkcs7->d.sign->contents->d.other->value.sequence->length;
	const unsigned char* data = pkcs7->d.sign->contents->d.other->value.sequence->data;

	spcContent = d2i_SpcIndirectDataContent(nullptr, &data, len);

	if (!spcContent) {
		throw std::runtime_error("Couldn't parse the ContentInfo");
	}

	digest = std::vector<std::uint8_t>(spcContent->messageDigest->digest->data,
			spcContent->messageDigest->digest->data + spcContent->messageDigest->digest->length);

	digestAlgorithm = asn1ToAlgorithm(spcContent->messageDigest->digestAlgorithm->algorithm);
}

/**
 * @brief Parses out bytes into a PKCS7 and other objects that are stored inside (countersignatures etc.)
 * 
 * @param input 
 */
Pkcs7::Pkcs7(std::vector<unsigned char>& input)
{
	/* 
	SignedData ::= SEQUENCE {
	    version Version, (Must be 1)
	    digestAlgorithms DigestAlgorithmIdentifiers,
	    contentInfo ContentInfo,
	    certificates
	        [0] IMPLICIT ExtendedCertificatesAndCertificates
	        OPTIONAL,
	    Crls
	        [1] IMPLICIT CertificateRevocationLists OPTIONAL, (Not used in AC)
	    signerInfos SignerInfos }
	
	    DigestAlgorithmIdentifiers ::=  (1 structure for each signer)
	         SET OF DigestAlgorithmIdentifier
	
	    ContentInfo ::= SEQUENCE {
	        contentType ContentType,
	        content (Must be SpcIndirectDataContent)
	            [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }

	   ContentType ::= OBJECT IDENTIFIER
	   SignerInfos ::= SET OF SignerInfo (Only one signer is supported)
	
	Source for the parsing constraints is in the MS Authenticode spec
	https://www.symbolcrash.com/wp-content/uploads/2019/02/Authenticode_PE-1.pdf
	*/
	pkcs7 = getPkcs7(input);
	if (!pkcs7) {
		throw std::runtime_error("Couldn't parse the data as PKCS#7");
	}

	/* Authenticode uses SignedData Pkcs7 type, check if that complies */
	if (!PKCS7_type_is_signed(pkcs7)) {
		throw std::runtime_error("Invalid Authenticode PKCS#7 type");
	}

	STACK_OF(X509_ALGOR)* algos = pkcs7->d.sign->md_algs;
	/* Must be exactly 1 signer and for each signer there is one algorithm */
	if (sk_X509_ALGOR_num(algos) != 1) {
		throw std::runtime_error("Invalid number of DigestAlgorithmIdentifiers");
	}
	X509_ALGOR* contentAlgo = sk_X509_ALGOR_value(algos, 0);
	contentDigestAlgorithm = asn1ToAlgorithm(contentAlgo->algorithm);

	/* Parse the content info */
	contentInfo = ContentInfo(pkcs7);

	ASN1_INTEGER_get_uint64(&version, pkcs7->d.sign->version);
	/* Version has to be equal to 1 */
	if (version != 1) {
		throw std::runtime_error("Invalid Authenticode version");
	}

	/* Parse the certificate data into internal structures */
	STACK_OF(X509)* certs = getCertificates();

	int cert_count = sk_X509_num(certs);
	for (size_t i = 0; i < cert_count; i++) {
		X509Certificate cert(sk_X509_value(certs, i));
		certificates.push_back(cert);
	}

	signerInfo = SignerInfo(pkcs7, certs);
}

static std::string serialToString(ASN1_INTEGER* serial)
{
	BIGNUM* bignum = ASN1_INTEGER_to_BN(serial, nullptr);

	BIO* bio = BIO_new(BIO_s_mem());
	BN_print(bio, bignum);
	auto data_len = BIO_number_written(bio);

	std::vector<char> result(data_len);
	BIO_read(bio, static_cast<void*>(result.data()), data_len);
	return { result.begin(), result.end() };
}

static std::string X509NameToString(X509_NAME* name)
{
	BIO* bio = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
	auto str_size = BIO_number_written(bio);

	std::string result(str_size, '\0');
	BIO_read(bio, (void*)result.data(), result.size());
	return result;
}

Pkcs7::SignerInfo::SignerInfo(PKCS7* pkcs7, STACK_OF(X509)* raw_certs)
{
	/*
	SignerInfo ::= SEQUENCE {
	   version Version,
	   issuerAndSerialNumber IssuerAndSerialNumber,
	   digestAlgorithm DigestAlgorithmIdentifier,
	   authenticatedAttributes
	       [0] IMPLICIT Attributes OPTIONAL,
	   digestEncryptionAlgorithm
	       DigestEncryptionAlgorithmIdentifier,
	   encryptedDigest EncryptedDigest,
	   unauthenticatedAttributes
	       [1] IMPLICIT Attributes OPTIONAL }
	IssuerAndSerialNumber ::= SEQUENCE {
	   issuer Name,
	   serialNumber CertificateSerialNumber }
	EncryptedDigest ::= OCTET STRING
	*/
	/*
		"Because Authenticode signatures support only one signer,"
		https://www.symbolcrash.com/wp-content/uploads/2019/02/Authenticode_PE-1.pdf page 7 
	*/

	STACK_OF(PKCS7_SIGNER_INFO)* signer_infos = PKCS7_get_signer_info(pkcs7);
	if (!signer_infos) {
		throw std::runtime_error("Couldn't parse signers");
	}

	if (sk_PKCS7_SIGNER_INFO_num(signer_infos) != 1) {
		throw std::runtime_error("Invalid number of Signers - Authenticode supports single Signer");
	}

	PKCS7_SIGNER_INFO* si_info = sk_PKCS7_SIGNER_INFO_value(signer_infos, 0);

	X509_ALGOR* digestAlgo = si_info->digest_alg;
	X509_ALGOR* digestEncryptAlgo = si_info->digest_enc_alg;

	digestAlgorithm = asn1ToAlgorithm(digestAlgo->algorithm);
	digestEncryptAlgorithm = asn1ToAlgorithm(digestEncryptAlgo->algorithm);

	/* Get the signer certificate */
	STACK_OF(X509)* raw_signers = PKCS7_get0_signers(pkcs7, raw_certs, 0);
	/* TODO maybe don't throw on no signers? And just leave the signatures empty? */
	if (!raw_signers) {
		throw std::runtime_error("Couldn't parse any signers");
	}

	int signers_count = sk_X509_num(raw_signers);
	/* This by logic shouldn't happen as above we established there is single SignerInfo,
	   but I am not completely sure so I'll keep it here for a while */
	if (signers_count != 1) {
		throw std::runtime_error("Invalid number of Signers - Authenticode supports single Signer");
	}
	signerCert = sk_X509_value(raw_signers, 0);

	encryptDigest = std::vector<std::uint8_t>(si_info->enc_digest->data,
			si_info->enc_digest->data + si_info->enc_digest->length);

	ASN1_INTEGER_get_uint64(&version, si_info->version);

	serial = serialToString(si_info->issuer_and_serial->serial);
	issuer = X509NameToString(si_info->issuer_and_serial->issuer);
	
	parseUnauthAttrs(si_info, raw_certs);
	parseAuthAttrs(si_info);
}
void Pkcs7::SignerInfo::parseAuthAttrs(PKCS7_SIGNER_INFO* si_info)
{
	for (int j = 0; j < sk_X509_ATTRIBUTE_num(si_info->auth_attr); ++j) {
		X509_ATTRIBUTE* attr = sk_X509_ATTRIBUTE_value(si_info->auth_attr, j);
		ASN1_TYPE* attr_type = X509_ATTRIBUTE_get0_type(attr, 0);
		ASN1_OBJECT* attr_object = X509_ATTRIBUTE_get0_object(attr);

		if (!attr_object) {
			continue; // Does this happen?
		}
		auto attr_object_nid = OBJ_obj2nid(attr_object);
		char buf[100]; /* 100 should be more than enough for any oid - openssl docs */
		if (attr_object_nid == NID_pkcs9_contentType) {
			/* 
			 ContentType ::= OBJECT IDENTIFIER 
			*/
			OBJ_obj2txt(buf, 100, attr_type->value.object, 0);
			contentType = std::string(buf, buf + strlen(buf));
		} 
		else if (attr_object_nid == NID_pkcs9_messageDigest) {
			/*
			 MessageDigest ::= OCTET STRING
			*/
			messageDigest = std::string(attr_type->value.asn1_string->data,
					attr_type->value.asn1_string->data + attr_type->value.asn1_string->length);
		}
		else if (attr_object_nid == NID_spc_sp_opus_info_objid) {
			/*
			SpcSpOpusInfo ::= SEQUENCE {
			    programName [0] EXPLICIT SpcString OPTIONAL,
			    moreInfo    [1] EXPLICIT SpcLink OPTIONAL,
		    } --#public--
			 */
			spcInfo = d2i_SpcSpOpusInfo(nullptr,
					(const unsigned char**)&attr_type->value.sequence->data,
					attr_type->value.sequence->length);
		}
	}
}
void Pkcs7::SignerInfo::parseUnauthAttrs(PKCS7_SIGNER_INFO* si_info, STACK_OF(X509)* raw_certs)
{
	for (int j = 0; j < sk_X509_ATTRIBUTE_num(si_info->unauth_attr); ++j) {
		X509_ATTRIBUTE* attr = sk_X509_ATTRIBUTE_value(si_info->unauth_attr, j);
		ASN1_TYPE* attr_type = X509_ATTRIBUTE_get0_type(attr, 0);
		ASN1_OBJECT* attr_object = X509_ATTRIBUTE_get0_object(attr);
		if (!attr_object) {
			continue;
		}
		auto attr_object_nid = OBJ_obj2nid(attr_object);

		if (attr_object_nid == NID_spc_nested_signature) {
			std::vector<unsigned char> nested_sig_data(attr_type->value.sequence->data,
					attr_type->value.sequence->data + attr_type->value.sequence->length);

			nestedSignatures.push_back(Pkcs7(nested_sig_data));
		}
		else if (attr_object_nid == NID_pkcs9_countersignature) {
			std::vector<unsigned char> countersig_data(attr_type->value.sequence->data,
					attr_type->value.sequence->data + attr_type->value.sequence->length);

			counterSignatures.push_back(Pkcs9(countersig_data, raw_certs));
		}
		// else if (attr_object_nid == NID_spc_ms_countersignature) {

		// }
	}
}

X509* Pkcs7::SignerInfo::getSignerCert() const
{
	return signerCert;
}

STACK_OF(X509)* Pkcs7::getSigners()
{
	return PKCS7_get0_signers(pkcs7, pkcs7->d.sign->cert, 0);
}

STACK_OF(X509)* Pkcs7::getCertificates() const
{
	return pkcs7->d.sign->cert;
}

std::vector<DigitalSignature> Pkcs7::getSignatures() const
{
	std::vector<DigitalSignature> signatures;

	CertificateProcessor processor;

	DigitalSignature signature{
		.signed_digest = contentInfo.digest,
		.digest_algorithm = algorithmToString(contentInfo.digestAlgorithm),
	};

	STACK_OF(X509)* certs = getCertificates();

	std::vector<X509Certificate> chain = processor.getChain(signerInfo.getSignerCert(), certs);
	auto fileformat_chain = createFileformatChain(chain);

	/* Authenticode has a single signer */
	signature.signers.push_back(Signer{
			.chain = fileformat_chain });
	Signer sigs;
	for (auto&& counter_sig : signerInfo.counterSignatures) {
		CertificateProcessor processor;
		// TODO fix chain creation it's wrongly ordered probably
		auto chain = processor.getChain(counter_sig.getX509(), certs);
		auto fileformat_chain = createFileformatChain(chain);
		signature.signers[0].counter_signers.push_back(Signer{ .chain = fileformat_chain });
	}
	signatures.push_back(signature);

	for (auto&& nested_pkcs7 : signerInfo.nestedSignatures) {
		auto nested_sigs = nested_pkcs7.getSignatures();
		signatures.insert(signatures.end(), nested_sigs.begin(), nested_sigs.end());
	}

	return signatures;
}

Pkcs7::~Pkcs7()
{
	// you can't free it as the data is used outside and is not copied ?
	// figure how to handle it (probably just copy it)
	// PKCS7_free(pkcs7);
}

} // namespace authenticode