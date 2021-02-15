/**
 * @file src/fileformat/file_format/pe/authenticode/pkcs7.cpp
 * @brief Class wrapper above openssl Pkcs7
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "pkcs7.h"
#include "helper.h"

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

/* naming is hard */
static std::vector<Certificate> convertToFileformatCertChain(std::vector<X509Certificate> chain)
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

	auto* spcContent = SpcIndirectDataContent_new();
	if (!spcContent) {
		throw std::runtime_error("Couldn't allocate the ContentInfo");
	}

	d2i_SpcIndirectDataContent(&spcContent, &data, len); /* this leak but I SpcIndirectDataContent_free() segfaults.... */

	if (!spcContent) {
		throw std::runtime_error("Couldn't parse the ContentInfo");
	}

	digest = bytesToHexString(spcContent->messageDigest->digest->data, spcContent->messageDigest->digest->length);

	digestAlgorithm = asn1ToAlgorithm(spcContent->messageDigest->digestAlgorithm->algorithm);

	SpcIndirectDataContent_free(spcContent);
}

/**
 * @brief Parses out bytes into a PKCS7 and other objects that are stored inside (countersignatures etc.)
 * 
 * @param input 
 */
Pkcs7::Pkcs7(const std::vector<unsigned char>& input) noexcept
	: pkcs7(nullptr, PKCS7_free)
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
	pkcs7.reset(getPkcs7(input));

	if (!pkcs7) {
		warnings.emplace_back("Couldn't parse the data as PKCS#7");
		return;
	}

	/* Authenticode uses SignedData Pkcs7 type, check if that complies */
	if (!PKCS7_type_is_signed(pkcs7)) {
		warnings.emplace_back("Invalid Authenticode PKCS#7 type");
	}

	STACK_OF(X509_ALGOR)* algos = pkcs7->d.sign->md_algs;
	/* Must be exactly 1 signer and for each signer there is one algorithm */
	if (sk_X509_ALGOR_num(algos) != 1) {
		warnings.emplace_back("Invalid number of DigestAlgorithmIdentifiers: " + std::to_string(sk_X509_ALGOR_num(algos)) + " - should be 1.");
	}

	X509_ALGOR* contentAlgo = sk_X509_ALGOR_value(algos, 0);
	contentDigestAlgorithm = asn1ToAlgorithm(contentAlgo->algorithm);

	/* Parse the content info */
	contentInfo = ContentInfo(pkcs7.get());

	ASN1_INTEGER_get_uint64(&version, pkcs7->d.sign->version);
	/* Version has to be equal to 1 */
	if (version != 1) {
		warnings.emplace_back("Invalid Pkcs7 version: " + std::to_string(version) + " - should be 1.");
	}

	/* Parse the certificate data into internal structures */
	STACK_OF(X509)* certs = getCertificates();

	int cert_count = sk_X509_num(certs);
	for (size_t i = 0; i < cert_count; i++) {
		X509Certificate cert(sk_X509_value(certs, i));
		certificates.push_back(cert);
	}
	signerInfo.emplace(pkcs7.get(), certs);
}

Pkcs7::SignerInfo::SignerInfo(PKCS7* pkcs7, STACK_OF(X509)* raw_certs)
	: raw_signers(nullptr, sk_X509_free)
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
	raw_signers.reset(PKCS7_get0_signers(pkcs7, raw_certs, 0));

	/* TODO maybe don't throw on no signers? And just leave the signatures empty? */
	if (!raw_signers) {
		throw std::runtime_error("Couldn't parse any signers");
	}

	int signers_count = sk_X509_num(raw_signers.get());
	/* This by logic shouldn't happen as above we established there is single SignerInfo,
	   but I am not completely sure so I'll keep it here for a while */
	if (signers_count != 1) {
		throw std::runtime_error("Invalid number of Signers - Authenticode supports single Signer");
	}
	signerCert = sk_X509_value(raw_signers.get(), 0);

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
			// spcInfo = SpcSpOpusInfo((const unsigned char*)attr_type->value.sequence->data, attr_type->value.sequence->length);
		}
	}
}

Pkcs7::SpcSpOpusInfo::SpcSpOpusInfo(const unsigned char* data, int len) noexcept
{
	// TODO
	/*
	SpcSpOpusInfo ::= SEQUENCE {
		programName [0] EXPLICIT SpcString OPTIONAL,
		moreInfo    [1] EXPLICIT SpcLink OPTIONAL,
	} --#public--
	*/
	::SpcSpOpusInfo* spcInfo = SpcSpOpusInfo_new();
	d2i_SpcSpOpusInfo(&spcInfo, &data, len);
	SpcSpOpusInfo_free(spcInfo);
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
			std::vector<std::uint8_t> nested_sig_data(attr_type->value.sequence->data,
					attr_type->value.sequence->data + attr_type->value.sequence->length);

			nestedSignatures.emplace_back(nested_sig_data);
		}
		else if (attr_object_nid == NID_pkcs9_countersignature) {
			std::vector<std::uint8_t> countersig_data(attr_type->value.sequence->data,
					attr_type->value.sequence->data + attr_type->value.sequence->length);

			counterSignatures.emplace_back(countersig_data, raw_certs);
		}
		else if (attr_object_nid == NID_spc_ms_countersignature) {
			std::vector<std::uint8_t> countersig_data(attr_type->value.sequence->data,
					attr_type->value.sequence->data + attr_type->value.sequence->length);

			msSignatures.emplace_back(countersig_data);
		}
	}
}

const X509* Pkcs7::SignerInfo::getSignerCert() const
{
	return signerCert;
}

STACK_OF(X509)* Pkcs7::getSigners()
{
	return PKCS7_get0_signers(pkcs7.get(), pkcs7->d.sign->cert, 0);
}

STACK_OF(X509)* Pkcs7::getCertificates() const
{
	return pkcs7->d.sign->cert;
}

/* TODO move all the processing into ctor? */
std::vector<DigitalSignature> Pkcs7::getSignatures() const
{
	std::vector<DigitalSignature> signatures;

	CertificateProcessor processor;

	if (!signerInfo.has_value()) {
		// warnings.emplace_back("There is no signer in SignerInfos");
	}
	const SignerInfo& signInfo = signerInfo.value();

	STACK_OF(X509)* certs = getCertificates();
	const X509* signer_cert = signInfo.getSignerCert();
	if (!signer_cert) {
		// warnings.emplace_back("T1here is no signer certificate in SignerInfo");
	}

	std::vector<X509Certificate> chain = processor.getChain(signer_cert, certs);
	auto fileformat_chain = convertToFileformatCertChain(chain);

	DigitalSignature signature{
		.signedDigest = contentInfo.digest,
		.digestAlgorithm = algorithmToString(contentInfo.digestAlgorithm),
		.warnings = warnings,
	};

	/* Authenticode has a single signer */
	signature.signers.push_back(Signer{ .chain = fileformat_chain });

	for (auto&& counterSig : signInfo.counterSignatures) {
		CertificateProcessor processor;
		auto certChain = processor.getChain(counterSig.getX509(), certs);
		auto fileformatCertChain = convertToFileformatCertChain(certChain);

		signature.signers[0].counterSigners.push_back(Signer{ .chain = fileformatCertChain, .signingTime = counterSig.signingTime, .digest = counterSig.digest });
	}
	for (auto&& msCounterSig : signInfo.msSignatures) {
		CertificateProcessor processor;
		auto certChain = processor.getChain(msCounterSig.signCert, msCounterSig.certs);
		auto fileformatCertChain = convertToFileformatCertChain(certChain);

		signature.signers[0].counterSigners.push_back(Signer{ .chain = fileformatCertChain, .signingTime = msCounterSig.signTime, .digest = msCounterSig.digest });
	}

	signatures.push_back(signature);

	for (auto&& nestedPkcs7 : signInfo.nestedSignatures) {
		auto nestedSigs = nestedPkcs7.getSignatures();
		signatures.insert(signatures.end(), nestedSigs.begin(), nestedSigs.end());
	}

	return signatures;
}
} // namespace authenticode