#include "sig_parser.h"

#define SHA1_BYTES 20
#define SHA256_BYTES 32

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

	signer_infos = PKCS7_get_signer_info (pkcs7);
	/* Must be 1 be the specification */
	if (!signer_infos || sk_PKCS7_SIGNER_INFO_num (signer_infos) != 1) {
		throw std::exception(); 
	} 
	/* Parse the signer info part */
	parse_signer_info (sk_PKCS7_SIGNER_INFO_value (signer_infos, 0));

	/* signed info */
	// PKCS7_
	signers = PKCS7_get0_signers (pkcs7, NULL, 0);
	if (!signers) {
		return;
	}
	/* parse version */
	ASN1_INTEGER_get_uint64(&version, pkcs7->d.sign->version);
	std::cout << "** Version: "  << version << std::endl;
	// unsigned char thumbprint[SHA256_BYTES];
	// char thumbprint_ascii[SHA256_BYTES * 2 + 1];
	// char buffer[256];

	// const EVP_MD* sha1_digest = EVP_sha1 ();
	// const EVP_MD* sha256_digest = EVP_sha256 ();

	// X509 *cert = NULL;
	// for (size_t i = 0; i < sk_X509_num (signers); i++) {
	// 	cert = sk_X509_value (signers, i);

	// 	unsigned char sha256[SHA256_BYTES];
	// 	unsigned char sha1[SHA1_BYTES];
	// 	X509_digest (cert, sha1_digest, thumbprint, NULL);
	// 	X509_digest (cert, sha256_digest, thumbprint, NULL);
	// 	for (size_t j = 0; j < SHA1_BYTES; j++) {
	// 		sprintf (thumbprint_ascii + (j * 2), "%02x", thumbprint[j]);
	// 	}
	// 	printf ("SHA1: %s\n", thumbprint_ascii);
		
	// 	for (size_t j = 0; j < SHA256_BYTES; j++) {
	// 		sprintf (thumbprint_ascii + (j * 2), "%02x", thumbprint[j]);
	// 	}
	// 	printf ("SHA256 %s\n", thumbprint_ascii);

	// 	X509_NAME_oneline (X509_get_issuer_name (cert), buffer, sizeof(buffer));

	// 	printf ("Issuer: %s\n", buffer);
	// 	X509_NAME_oneline (X509_get_subject_name (cert), buffer, sizeof(buffer));

	// 	printf ("Subject: %s\n", buffer);
	// 	printf ("Version: %ld\n", X509_get_version( cert) + 1);
 
	// 	const char *sig_alg = OBJ_nid2sn (X509_get_signature_nid (cert));
	// 	printf ("Signature algorithm: %s\n", sig_alg);

	// 	ASN1_INTEGER *serial = X509_get_serialNumber (cert);
	// 	if (serial) {
	// 		int bytes = i2d_ASN1_INTEGER(serial, NULL);
	// 		unsigned char serial_buf[22];
	// 		unsigned char *serial_str = serial_buf;
	// 		int length = i2d_ASN1_INTEGER (serial, &serial_str);
	// 		char *serial_ascii = (char*) malloc(22 * 3);

	// 		serial_str +=2;
	// 		if (serial_ascii) {
	// 			for (size_t j = 0; j < bytes; j++) {
	// 				snprintf(serial_ascii + 3 * j, 3, "%02x", serial_str[j]);
	// 			}	
	// 		}
	// 		printf ("Serial: %s\n", serial_ascii);
	// 	}
	// }
}

void Pkcs7::parse_signer_info (PKCS7_SIGNER_INFO *info) {
	/* SignerInfo contains
	- Signed hash of contentInfo
	- Publisher description and URL (optional)
	- Timestamp (optional)
		- If timestamp exists it needs to have counter-signer to confirm */
	for (int j = 0; j < sk_X509_ATTRIBUTE_num(info->unauth_attr); ++j)
	{
		X509_ATTRIBUTE *attr = sk_X509_ATTRIBUTE_value(info->unauth_attr, j);
		ASN1_TYPE *attr_type = X509_ATTRIBUTE_get0_type(attr, 0);
		ASN1_OBJECT *attr_object = X509_ATTRIBUTE_get0_object(attr);
		if (!attr_object)
			continue;

		auto attr_object_nid = OBJ_obj2nid(attr_object);
		if (attr_object_nid == NID_pkcs9_countersignature) {
			;;
		}
	}
}
HashType Pkcs7::get_digest_algorithm () const {
	
}