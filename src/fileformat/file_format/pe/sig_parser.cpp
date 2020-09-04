#include "sig_parser.hpp"

#define SHA1_BYTES 20
#define SHA256_BYTES 32

Certificate::Certificate(X509 *cert) {
	this->cert = cert;
}

template <typename Getter>
std::string Certificate::get_oneline_string(Getter&& getter) const
{
	BIO *bio = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(bio, getter(cert), 0, XN_FLAG_RFC2253);
	auto str_size = BIO_number_written(bio);

	std::string result(str_size, '\0');
	BIO_read(bio, result.data(), result.size());
	return result;
}

std::string Certificate::get_subject_string() const
{
	return get_oneline_string([](X509* cert) {
		return X509_get_subject_name(cert);
	});
}

std::string Certificate::get_issuer_string() const
{
	return get_oneline_string([](X509* cert) {
		return X509_get_issuer_name(cert);
	});
}

std::string Certificate::get_serial_number() const
{
	auto serial_number_asn1 = get_serial_number_asn1();
	BIGNUM *bignum = ASN1_INTEGER_to_BN(serial_number_asn1, nullptr);

	BIO *bio = BIO_new(BIO_s_mem());
	BN_print(bio, bignum);
	auto data_len = BIO_number_written(bio);

	std::vector<char> result(data_len);
	BIO_read(bio, static_cast<void*>(result.data()), data_len);
	return { result.begin(), result.end() };
}

std::string Certificate::get_signature_algorithm() const
{
	auto algo = X509_get0_tbs_sigalg(cert);
	char name[256] = { '\0' };
	OBJ_obj2txt(name, 255, algo->algorithm, 0);
	return name;
}

EVP_PKEY *Certificate::get_public_key() const
{
	return X509_get0_pubkey(cert);
}
//////
std::time_t asn1_time_to_timestamp(const ASN1_TIME* asn1_time)
{
	struct tm timepoint;
	ASN1_TIME_to_tm(asn1_time, &timepoint);
	return mktime(&timepoint);
}
//////

std::time_t Certificate::get_not_before() const
{
	return asn1_time_to_timestamp(X509_get0_notBefore(cert));
}

std::time_t Certificate::get_not_after() const
{
	return asn1_time_to_timestamp(X509_get0_notAfter(cert));
}

std::string Certificate::get_pem() const
{
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, cert);
	auto data_len = BIO_number_written(bio);

	std::vector<char> result(data_len);
	BIO_read(bio, static_cast<void*>(result.data()), data_len);
	return { result.begin(), result.end() };
}

ASN1_INTEGER* Certificate::get_serial_number_asn1() const
{
	return X509_get_serialNumber(cert);
}

X509* Certificate::get_x509() const
{
	return cert;
}

const char *hash_name_from_asn1(ASN1_OBJECT *obj) {
	switch (OBJ_obj2nid(obj)) {
	case NID_md5:
	case NID_md5WithRSAEncryption:
		return "MD5";
	case NID_sha1:
	case NID_sha1WithRSAEncryption:
		return "SHA1";
	case NID_sha256:
	case NID_sha256WithRSAEncryption:
		return "SHA256";
	case NID_sha384:
	case NID_sha384WithRSAEncryption:
		return "SHA384";
	case NID_sha512:
	case NID_sha512WithRSAEncryption:
		return "SHA512";
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
	/* Parse the signer info part */
	parse_signer_info (sk_PKCS7_SIGNER_INFO_value (signer_infos, 0));
}

#define SPC_NESTED_SIGNATURE_OBJID  "1.3.6.1.4.1.311.2.4.1"
#define SPC_NESTED_SIGNATURE_NAME "spcNestedSignature"

void Pkcs7::parse_signer_info (PKCS7_SIGNER_INFO *si_info) {
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

		const int NID_spc_nested_signature = OBJ_create ("1.3.6.1.4.1.311.2.4.1", SPC_NESTED_SIGNATURE_NAME, "SPC_NESTED_SIGNATURE (Authenticode)");
		if (attr_object_nid == NID_spc_nested_signature) {
			std::vector<unsigned char> nested_sig_data (attr_type->value.sequence->data, attr_type->value.sequence->data + attr_type->value.sequence->length);
			nested_signatures.push_back (Pkcs7 (nested_sig_data));
		} else if (attr_object_nid == NID_pkcs9_countersignature) {
			std::vector<unsigned char> countersig_data (attr_type->value.sequence->data, attr_type->value.sequence->data + attr_type->value.sequence->length);
			counter_signatures.push_back (Pkcs9 (countersig_data));
		}
	}
	;;;
}

STACK_OF(X509) *Pkcs7::get_certificates() {
	return pkcs7->d.sign->cert;
}

STACK_OF(X509) *Pkcs7::get_signers() {
	return PKCS7_get0_signers (pkcs7, pkcs7->d.sign->cert, 0);
}

const char *Pkcs7::get_digest_algorithm() const {
	return hash_name_from_asn1 (spc_content->messageDigest->digestAlgorithm->algorithm);
}

std::string Pkcs7::get_signed_digest() const {
	return std::string ((char *)spc_content->messageDigest->digest->data, spc_content->messageDigest->digest->length);
}

void Pkcs7::print() {
	std::cout << "** My output: **" << std::endl;
	std::cout << "File hash algoritm, " << get_digest_algorithm () << std::endl;
	std::cout << "Signed hash, " << get_signed_digest () << std::endl; /* fix - TODO decode*/
	for (size_t i = 0; i < sk_X509_num (get_certificates ()); i++)
	{
		Certificate cert(sk_X509_value (get_certificates (), i));
		std::cout << "subject: " << cert.get_subject_string () << std::endl;
		std::cout << "issuer: " << cert.get_issuer_string () << std::endl;
		std::cout << "serial_number: " << cert.get_serial_number () << std::endl;
		std::cout << "signature_algorithm: " << cert.get_signature_algorithm () << std::endl;
		std::cout << "pem: " << cert.get_pem () << std::endl;
		std::cout << "not_before: " << cert.get_not_before () << std::endl;
		std::cout << "not_after: " << cert.get_not_after () << std::endl;
	}
	
	// printf ("chain \n");
	// printf ("countersignatures\n");
}

Pkcs9::Pkcs9(std::vector<unsigned char> data) {
	const auto *data_ptr = data.data ();
	countersign_info = d2i_PKCS7_SIGNER_INFO (nullptr, &data_ptr, data.size ());
	if (!countersign_info) {
		throw std::exception();
	}
}