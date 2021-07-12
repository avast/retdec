/**
 * @file src/fileformat/file_format/pe/authenticode/x509_certificate.h
 * @brief Class that wraps openssl x509 certificate information.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#include "x509_certificate.h"
#include <cstdint>
#include <cstdlib>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string>

namespace authenticode {

X509Certificate::X509Certificate(const X509* cert)
	: cert(cert) {}

std::string X509Certificate::getSerialNumber() const
{
    // https://github.com/VirusTotal/yara/blob/879a6576dd6e544bf9fc7711821029bf842fac54/libyara/modules/pe/pe.c#L1316
    ASN1_INTEGER* serial_number_asn1 = X509_get_serialNumber(const_cast<X509*>(cert));
    if (!serial_number_asn1)
        return {};

    // ASN1_INTEGER can be negative (serial->type & V_ASN1_NEG_INTEGER),
    // in which case the serial number will be stored in 2's complement.
    //
    // Handle negative serial numbers, which are technically not allowed
    // by RFC5280, but do exist. An example binary which has a negative
    // serial number is: 4bfe05f182aa273e113db6ed7dae4bb8.
    //
    // Negative serial numbers are handled by calling i2d_ASN1_INTEGER()
    // with a NULL second parameter. This will return the size of the
    // buffer necessary to store the proper serial number.
    //
    // Do this even for positive serial numbers because it makes the code
    // cleaner and easier to read.

    int bytes = i2d_ASN1_INTEGER(serial_number_asn1, nullptr);

    // According to X.509 specification the maximum length for the
    // serial number is 20 octets. Add two bytes to account for
    // DER type and length information.

    if (bytes <= 2 || bytes > 22)
        return {};

    // Now that we know the size of the serial number allocate enough
    // space to hold it, and use i2d_ASN1_INTEGER() one last time to
    // hold it in the allocated buffer.

    std::vector<unsigned char> serial_der(bytes, 0);
    auto tmp_pointer = serial_der.data();

    // First 2 bytes are DER length information
    bytes = i2d_ASN1_INTEGER(serial_number_asn1, &tmp_pointer) - 2;

    // For each byte in the serial to convert to hexlified format we
    // need three bytes, two for the byte itself and one for colon.
    // The last one doesn't have the colon, but the extra byte is used
    // for the NULL terminator.
    std::vector<char> result(bytes * 3, 0);
    for (int j = 0; j < bytes; j++)
    {
        // Don't put the colon on the last one.
        // Skip over DER type, length information (first 2 bytes of serial_der)
        if (j < bytes - 1)
            snprintf(result.data() + 3 * j, 4, "%02x:", serial_der[j + 2]);
        else
            snprintf(result.data() + 3 * j, 3, "%02x", serial_der[j + 2]);
    }
    // Ignore NULL terminator
    return {result.begin(), result.end() - 1};
}

std::string X509Certificate::getSignatureAlgorithm() const
{
	auto algo = X509_get0_tbs_sigalg(cert);
	char name[256] = { '\0' };
	OBJ_obj2txt(name, 255, algo->algorithm, 0);
	return name;
}

std::string X509Certificate::getValidSince() const
{
	return parseDateTime(X509_get_notBefore(cert));
}

std::string X509Certificate::getValidUntil() const
{
	return parseDateTime(X509_get_notAfter(cert));
}

std::string X509Certificate::getPem() const
{
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, const_cast<X509*>(cert));
	auto data_len = BIO_number_written(bio);

	std::vector<char> result(data_len);
	BIO_read(bio, static_cast<void*>(result.data()), data_len);
	return { result.begin(), result.end() };
}

Certificate::Attributes parseAttributes(X509_NAME* raw)
{
	Certificate::Attributes attributes;

	std::size_t numEntries = X509_NAME_entry_count(raw);
	for (std::size_t i = 0; i < numEntries; ++i) {
		auto nameEntry = X509_NAME_get_entry(raw, int(i));
		auto valueObj = X509_NAME_ENTRY_get_data(nameEntry);

		std::string key = OBJ_nid2sn(
				OBJ_obj2nid(X509_NAME_ENTRY_get_object(nameEntry)));
		std::string value = std::string(
				reinterpret_cast<const char*>(valueObj->data),
				valueObj->length);

		if (key == "C")
			attributes.country = value;
		else if (key == "O")
			attributes.organization = value;
		else if (key == "OU")
			attributes.organizationalUnit = value;
		else if (key == "dnQualifier")
			attributes.nameQualifier = value;
		else if (key == "ST")
			attributes.state = value;
		else if (key == "CN")
			attributes.commonName = value;
		else if (key == "serialNumber")
			attributes.serialNumber = value;
		else if (key == "L")
			attributes.locality = value;
		else if (key == "title")
			attributes.title = value;
		else if (key == "SN")
			attributes.surname = value;
		else if (key == "GN")
			attributes.givenName = value;
		else if (key == "initials")
			attributes.initials = value;
		else if (key == "pseudonym")
			attributes.pseudonym = value;
		else if (key == "generationQualifier")
			attributes.generationQualifier = value;
		else if (key == "emailAddress")
			attributes.emailAddress = value;
	}

	return attributes;
}

Certificate::Attributes X509Certificate::getSubject() const
{
	return parseAttributes(X509_get_subject_name(cert));
}
Certificate::Attributes X509Certificate::getIssuer() const
{
	return parseAttributes(X509_get_issuer_name(cert));
}

std::string X509Certificate::getPublicKey() const
{
	std::uint8_t* data = nullptr;
	EVP_PKEY* pkey = X509_get0_pubkey(cert);
	BIO* memBio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(memBio, pkey);

	std::string result(parsePublicKey(memBio));
	BIO_free_all(memBio);

	return result;
}

std::string X509Certificate::getPublicKeyAlgorithm() const
{
	const EVP_PKEY* pkey = X509_get0_pubkey(cert);
	if (!pkey) {
		return "unknown";
	}

	return OBJ_nid2sn(EVP_PKEY_base_id(pkey));
}

std::string X509Certificate::getSha1() const
{
	const int sha1_length = 20;
	std::uint8_t sha1_bytes[sha1_length];

	std::uint8_t* data = nullptr;
	int len = i2d_X509(const_cast<X509*>(cert), &data);

	const EVP_MD* md = EVP_sha1();
	calculateDigest(md, data, len, sha1_bytes);

	free(data);
	return bytesToHexString(sha1_bytes, sha1_length);
}
std::string X509Certificate::getSha256() const
{
	const int sha256_length = 32;
	std::uint8_t sha256_bytes[sha256_length];

	std::uint8_t* data = nullptr;
	int len = i2d_X509(const_cast<X509*>(cert), &data);

	const EVP_MD* md = EVP_sha256();
	calculateDigest(md, data, len, sha256_bytes);

	free(data);
	return bytesToHexString(sha256_bytes, sha256_length);
}

int X509Certificate::getVersion() const
{
	return X509_get_version(cert);
}

std::string X509Certificate::getRawSubject() const
{
	return X509NameToString(X509_get_subject_name(cert));
}

std::string X509Certificate::getRawIssuer() const
{
	return X509NameToString(X509_get_issuer_name(cert));
}

// Oneline version for YARA compatibility
std::string X509Certificate::getOnelineSubject() const
{
	char buffer[256] = {0};
	X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer));
	return std::string(buffer);
}

// Oneline version for YARA compatibility
std::string X509Certificate::getOnelineIssuer() const
{
	char buffer[256] = {0};
	X509_NAME_oneline(X509_get_issuer_name(cert), buffer, sizeof(buffer));
	return std::string(buffer);
}

Certificate X509Certificate::createCertificate() const
{
	Certificate out_cert;
	out_cert.issuerRaw = getRawIssuer();
	out_cert.issuerOneline = getOnelineIssuer();
	out_cert.subjectRaw = getRawSubject();
	out_cert.subjectOneline = getOnelineSubject();
	out_cert.issuer = getIssuer();
	out_cert.subject = getSubject();
	out_cert.publicKey = getPublicKey();
	out_cert.publicKeyAlgo = getPublicKeyAlgorithm();
	out_cert.signatureAlgo = getSignatureAlgorithm();
	out_cert.serialNumber = getSerialNumber();
	out_cert.sha1Digest = getSha1();
	out_cert.sha256Digest = getSha256();
	out_cert.validSince = getValidSince();
	out_cert.validUntil = getValidUntil();
	return out_cert;
}

CertificateProcessor::CertificateProcessor()
	: trust_store(nullptr, X509_STORE_free),
	  ctx(nullptr, X509_STORE_CTX_free)
{
	trust_store.reset(X509_STORE_new());
	ctx.reset(X509_STORE_CTX_new());
}

std::vector<X509Certificate> CertificateProcessor::getChain(const X509* signer, const STACK_OF(X509)* all_certs)
{
	std::vector<X509Certificate> certificates;

	if (!signer) {
		return certificates;
	}

	X509_STORE_CTX_init(ctx.get(), trust_store.get(), const_cast<X509*>(signer), const_cast<STACK_OF(X509)*>(all_certs));
	bool is_valid = X509_verify_cert(ctx.get()) == 1;
	STACK_OF(X509)* chain = X509_STORE_CTX_get_chain(ctx.get());


	int cert_cnt = sk_X509_num(chain);
	for (int i = 0; i < cert_cnt; i++) {
		certificates.emplace_back(sk_X509_value(chain, i));
	}

	return certificates;
}

const X509_STORE* CertificateProcessor::getStore() const
{
	return trust_store.get();
}
} // namespace authenticode
