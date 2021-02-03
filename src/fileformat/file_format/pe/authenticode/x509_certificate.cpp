/**
 * @file src/fileformat/file_format/pe/authenticode/x509_certificate.h
 * @brief Class that wraps openssl x509 certificate information.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "x509_certificate.h"
#include <cstdint>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>

namespace authenticode {

static std::time_t asn1TimeToTimestamp(const ASN1_TIME* asn1_time)
{
	struct tm timepoint;
	ASN1_TIME_to_tm(asn1_time, &timepoint);
	return mktime(&timepoint);
}
/* Calculates md digest type from data, result is a written into 
   digest that has to be large enough to accomodate whole digest */
static void calculateDigest(const EVP_MD* md, std::uint8_t* data, int len, std::uint8_t* digest)
{
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, data, len);
	EVP_DigestFinal_ex(mdctx, digest, NULL);
	EVP_MD_CTX_free(mdctx);
}

static std::string bytesToHexString(const std::uint8_t* in, int len)
{
	const std::uint8_t* end = in + len;
	std::ostringstream oss;
	for (; in != end; ++in)
		oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*in);
	return oss.str();
}

X509Certificate::X509Certificate(X509* cert)
{
	this->cert = cert;
}

std::string X509Certificate::getX509Name(X509_NAME* name) const
{
	BIO* bio = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
	auto str_size = BIO_number_written(bio);

	std::string result(str_size, '\0');
	BIO_read(bio, (void*)result.data(), result.size());
	BIO_free_all(bio);
	return result;
}

std::string X509Certificate::getSerialNumber() const
{
	ASN1_INTEGER* serial_number_asn1 = X509_get_serialNumber(cert);
	BIGNUM* bignum = ASN1_INTEGER_to_BN(serial_number_asn1, nullptr);

	BIO* bio = BIO_new(BIO_s_mem());
	BN_print(bio, bignum);
	auto data_len = BIO_number_written(bio);

	std::vector<char> result(data_len);
	BIO_read(bio, static_cast<void*>(result.data()), data_len);
	BIO_free_all(bio);
	return { result.begin(), result.end() };
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
	std::time_t timestamp = asn1TimeToTimestamp(X509_get0_notBefore(cert));
	std::stringstream buffer;
	buffer << std::put_time(std::gmtime(&timestamp), "%c %Z");
	return buffer.str();
}

std::string X509Certificate::getValidUntil() const
{
	std::time_t timestamp = asn1TimeToTimestamp(X509_get0_notAfter(cert));
	std::stringstream buffer;
	buffer << std::put_time(std::gmtime(&timestamp), "%c %Z");
	return buffer.str();
}

std::string X509Certificate::getPem() const
{
	BIO* bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, cert);
	auto data_len = BIO_number_written(bio);

	std::vector<char> result(data_len);
	BIO_read(bio, static_cast<void*>(result.data()), data_len);
	return { result.begin(), result.end() };
}

X509* X509Certificate::getX509() const
{
	return cert;
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
	return "";
}

std::string X509Certificate::getPublicKeyAlgorithm() const
{
	return "";
}

std::string X509Certificate::getSignature() const
{
	return "";
}

std::string X509Certificate::getSha1() const
{
	const int sha1_length = 20;
	std::uint8_t sha1_bytes[sha1_length];

	std::uint8_t* data = nullptr;
	int len = i2d_X509(cert, &data);

	const EVP_MD* md = EVP_sha1();
	calculateDigest(md, data, len, sha1_bytes);
	return bytesToHexString(sha1_bytes, sha1_length);
}
std::string X509Certificate::getSha256() const
{
	const int sha256_length = 32;
	std::uint8_t sha256_bytes[sha256_length];

	std::uint8_t* data = nullptr;
	int len = i2d_X509(cert, &data);

	const EVP_MD* md = EVP_sha256();
	calculateDigest(md, data, len, sha256_bytes);

	return bytesToHexString(sha256_bytes, sha256_length);
}

int X509Certificate::getVersion() const
{
	return X509_get_version(cert);
}

std::string X509Certificate::getRawSubject() const
{
	return getX509Name(X509_get_subject_name(cert));
}

std::string X509Certificate::getRawIssuer() const
{
	return getX509Name(X509_get_issuer_name(cert));
}

Certificate X509Certificate::createCertificate() const
{
	Certificate out_cert;
	out_cert.issuerRaw = getRawIssuer();
	out_cert.subjectRaw = getRawSubject();
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

/* TODO Chain is processed by callbacks set in the CertProcessor constructor 
   !! The order of the certificates is not guaranteed to be corret right now */
std::vector<X509Certificate> CertificateProcessor::getChain(X509* cert, STACK_OF(X509)* all_certs)
{
	X509_STORE_CTX_init(ctx, trust_store, cert, all_certs);
	X509_verify_cert(ctx);
	return chain;
}

static CertificateProcessor* get_processor(X509_STORE_CTX* ctx)
{
	return static_cast<CertificateProcessor*>(X509_STORE_get_ex_data(X509_STORE_CTX_get0_store(ctx), 0));
}

static void addCertificateToChain(X509_STORE_CTX* ctx, const X509Certificate& cert)
{
	auto depth = X509_STORE_CTX_get_error_depth(ctx); // use this?
	void* data = X509_STORE_CTX_get_ex_data(ctx, depth);
	if (data == nullptr) {
		CertificateProcessor* processor = get_processor(ctx);
		processor->chain.push_back(cert);
		X509_STORE_CTX_set_ex_data(ctx, depth, (void*)processor); // set random pointer for now
	}
}

static int verify_callback(int /*ok*/, X509_STORE_CTX* ctx)
{
	auto cert = X509_STORE_CTX_get_current_cert(ctx);
	addCertificateToChain(ctx, cert);
	return 1;
}

CertificateProcessor::CertificateProcessor()
{
	trust_store = X509_STORE_new();
	ctx = X509_STORE_CTX_new();

	X509_STORE_set_verify_cb(trust_store, &verify_callback);
	X509_STORE_set_ex_data(trust_store, 0, static_cast<void*>(this));
}

} // namespace authenticode
