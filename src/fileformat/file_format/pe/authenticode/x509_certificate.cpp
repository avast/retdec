/**
 * @file src/fileformat/file_format/pe/authenticode/x509_certificate.h
 * @brief Class that wraps openssl x509 certificate information.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "x509_certificate.h"

namespace authenticode {

X509Certificate::X509Certificate(X509* cert)
{
	this->cert = cert;
}

static std::time_t asn1TimeToTimestamp(const ASN1_TIME* asn1_time)
{
	struct tm timepoint;
	ASN1_TIME_to_tm(asn1_time, &timepoint);
	return mktime(&timepoint);
}

std::string X509Certificate::getX509Name(X509_NAME* name) const
{
	BIO* bio = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
	auto str_size = BIO_number_written(bio);

	std::string result(str_size, '\0');
	BIO_read(bio, result.data(), result.size());
	return result;
}

std::string X509Certificate::getRawSubject() const
{
	return getX509Name(X509_get_subject_name(cert));
}

std::string X509Certificate::getRawIssuer() const
{
	return getX509Name(X509_get_issuer_name(cert));
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
	if (data == nullptr)
	{
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

Certificate::Attributes parseAttributes(X509_NAME* raw)
{
	Certificate::Attributes attributes;

	std::size_t numEntries = X509_NAME_entry_count(raw);
	for (std::size_t i = 0; i < numEntries; ++i)
	{
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

// TODO
std::string X509Certificate::getPublicKey() const
{
	return "";
}
// TODO
std::string X509Certificate::getPublicKeyAlgorithm() const
{
	return "";
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
	out_cert.sha1Digest = "";
	out_cert.sha256Digest = "";
	out_cert.validSince = getValidSince();
	out_cert.validUntil = getValidUntil();
	return out_cert;
}

} // namespace authenticode
