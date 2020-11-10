#include "certificate.h"

namespace authenticode {

Certificate::Certificate(X509 *cert) {
	this->cert = cert;
}

static std::time_t asn1_time_to_timestamp(const ASN1_TIME* asn1_time) {
	struct tm timepoint;
	ASN1_TIME_to_tm(asn1_time, &timepoint);
	return mktime(&timepoint);
}

std::string Certificate::get_x509_name(X509_NAME *name) const {
	BIO *bio = BIO_new(BIO_s_mem());
	X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
	auto str_size = BIO_number_written(bio);

	std::string result(str_size, '\0');
	BIO_read(bio, result.data(), result.size());
	return result;
}

std::string Certificate::get_subject_string() const {
	return get_x509_name(X509_get_subject_name(cert));
}

std::string Certificate::get_issuer_string() const {
	return get_x509_name(X509_get_issuer_name(cert));
}

std::string Certificate::get_serial_number() const {
	auto serial_number_asn1 = get_serial_number_asn1();
	BIGNUM *bignum = ASN1_INTEGER_to_BN(serial_number_asn1, nullptr);

	BIO *bio = BIO_new(BIO_s_mem());
	BN_print(bio, bignum);
	auto data_len = BIO_number_written(bio);

	std::vector<char> result(data_len);
	BIO_read(bio, static_cast<void*>(result.data()), data_len);
	return { result.begin(), result.end() };
}

std::string Certificate::get_signature_algorithm() const {
	auto algo = X509_get0_tbs_sigalg(cert);
	char name[256] = { '\0' };
	OBJ_obj2txt(name, 255, algo->algorithm, 0);
	return name;
}

EVP_PKEY *Certificate::get_public_key() const {
	return X509_get0_pubkey(cert);
}

std::time_t Certificate::get_not_before() const {
	return asn1_time_to_timestamp(X509_get0_notBefore(cert));
}

std::time_t Certificate::get_not_after() const {
	return asn1_time_to_timestamp(X509_get0_notAfter(cert));
}

std::string Certificate::get_pem() const {
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(bio, cert);
	auto data_len = BIO_number_written(bio);

	std::vector<char> result(data_len);
	BIO_read(bio, static_cast<void*>(result.data()), data_len);
	return { result.begin(), result.end() };
}

ASN1_INTEGER* Certificate::get_serial_number_asn1() const {
	return X509_get_serialNumber(cert);
}

X509* Certificate::get_x509() const {
	return cert;
}

void Certificate::print() {
	std::time_t not_before = get_not_before ();
	std::time_t not_after = get_not_after ();

	std::cout << "   Certificate" << "\n";
	std::cout << "      Subject              : " << get_subject_string () << "\n";
	std::cout << "      Issuer               : " << get_issuer_string () << "\n";
	std::cout << "      Serial number        : " << get_serial_number () << "\n";
	std::cout << "      Public key algorithm : " << "\n";
	std::cout << "      Signature algorithm  : " << get_signature_algorithm () << "\n";
	std::cout << "      Not before           : " << std::put_time (std::gmtime (&not_before), "%c %Z") << "\n";
	std::cout << "      Not after            : " << std::put_time (std::gmtime (&not_after), "%c %Z") << "\n\n";
	// std::cout << "pem: " << get_pem () << std::endl;
}

/* Chain is processed by callbacks set in the CertProcessor constructor 
   !! The order of the certificates is not guaranteed to be corret right now */
std::vector<Certificate> CertificateProcessor::get_chain (X509 *cert, STACK_OF(X509) *all_certs) {
	X509_STORE_CTX_init(ctx, trust_store, cert, all_certs);
	X509_verify_cert(ctx);
	return chain;
}

static CertificateProcessor* get_processor(X509_STORE_CTX* ctx) {
	return static_cast<CertificateProcessor*>(X509_STORE_get_ex_data(X509_STORE_CTX_get0_store(ctx), 0));
}

static void get_or_create_certificate_verification_result(X509_STORE_CTX* ctx, const Certificate& cert) {
	auto depth = X509_STORE_CTX_get_error_depth(ctx);
	void *data = X509_STORE_CTX_get_ex_data(ctx, depth);
	if (data == nullptr)
	{
		CertificateProcessor *processor = get_processor (ctx);
		processor->chain.push_back(cert);
		X509_STORE_CTX_set_ex_data(ctx, depth, (void *) processor); // set random pointer for now
	}
}


static int verify_callback(int /*ok*/, X509_STORE_CTX* ctx) {
	auto cert = X509_STORE_CTX_get_current_cert (ctx);
	get_or_create_certificate_verification_result (ctx, cert);
	// auto error_code = X509_STORE_CTX_get_error (ctx);
	// X509_STORE_CTX_set_error(ctx, X509_V_OK);
	return 1;
}

static STACK_OF(X509_CRL)* lookup_crl_callback(X509_STORE_CTX* ctx, X509_NAME* /*name*/) {
	auto crls = sk_X509_CRL_new_null ();
	auto cert = X509_STORE_CTX_get_current_cert (ctx);
	get_or_create_certificate_verification_result (ctx, cert);
	return crls;
}


CertificateProcessor::CertificateProcessor() {
	trust_store = X509_STORE_new ();
	ctx = X509_STORE_CTX_new ();

	if (auto ca_dir = getenv ("CA_DIR"); ca_dir) {
		namespace fs = std::filesystem;

		if (fs::is_directory (ca_dir)) {
			for (auto &p : fs::recursive_directory_iterator (ca_dir)) {
				auto ext = p.path ().extension ();
				if (ext == ".crt" || ext == ".pem" || ext == ".cer")
					X509_STORE_load_locations (trust_store, p.path ().c_str (), nullptr);
			}
		}
	}

	X509_STORE_set_flags (trust_store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	X509_STORE_set_verify_cb (trust_store, &verify_callback);
	// X509_STORE_set_lookup_crls(trust_store, &lookup_crl_callback);
	X509_STORE_set_ex_data (trust_store, 0, static_cast<void *> (this));
}

}