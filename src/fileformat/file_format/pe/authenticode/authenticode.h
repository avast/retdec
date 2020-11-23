#pragma once

#include "retdec/fileformat/types/certificate_table/certificate_table.h"

#include "authenticode_structs.h"
#include "x509_certificate.h"
#include "pkcs7.h"

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <vector>
#include <string>
#include <cstdint>
#include <iostream> /* remove */
#include <ctime>

using retdec::fileformat::DigitalSignature;

namespace authenticode {

class Authenticode {
	private:
		Pkcs7 pkcs7;

	public:
		Authenticode (std::vector<unsigned char> data);
		std::vector<DigitalSignature> getSignatures () const;
};
} // namespace authenticode