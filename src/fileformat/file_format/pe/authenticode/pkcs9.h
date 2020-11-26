/**
 * @file src/fileformat/file_format/pe/authenticode/pkcs9.h
 * @brief Class that wraps openssl pkcs9 information.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#pragma once

#include "authenticode_structs.h"
#include "x509_certificate.h"

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

namespace authenticode {

class Pkcs9
{
public:
	Pkcs9(std::vector<unsigned char> data, STACK_OF(X509)* certificates);
	void print();
	X509* certificate;

private:
	PKCS7_SIGNER_INFO* countersign_info;
};

} // namespace authenticode