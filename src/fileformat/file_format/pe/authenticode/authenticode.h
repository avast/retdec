/**
 * @file src/fileformat/file_format/pe/authenticode/authenticode.h
 * @brief Class that parses PE Authenticode data
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#pragma once

#include "retdec/fileformat/types/certificate_table/certificate_table.h"

#include "authenticode_structs.h"
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

/* Basically a PKCS7 with specific contraints */
class Authenticode
{
private:
	Pkcs7 pkcs7;

public:
	Authenticode(std::vector<unsigned char> data);
	std::vector<DigitalSignature> getSignatures() const;
};

} // namespace authenticode