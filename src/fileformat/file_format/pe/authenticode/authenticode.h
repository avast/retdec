/**
 * @file src/fileformat/file_format/pe/authenticode/authenticode.h
 * @brief Class that parses PE Authenticode data
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#pragma once

#include "retdec/fileformat/types/certificate_table/certificate_table.h"

#include "authenticode_structs.h"
#include "pkcs7_signature.h"

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
#include <ctime>

using retdec::fileformat::DigitalSignature;

namespace authenticode {

class Authenticode
{
private:
	Pkcs7Signature pkcs7;

public:
	Authenticode(const std::vector<unsigned char>& data);
	std::vector<DigitalSignature> getSignatures(const retdec::fileformat::PeFormat* peFile) const;
};

} // namespace authenticode
