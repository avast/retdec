/**
 * @file src/fileformat/file_format/pe/authenticode/helper.h
 * @brief Helper functions used for Authenticode components
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
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
#include <openssl/pkcs7.h>

namespace authenticode {

std::string bytesToHexString(const std::uint8_t* in, int len);
std::string parsePublicKey(BIO* bio);
std::string serialToString(ASN1_INTEGER* serial);
std::string X509NameToString(X509_NAME* name);
std::string parseDateTime(const ASN1_TIME* dateTime);
PKCS7* getPkcs7(const std::vector<unsigned char>& input);
void calculateDigest(const EVP_MD* md, const std::uint8_t* data, int len, std::uint8_t* digest);

} // namespace authenticode
