#pragma once

#include "authenticode_structs.hpp"
#include "certificate.hpp"
#include "pkcs7.hpp"

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

class Authenticode {
private:
	Pkcs7 pkcs7;
public:
	Authenticode(std::vector<unsigned char> data);
};