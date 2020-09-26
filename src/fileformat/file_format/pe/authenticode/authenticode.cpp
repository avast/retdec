#include "authenticode.hpp"

/* authenticode is just PKCS7 with some specific constraints */
Authenticode::Authenticode(std::vector<unsigned char> data) : pkcs7 (data) {}
