#include "authenticode.h"

namespace authenticode {
/* authenticode is just PKCS7 with some specific constraints, 
	do we validate them? if yes is should be done here I suppose*/
Authenticode::Authenticode (std::vector<unsigned char> data)
    : pkcs7 (data) {}
} // namespace authenticode