#include "authenticode.h"

namespace authenticode {
/* authenticode is just PKCS7 with some specific constraints, 
	do we validate them? if yes is should be done here I suppose*/
Authenticode::Authenticode (std::vector<unsigned char> data)
	: pkcs7 (data) {}

std::vector<DigitalSignature> Authenticode::getSignatures() const
{
	return pkcs7.get_signatures (); 
}
} // namespace authenticode