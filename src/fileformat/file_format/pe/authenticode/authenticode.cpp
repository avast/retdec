/**
 * @file src/fileformat/file_format/pe/authenticode/authenticode.cpp
 * @brief Class that parses PE Authenticode data
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include "authenticode.h"

namespace authenticode {
/* authenticode is just PKCS7 with some specific constraints, 
	do we validate them? if yes is should be done here I suppose*/
Authenticode::Authenticode(std::vector<unsigned char> data)
	: pkcs7(data) {}

std::vector<DigitalSignature> Authenticode::getSignatures() const
{
	return pkcs7.getSignatures();
}

} // namespace authenticode