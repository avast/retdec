/**
 * @file src/fileformat/file_format/pe/authenticode/authenticode.cpp
 * @brief Class that parses PE Authenticode data
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#include "authenticode.h"

namespace authenticode {
Authenticode::Authenticode(const std::vector<unsigned char>& data)
	: pkcs7(data) {}

std::vector<DigitalSignature> Authenticode::getSignatures(const retdec::fileformat::PeFormat* peFile) const
{
	return pkcs7.getSignatures(peFile);
}

} // namespace authenticode
