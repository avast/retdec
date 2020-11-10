/**
 * @file include/retdec/fileformat/types/certificate_table/certificate_table.h
 * @brief Class for certificate table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_CERTIFICATE_TABLE_CERTIFICATE_TABLE_H
#define RETDEC_FILEFORMAT_TYPES_CERTIFICATE_TABLE_CERTIFICATE_TABLE_H

#include <vector>

#include "retdec/fileformat/types/certificate_table/certificate.h"
#include "../src/fileformat//file_format/pe/authenticode/authenticode.h"

namespace retdec {
namespace fileformat {


struct CounterSigner {
	std::vector<Certificate> chain;
	std::vector<CounterSigner> counter_signers;
};

struct Signer {
	std::vector<Certificate> chain;
	std::vector<CounterSigner> counter_signers;
};

struct Signature 
{
	std::vector<std::uint8_t> signed_digest;
	std::string digest_algorithm;

	std::vector<Signer> signers;
};


/**
 * Table of certificates
 * TODO need to refactor this quite a bit to support Authenticode
 */
class CertificateTable
{
	private:
		std::vector<Signature> signatures;

	public:
		CertificateTable(authenticode::Authenticode authenticode);
		bool empty() const;
};

} // namespace fileformat
} // namespace retdec

#endif
