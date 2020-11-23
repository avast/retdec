/**
 * @file include/retdec/fileformat/types/certificate_table/certificate_table.h
 * @brief Class for certificate table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_CERTIFICATE_TABLE_CERTIFICATE_TABLE_H
#define RETDEC_FILEFORMAT_TYPES_CERTIFICATE_TABLE_CERTIFICATE_TABLE_H

#include <vector>

#include "retdec/fileformat/types/certificate_table/certificate.h"

namespace retdec {
namespace fileformat {

struct Signer
{
	std::vector<Certificate> chain;
	/*
	Note 2 - A countersignature, since it has type SignerInfo, can itself
	contain a countersignature attribute.  Thus it is possible to
	construct arbitrarily long series of countersignatures.
	https://tools.ietf.org/html/rfc2985
	*/
	std::vector<Signer> counter_signers;
};

/* naming - simply Signature was already taken by unpackers */
struct DigitalSignature
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
public:
	std::vector<DigitalSignature> signatures;

	CertificateTable(std::vector<DigitalSignature> signatures);
	CertificateTable() = default;
	bool empty() const;
};

} // namespace fileformat
} // namespace retdec

#endif
