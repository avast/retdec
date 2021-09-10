/**
 * @file include/retdec/fileformat/types/certificate_table/certificate_table.h
 * @brief Class for certificate table.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
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
	"A countersignature, since it has type SignerInfo, can itself
	contain a countersignature attribute.  Thus it is possible to
	construct arbitrarily long series of countersignatures.""
	https://tools.ietf.org/html/rfc2985
	*/
	std::string signingTime; /* Timestamp counter signatures will have this set */
	std::string digest;
	std::string digestAlgorithm;
	std::vector<std::string> warnings; /* warning messages about the content validity */
	std::vector<Signer> counterSigners;
};

/* naming - "Signature" was already taken by unpackers */
struct DigitalSignature
{
	bool isValid;
	std::string fileDigest;
	std::string signedDigest;
	std::string digestAlgorithm;
	std::string programName;
	std::vector<Certificate> certificates;
	std::vector<std::string> warnings; /* warning messages about the content validity */
	Signer signer;
};

/**
 * Table of certificates
 * Currently PE - Authenticode specific structure (PKCS7)
 */
class CertificateTable
{
public:
	std::vector<DigitalSignature> signatures;
	// if the certificates overlap any section then they are not visible for windows
	bool isOutsideImage = false;

	CertificateTable(std::vector<DigitalSignature> signatures);
	CertificateTable() = default;
	std::size_t signatureCount() const { return signatures.size(); }
	bool empty() const;
};

} // namespace fileformat
} // namespace retdec

#endif
