/**
 * @file src/fileformat/types/certificate_table/certificate_table.cpp
 * @brief Class for certificate table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/certificate_table/certificate_table.h"

namespace retdec {
namespace fileformat {


CertificateTable::CertificateTable(authenticode::Authenticode authenticode) {
	std::vector<authenticode::Signature> sigs = authenticode.getSignatures();
	for (auto &&sig: sigs) {
		Signature signature {
			.signed_digest = sig.signed_digest, 
			.digest_algorithm = sig.digest_algorithm,
		};
		/* Authenticode has single signer */
		/* Signer signer {
			.counter_signers = sig.signer.counter_signers;
			.
		} */
		// signature.signers.push_back(sig.signer);
	}
}

/**
 * Check if certificate table is empty
 * @return @c true if table does not contain any certificates, @c false otherwise
 */
bool CertificateTable::empty() const
{
	return signatures.empty();
}

} // namespace fileformat
} // namespace retdec
