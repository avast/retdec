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

/**
 * Table of certificates
 */
class CertificateTable
{
	private:
		using certificatesIterator = std::vector<Certificate>::const_iterator;
		bool hasSigner;                        ///< flag indicating whether signer is present
		bool hasCounterSigner;                 ///< flag indicating whether counter signer is present
		std::size_t signerIndex;               ///< index of certificate of the signer
		std::size_t counterSignerIndex;        ///< index of certificate of the counter-signer
		std::vector<Certificate> certificates; ///< stored certificates
	public:
		CertificateTable();
		~CertificateTable();

		/// @name Getters
		/// @{
		std::size_t getNumberOfCertificates() const;
		std::size_t getSignerCertificateIndex() const;
		std::size_t getCounterSignerCertificateIndex() const;
		const Certificate* getCertificate(std::size_t certIndex) const;
		/// @}

		/// @name Setters
		/// @{
		void setSignerCertificateIndex(std::size_t certIndex);
		void setCounterSignerCertificateIndex(std::size_t certIndex);
		/// @}

		/// @name Iterators
		/// @{
		certificatesIterator begin() const;
		certificatesIterator end() const;
		/// @}

		/// @name Other methods
		/// @{
		bool hasSignerCertificate() const;
		bool hasCounterSignerCertificate() const;
		void addCertificate(const Certificate &certificate);
		bool empty() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
