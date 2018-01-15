/**
 * @file src/fileinfo/file_information/file_information_types/certificate_table.h
 * @brief Certificate table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_CERTIFICATE_TABLE_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_CERTIFICATE_TABLE_H

#include "retdec/fileformat/types/certificate_table/certificate_table.h"

namespace fileinfo {

/**
 * Class for certificate table
 */
class CertificateTable
{
	private:
		const retdec::fileformat::CertificateTable *table;
	public:
		CertificateTable();
		~CertificateTable();

		/// @name Getters
		/// @{
		std::size_t getNumberOfCertificates() const;
		std::size_t getSignerCertificateIndex() const;
		std::size_t getCounterSignerCertificateIndex() const;
		std::string getCertificateValidSince(std::size_t position) const;
		std::string getCertificateValidUntil(std::size_t position) const;
		std::string getCertificatePublicKey(std::size_t position) const;
		std::string getCertificatePublicKeyAlgorithm(std::size_t position) const;
		std::string getCertificateSignatureAlgorithm(std::size_t position) const;
		std::string getCertificateSerialNumber(std::size_t position) const;
		std::string getCertificateSha1Digest(std::size_t position) const;
		std::string getCertificateSha256Digest(std::size_t position) const;
		std::string getCertificateSubjectRaw(std::size_t position) const;
		std::string getCertificateIssuerRaw(std::size_t position) const;
		std::string getCertificateIssuerCountry(std::size_t position) const;
		std::string getCertificateIssuerOrganization(std::size_t position) const;
		std::string getCertificateIssuerOrganizationalUnit(std::size_t position) const;
		std::string getCertificateIssuerNameQualifier(std::size_t position) const;
		std::string getCertificateIssuerState(std::size_t position) const;
		std::string getCertificateIssuerCommonName(std::size_t position) const;
		std::string getCertificateIssuerSerialNumber(std::size_t position) const;
		std::string getCertificateIssuerLocality(std::size_t position) const;
		std::string getCertificateIssuerTitle(std::size_t position) const;
		std::string getCertificateIssuerSurname(std::size_t position) const;
		std::string getCertificateIssuerGivenName(std::size_t position) const;
		std::string getCertificateIssuerInitials(std::size_t position) const;
		std::string getCertificateIssuerPseudonym(std::size_t position) const;
		std::string getCertificateIssuerGenerationQualifier(std::size_t position) const;
		std::string getCertificateIssuerEmailAddress(std::size_t position) const;
		std::string getCertificateSubjectCountry(std::size_t position) const;
		std::string getCertificateSubjectOrganization(std::size_t position) const;
		std::string getCertificateSubjectOrganizationalUnit(std::size_t position) const;
		std::string getCertificateSubjectNameQualifier(std::size_t position) const;
		std::string getCertificateSubjectState(std::size_t position) const;
		std::string getCertificateSubjectCommonName(std::size_t position) const;
		std::string getCertificateSubjectSerialNumber(std::size_t position) const;
		std::string getCertificateSubjectLocality(std::size_t position) const;
		std::string getCertificateSubjectTitle(std::size_t position) const;
		std::string getCertificateSubjectSurname(std::size_t position) const;
		std::string getCertificateSubjectGivenName(std::size_t position) const;
		std::string getCertificateSubjectInitials(std::size_t position) const;
		std::string getCertificateSubjectPseudonym(std::size_t position) const;
		std::string getCertificateSubjectGenerationQualifier(std::size_t position) const;
		std::string getCertificateSubjectEmailAddress(std::size_t position) const;
		/// @}

		/// @name Setters
		/// @{
		void setTable(const retdec::fileformat::CertificateTable *certificateTable);
		/// @}

		/// @name Other methods
		/// @{
		bool hasRecords() const;
		bool hasSignerCertificate() const;
		bool hasCounterSignerCertificate() const;
		/// @}
};

} // namespace fileinfo

#endif
