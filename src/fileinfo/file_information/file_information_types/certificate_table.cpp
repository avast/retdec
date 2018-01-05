/**
 * @file src/fileinfo/file_information/file_information_types/certificate_table.cpp
 * @brief Certificate table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/certificate_table.h"

namespace fileinfo {

/**
 * Constructor
 */
CertificateTable::CertificateTable() : table(nullptr)
{

}

/**
 * Destructor
 */
CertificateTable::~CertificateTable()
{

}

/**
 * Get number of certificates in table
 * @return Number of certificates in table
 */
std::size_t CertificateTable::getNumberOfCertificates() const
{
	return table ? table->getNumberOfCertificates() : 0;
}

/**
 * Get index of the certificate of the signer
 * @return Index of the signer's certificate
 */
std::size_t CertificateTable::getSignerCertificateIndex() const
{
	return table ? table->getSignerCertificateIndex() : 0;
}

/**
 * Get index of the certificate of the counter-signer. Returned value should not be used without prior checking
 * of whether the table has counter-signer certificate.
 * @return Index of the counter-signer's certificate
 */
std::size_t CertificateTable::getCounterSignerCertificateIndex() const
{
	return table ? table->getCounterSignerCertificateIndex() : 0;
}

/**
 * Get date since when is certificate valid
 * @param position Index of selected certificate from table (indexed from 0)
 * @return Date since when is certificate valid
 */
std::string CertificateTable::getCertificateValidSince(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getValidSince() : "";
}

/**
 * Get date until when is certificate valid
 * @param position Index of selected certificate from table (indexed from 0)
 * @return Date until when is certificate valid
 */
std::string CertificateTable::getCertificateValidUntil(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getValidUntil() : "";
}

/**
 * Get certificate public key
 * @param position Index of selected certificate from table (indexed from 0)
 * @return Public key
 */
std::string CertificateTable::getCertificatePublicKey(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getPublicKey() : "";
}

/**
 * Get certificate public key algorithm
 * @param position Index of selected certificate from table (indexed from 0)
 * @return Public key algorithm
 */
std::string CertificateTable::getCertificatePublicKeyAlgorithm(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getPublicKeyAlgorithm() : "";
}

/**
 * Get certificate signature algorithm
 * @param position Index of selected certificate from table (indexed from 0)
 * @return Signature algorithm
 */
std::string CertificateTable::getCertificateSignatureAlgorithm(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSignatureAlgorithm() : "";
}

/**
 * Get certificate serial number
 * @param position Index of selected certificate from table (indexed from 0)
 * @return Serial number
 */
std::string CertificateTable::getCertificateSerialNumber(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSerialNumber() : "";
}

/**
 * Get certificate SHA1 digest
 * @param position Index of selected certificate from table (indexed from 0)
 * @return SHA1 digest
 */
std::string CertificateTable::getCertificateSha1Digest(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSha1Digest() : "";
}

/**
 * Get certificate SHA256 digest
 * @param position Index of selected certificate from table (indexed from 0)
 * @return SHA256 digest
 */
std::string CertificateTable::getCertificateSha256Digest(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSha256Digest() : "";
}

/**
 * Get certificate subject
 * @param position Index of selected certificate from table (indexed from 0)
 * @return Certificate subject
 */
std::string CertificateTable::getCertificateSubjectRaw(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getRawSubject() : "";
}

/**
 * Get certificate issuer
 * @param position Index of selected certificate from table (indexed from 0)
 * @return Certificate issuer
 */
std::string CertificateTable::getCertificateIssuerRaw(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getRawIssuer() : "";
}

/**
 * Get certificate issuer country
 * @param position Index of selected certificate (indexed from 0)
 * @return Country of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerCountry(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().country : "";
}

/**
 * Get certificate issuer organization
 * @param position Index of selected certificate (indexed from 0)
 * @return Organization of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerOrganization(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().organization : "";
}

/**
 * Get certificate issuer organizational unit
 * @param position Index of selected certificate (indexed from 0)
 * @return Organizational unit of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerOrganizationalUnit(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().organizationalUnit : "";
}

/**
 * Get certificate issuer name qualifier
 * @param position Index of selected certificate (indexed from 0)
 * @return Name qualifier of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerNameQualifier(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().nameQualifier : "";
}

/**
 * Get certificate issuer state
 * @param position Index of selected certificate (indexed from 0)
 * @return State of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerState(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().state : "";
}

/**
 * Get certificate issuer common name
 * @param position Index of selected certificate (indexed from 0)
 * @return Common name of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerCommonName(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().commonName : "";
}

/**
 * Get certificate issuer serial number
 * @param position Index of selected certificate (indexed from 0)
 * @return Serial number of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerSerialNumber(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().serialNumber : "";
}

/**
 * Get certificate issuer locality
 * @param position Index of selected certificate (indexed from 0)
 * @return Locality of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerLocality(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().locality : "";
}

/**
 * Get certificate issuer title
 * @param position Index of selected certificate (indexed from 0)
 * @return Title of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerTitle(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().title : "";
}

/**
 * Get certificate issuer surname
 * @param position Index of selected certificate (indexed from 0)
 * @return Surname of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerSurname(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().surname : "";
}

/**
 * Get certificate issuer given name
 * @param position Index of selected certificate (indexed from 0)
 * @return Given name of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerGivenName(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().givenName : "";
}

/**
 * Get certificate issuer initials
 * @param position Index of selected certificate (indexed from 0)
 * @return Initials of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerInitials(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().initials : "";
}

/**
 * Get certificate issuer pseudonym
 * @param position Index of selected certificate (indexed from 0)
 * @return Pseudonym of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerPseudonym(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().pseudonym : "";
}

/**
 * Get certificate issuer generation qualifier
 * @param position Index of selected certificate (indexed from 0)
 * @return Generation qualifier of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerGenerationQualifier(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().generationQualifier : "";
}

/**
 * Get certificate issuer email address
 * @param position Index of selected certificate (indexed from 0)
 * @return Email address of selected certificate issuer
 */
std::string CertificateTable::getCertificateIssuerEmailAddress(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getIssuer().emailAddress : "";
}

/**
 * Get certificate subject country
 * @param position Index of selected certificate (indexed from 0)
 * @return Country of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectCountry(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().country : "";
}

/**
 * Get certificate subject organization
 * @param position Index of selected certificate (indexed from 0)
 * @return Organization of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectOrganization(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().organization : "";
}

/**
 * Get certificate subject organizational unit
 * @param position Index of selected certificate (indexed from 0)
 * @return Organizational unit of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectOrganizationalUnit(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().organizationalUnit : "";
}

/**
 * Get certificate subject name qualifier
 * @param position Index of selected certificate (indexed from 0)
 * @return Name qualifier of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectNameQualifier(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().nameQualifier : "";
}

/**
 * Get certificate subject state
 * @param position Index of selected certificate (indexed from 0)
 * @return State of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectState(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().state : "";
}

/**
 * Get certificate subject common name
 * @param position Index of selected certificate (indexed from 0)
 * @return Common name of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectCommonName(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().commonName : "";
}

/**
 * Get certificate subject serial number
 * @param position Index of selected certificate (indexed from 0)
 * @return Serial number of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectSerialNumber(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().serialNumber : "";
}

/**
 * Get certificate subject locality
 * @param position Index of selected certificate (indexed from 0)
 * @return Locality of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectLocality(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().locality : "";
}

/**
 * Get certificate subject title
 * @param position Index of selected certificate (indexed from 0)
 * @return Title of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectTitle(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().title : "";
}

/**
 * Get certificate subject surname
 * @param position Index of selected certificate (indexed from 0)
 * @return Surname of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectSurname(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().surname : "";
}

/**
 * Get certificate subject given name
 * @param position Index of selected certificate (indexed from 0)
 * @return Given name of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectGivenName(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().givenName : "";
}

/**
 * Get certificate subject initials
 * @param position Index of selected certificate (indexed from 0)
 * @return Initials of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectInitials(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().initials : "";
}

/**
 * Get certificate subject pseudonym
 * @param position Index of selected certificate (indexed from 0)
 * @return Pseudonym of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectPseudonym(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().pseudonym : "";
}

/**
 * Get certificate subject generation qualifier
 * @param position Index of selected certificate (indexed from 0)
 * @return Generation qualifier of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectGenerationQualifier(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().generationQualifier : "";
}

/**
 * Get certificate subject email address
 * @param position Index of selected certificate (indexed from 0)
 * @return Email address of selected certificate subject
 */
std::string CertificateTable::getCertificateSubjectEmailAddress(std::size_t position) const
{
	const auto *record = table ? table->getCertificate(position) : nullptr;
	return record ? record->getSubject().emailAddress : "";
}

/**
 * Set certificate table data
 * @param certificateTable Instance of class with original information about certificate table
 */
void CertificateTable::setTable(const retdec::fileformat::CertificateTable *certificateTable)
{
	table = certificateTable;
}

/**
 * Find out if there are any certificates
 * @return @c true if there are some certificates, @c false otherwise
 */
bool CertificateTable::hasRecords() const
{
	return table ? !table->empty() : false;
}

/**
 * Find out if there is signer certificate
 * @return @c true if there is signer certificate, @c false otherwise
 */
bool CertificateTable::hasSignerCertificate() const
{
	return table ? table->hasSignerCertificate() : false;
}

/**
 * Find out if there is counter-signer certificate
 * @return @c true if there is counter-signer certificate, @c false otherwise
 */
bool CertificateTable::hasCounterSignerCertificate() const
{
	return table ? table->hasCounterSignerCertificate() : false;
}

} // namespace fileinfo
