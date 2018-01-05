/**
 * @file src/fileformat/types/certificate_table/certificate_table.cpp
 * @brief Class for certificate table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/certificate_table/certificate_table.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
CertificateTable::CertificateTable() : hasSigner(false), hasCounterSigner(false), signerIndex(0), counterSignerIndex(0), certificates()
{

}

/**
 * Destructor
 */
CertificateTable::~CertificateTable()
{

}

/**
 * Get number of certificates
 * @return Number of certificates
 */
std::size_t CertificateTable::getNumberOfCertificates() const
{
	return certificates.size();
}

/**
 * Get index of the certificate of the signer
 * @return Index of the signer's certificate
 */
std::size_t CertificateTable::getSignerCertificateIndex() const
{
	return signerIndex;
}

/**
 * Get index of the certificate of the counter-signer. Returned value should not be used without prior checking
 * of whether the table has counter-signer certificate.
 * @return Index of the counter-signer's certificate
 */
std::size_t CertificateTable::getCounterSignerCertificateIndex() const
{
	return counterSignerIndex;
}

/**
 * Get selected certificate
 * @param certIndex Index of selected certificate (indexed from 0)
 * @return Pointer to selected certificate or @c nullptr if certificate index is invalid
 */
const Certificate* CertificateTable::getCertificate(std::size_t certIndex) const
{
	return (certIndex < getNumberOfCertificates()) ? &certificates[certIndex] : nullptr;
}

/**
 * Set signer certificate index
 * @param certIndex Index of the signer certificate
 */
void CertificateTable::setSignerCertificateIndex(std::size_t certIndex)
{
	if(certIndex >= getNumberOfCertificates())
	{
		return;
	}

	hasSigner = true;
	signerIndex = certIndex;
}

/**
 * Set counter-signer certificate index
 * @param certIndex Index of the counter-signer certificate
 */
void CertificateTable::setCounterSignerCertificateIndex(std::size_t certIndex)
{
	if(certIndex >= getNumberOfCertificates())
	{
		return;
	}

	hasCounterSigner = true;
	counterSignerIndex = certIndex;
}

/**
 * Get begin certificates iterator
 * @return Begin certificates iterator
 */
CertificateTable::certificatesIterator CertificateTable::begin() const
{
	return certificates.begin();
}

/**
 * Get end certificates iterator
 * @return End certificates iterator
 */
CertificateTable::certificatesIterator CertificateTable::end() const
{
	return certificates.end();
}

/**
 * Get whether certificate table has signer certificate
 * @return @c true if has signer, otherwise @c false.
 */
bool CertificateTable::hasSignerCertificate() const
{
	return hasSigner;
}

/**
 * Get whether certificate table has counter-signer certificate
 * @return @c true if has counter-signer, otherwise @c false.
 */
bool CertificateTable::hasCounterSignerCertificate() const
{
	return hasCounterSigner;
}

/**
 * Add certificate
 * @param certificate Certificate which will be added
 */
void CertificateTable::addCertificate(const Certificate& certificate)
{
	certificates.push_back(certificate);
}

/**
 * Check if certificate table is empty
 * @return @c true if table does not contain any certificates, @c false otherwise
 */
bool CertificateTable::empty() const
{
	return !getNumberOfCertificates();
}

} // namespace fileformat
} // namespace retdec
