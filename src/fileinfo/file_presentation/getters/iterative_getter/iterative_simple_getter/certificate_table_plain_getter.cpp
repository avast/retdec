/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_simple_getter/certificate_table_plain_getter.cpp
 * @brief Methods of CertificateTablePlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_simple_getter/certificate_table_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
CertificateTablePlainGetter::CertificateTablePlainGetter(FileInformation &fileInfo) : IterativeSimpleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredCertificates());
	numberOfExtraElements.push_back(0);
	title = "Certificate table";
	elementHeader = "Certificate";
	commonHeaderElements.push_back("Subject name        : ");
	commonHeaderElements.push_back("Subject organization: ");
	commonHeaderElements.push_back("Subject             : ");
	commonHeaderElements.push_back("Issuer name         : ");
	commonHeaderElements.push_back("Issuer organization : ");
	commonHeaderElements.push_back("Issuer              : ");
	commonHeaderElements.push_back("Public key algorithm: ");
	commonHeaderElements.push_back("Signature algorithm : ");
	commonHeaderElements.push_back("Serial number       : ");
	commonHeaderElements.push_back("Valid since         : ");
	commonHeaderElements.push_back("Valid until         : ");
	commonHeaderElements.push_back("SHA1                : ");
	commonHeaderElements.push_back("SHA256              : ");
}

/**
 * Destructor
 */
CertificateTablePlainGetter::~CertificateTablePlainGetter()
{

}

std::size_t CertificateTablePlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.hasCertificateTableRecords())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of certificates          : ");
	desc.push_back("Signer certificate index        : ");
	desc.push_back("Counter-signer certificate index: ");
	info.push_back(numToStr(fileinfo.getNumberOfStoredCertificates()));
	if(fileinfo.hasCertificateTableSignerCertificate())
	{
		info.push_back(numToStr(fileinfo.getCertificateTableSignerCertificateIndex()));
	}
	else
	{
		info.push_back("");
	}
	if(fileinfo.hasCertificateTableCounterSignerCertificate())
	{
		info.push_back(numToStr(fileinfo.getCertificateTableCounterSignerCertificateIndex()));
	}
	else
	{
		info.push_back("");
	}

	return info.size();
}

bool CertificateTablePlainGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(replaceNonprintableChars(fileinfo.getCertificateSubjectCommonName(recIndex)));
	record.push_back(replaceNonprintableChars(fileinfo.getCertificateSubjectOrganization(recIndex)));
	record.push_back(fileinfo.getCertificateSubjectRawStr(recIndex));
	record.push_back(replaceNonprintableChars(fileinfo.getCertificateIssuerCommonName(recIndex)));
	record.push_back(replaceNonprintableChars(fileinfo.getCertificateIssuerOrganization(recIndex)));
	record.push_back(fileinfo.getCertificateIssuerRawStr(recIndex));
	record.push_back(fileinfo.getCertificatePublicKeyAlgorithm(recIndex));
	record.push_back(fileinfo.getCertificateSignatureAlgorithm(recIndex));
	record.push_back(fileinfo.getCertificateSerialNumber(recIndex));
	record.push_back(fileinfo.getCertificateValidSince(recIndex));
	record.push_back(fileinfo.getCertificateValidUntil(recIndex));
	record.push_back(fileinfo.getCertificateSha1Digest(recIndex));
	record.push_back(fileinfo.getCertificateSha256Digest(recIndex));

	return true;
}

bool CertificateTablePlainGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	flagsValue.clear();
	desc.clear();

	return true;
}

} // namespace fileinfo
