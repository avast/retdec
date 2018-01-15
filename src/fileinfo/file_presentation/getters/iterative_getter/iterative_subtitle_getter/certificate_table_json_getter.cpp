/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/certificate_table_json_getter.cpp
 * @brief Methods of CertificateTableJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/certificate_table_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
CertificateTableJsonGetter::CertificateTableJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredCertificates());
	numberOfExtraElements.push_back(0);
	title = "certificateTable";
	subtitle = "certificates";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("validSince");
	commonHeaderElements.push_back("validUntil");
	commonHeaderElements.push_back("publicKey");
	commonHeaderElements.push_back("publicKeyAlgorithm");
	commonHeaderElements.push_back("signatureAlgorithm");
	commonHeaderElements.push_back("serialNumber");
	commonHeaderElements.push_back("issuer");
	commonHeaderElements.push_back("subject");
	commonHeaderElements.push_back("sha1");
	commonHeaderElements.push_back("sha256");
}

/**
 * Destructor
 */
CertificateTableJsonGetter::~CertificateTableJsonGetter()
{

}

std::size_t CertificateTableJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.hasCertificateTableRecords())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("numberOfCertificates");
	desc.push_back("signerCertificateIndex");
	desc.push_back("counterSignerCertificateIndex");
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

bool CertificateTableJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(fileinfo.getCertificateValidSince(recIndex));
	record.push_back(fileinfo.getCertificateValidUntil(recIndex));
	record.push_back(fileinfo.getCertificatePublicKey(recIndex));
	record.push_back(fileinfo.getCertificatePublicKeyAlgorithm(recIndex));
	record.push_back(fileinfo.getCertificateSignatureAlgorithm(recIndex));
	record.push_back(fileinfo.getCertificateSerialNumber(recIndex));
	record.push_back(fileinfo.getCertificateIssuerRawStr(recIndex));
	record.push_back(fileinfo.getCertificateSubjectRawStr(recIndex));
	record.push_back(fileinfo.getCertificateSha1Digest(recIndex));
	record.push_back(fileinfo.getCertificateSha256Digest(recIndex));

	return true;
}

bool CertificateTableJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
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
