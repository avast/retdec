/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/tls_info_plain_getter.cpp
 * @brief Methods of TlsInfoPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/tls_info_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

const std::size_t distributionArray[] = {6, 20};
const std::string headerArray[] = {"i", "address"};
const std::string headerDesc[] = {"index", "address of callback"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
TlsInfoPlainGetter::TlsInfoPlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getTlsNumberOfCallBacks());
	numberOfExtraElements.push_back(0);
	title = "TLS info";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

std::size_t TlsInfoPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.isTlsUsed())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of callbacks          : ");
	desc.push_back("Address of start of raw data : ");
	desc.push_back("Address of end of raw data   : ");
	desc.push_back("Address of callbacks         : ");
	desc.push_back("Address of index             : ");
	desc.push_back("Size of zero fill            : ");
	desc.push_back("Characteristics              : ");
	info.push_back(std::to_string(fileinfo.getTlsNumberOfCallBacks()));
	info.push_back(fileinfo.getTlsRawDataStartAddrStr(hexWithPrefix));
	info.push_back(fileinfo.getTlsRawDataEndAddrStr(hexWithPrefix));
	info.push_back(fileinfo.getTlsIndexAddrStr(hexWithPrefix));
	info.push_back(fileinfo.getTlsCallBacksAddrStr(hexWithPrefix));
	info.push_back(fileinfo.getTlsZeroFillSizeStr(std::dec));
	info.push_back(fileinfo.getTlsCharacteristicsStr());

	return info.size();
}

bool TlsInfoPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(std::to_string(recIndex));
	record.push_back(fileinfo.getTlsCallBackAddrStr(recIndex, hexWithPrefix));
	return true;
}

bool TlsInfoPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
{
	if(structIndex >= numberOfStructures)
	{
		return false;
	}

	desc.clear();
	abbv.clear();

	return true;
}

} // namespace fileinfo
} // namespace retdec
