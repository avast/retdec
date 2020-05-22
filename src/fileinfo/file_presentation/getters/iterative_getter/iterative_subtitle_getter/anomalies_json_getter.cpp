/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/anomalies_json_getter.cpp
 * @brief Methods of AnomaliesJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/anomalies_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
AnomaliesJsonGetter::AnomaliesJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileInfo.getNumberOfAnomalies());
	numberOfExtraElements.push_back(0);
	title = "anomalyTable";
	subtitle = "anomalies";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("identifier");
	commonHeaderElements.push_back("description");
}

std::size_t AnomaliesJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || fileinfo.getNumberOfAnomalies() == 0)
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("numberOfAnomalies");
	info.push_back(std::to_string(fileinfo.getNumberOfAnomalies()));

	return info.size();
}

bool AnomaliesJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(std::to_string(recIndex));
	record.push_back(fileinfo.getAnomalyIdentifier(recIndex));
	record.push_back(fileinfo.getAnomalyDescription(recIndex));

	return true;
}

bool AnomaliesJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
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
} // namespace retdec
