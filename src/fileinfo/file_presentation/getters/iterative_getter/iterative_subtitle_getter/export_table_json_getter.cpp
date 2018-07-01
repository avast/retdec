/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/export_table_json_getter.cpp
 * @brief Methods of ExportTableJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/export_table_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
ExportTableJsonGetter::ExportTableJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredExports());
	numberOfExtraElements.push_back(0);
	title = "exportTable";
	subtitle = "exports";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("name");
	commonHeaderElements.push_back("ordinalNumber");
	commonHeaderElements.push_back("address");
}

/**
 * Destructor
 */
ExportTableJsonGetter::~ExportTableJsonGetter()
{

}

std::size_t ExportTableJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.hasExportTableRecords())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("numberOfExports");
	desc.push_back("crc32");
	desc.push_back("md5");
	desc.push_back("sha256");
	info.push_back(numToStr(fileinfo.getNumberOfStoredExports()));
	info.push_back(fileinfo.getExphashCrc32());
	info.push_back(fileinfo.getExphashMd5());
	info.push_back(fileinfo.getExphashSha256());

	return info.size();
}

bool ExportTableJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(replaceNonprintableChars(fileinfo.getExportName(recIndex)));
	record.push_back(fileinfo.getExportOrdinalNumberStr(recIndex, std::dec));
	record.push_back(fileinfo.getExportAddressStr(recIndex, hexWithPrefix));

	return true;
}

bool ExportTableJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
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
