/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/loader_info_json_getter.cpp
 * @brief Definition of MissingDepsJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/utils/conversion.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/fileformat/utils/other.h"
#include "fileinfo/file_presentation/getters/format.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/missing_deps_json_getter.h"

using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
MissingDepsJsonGetter::MissingDepsJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfMissingDeps());
	numberOfExtraElements.push_back(0);
	title = "items";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("name");
}

std::size_t MissingDepsJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.clear();
	info.clear();

	return info.size();
}

bool MissingDepsJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(std::to_string(recIndex));
	record.push_back(retdec::utils::replaceNonprintableChars(fileinfo.getMissingDepName(recIndex)));
	return true;
}

bool MissingDepsJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
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
