/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/entry_point_json_getter.cpp
 * @brief Methods of EntryPointJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/simple_getter/entry_point_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
EntryPointJsonGetter::EntryPointJsonGetter(FileInformation &fileInfo) : SimpleGetter(fileInfo)
{

}

/**
 * Destructor
 */
EntryPointJsonGetter::~EntryPointJsonGetter()
{

}

std::size_t EntryPointJsonGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	desc.clear();
	info.clear();

	desc.push_back("address");
	desc.push_back("offset");
	desc.push_back("sectionName");
	desc.push_back("sectionIndex");
	desc.push_back("bytes");

	info.push_back(fileinfo.getEpAddressStr(hexWithPrefix));
	info.push_back(fileinfo.getEpOffsetStr(hexWithPrefix));
	info.push_back(replaceNonprintableChars(fileinfo.getEpSectionName()));
	info.push_back(fileinfo.getEpSectionIndex());
	info.push_back(toLower(fileinfo.getEpBytes()));

	return info.size();
}

} // namespace fileinfo
