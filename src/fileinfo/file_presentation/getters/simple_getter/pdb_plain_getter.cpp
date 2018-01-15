/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/pdb_plain_getter.cpp
 * @brief Methods of PdbPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/utils/time.h"
#include "fileinfo/file_presentation/getters/simple_getter/pdb_plain_getter.h"

using namespace retdec::utils;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
PdbPlainGetter::PdbPlainGetter(FileInformation &fileInfo) : SimpleGetter(fileInfo)
{

}

/**
 * Destructor
 */
PdbPlainGetter::~PdbPlainGetter()
{

}

std::size_t PdbPlainGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	desc.clear();
	info.clear();

	desc.push_back("Type                     : ");
	desc.push_back("Path to original PDB file: ");
	desc.push_back("GUID                     : ");
	desc.push_back("Version of file (age)    : ");
	desc.push_back("Timestamp                : ");

	info.push_back(fileinfo.getPdbType());
	info.push_back(replaceNonprintableChars(fileinfo.getPdbPath()));
	info.push_back(toLower(fileinfo.getPdbGuid()));
	info.push_back(fileinfo.getPdbAgeStr(std::dec));
	std::time_t timestamp;
	if(strToNum(fileinfo.getPdbTimeStampStr(std::dec), timestamp, std::dec))
	{
		info.push_back(timestampToDate(timestamp));
	}
	else
	{
		info.push_back("");
	}

	return info.size();
}

} // namespace fileinfo
