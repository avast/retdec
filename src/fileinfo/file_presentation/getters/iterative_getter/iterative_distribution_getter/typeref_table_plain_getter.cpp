/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/typeref_table_plain_getter.cpp
 * @brief Methods of TypeRefTablePlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/typeref_table_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

const std::size_t distributionArray[] = {6, 40, 40, 45};
const std::string headerArray[] = {"i", "name", "nameSpace", "libName"};
const std::string headerDesc[] = {"index", "name of dotnet import", "namespace of type", "name of library from which is import imported"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
TypeRefTablePlainGetter::TypeRefTablePlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredDotnetImportedClasses());
	numberOfExtraElements.push_back(0);
	title = "TypeRef table";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

std::size_t TypeRefTablePlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.hasDotnetTypeRefTableRecords())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of dotnet imports: ");
	desc.push_back("CRC32                   : ");
	desc.push_back("MD5                     : ");
	desc.push_back("SHA256                  : ");
	info.push_back(std::to_string(fileinfo.getNumberOfStoredDotnetImportedClasses()));
	info.push_back(fileinfo.getDotnetTypeRefhashCrc32());
	info.push_back(fileinfo.getDotnetTypeRefhashMd5());
	info.push_back(fileinfo.getDotnetTypeRefhashSha256());

	return info.size();
}

bool TypeRefTablePlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(std::to_string(recIndex));
	record.push_back(replaceNonprintableChars(fileinfo.getDotnetImportedClassNameWithParentClassIndex(recIndex)));
	record.push_back(replaceNonprintableChars(fileinfo.getDotnetImportedClassNameSpace(recIndex)));
	record.push_back(replaceNonprintableChars(fileinfo.getDotnetImportedClassLibName(recIndex)));

	return true;
}

bool TypeRefTablePlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
