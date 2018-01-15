/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/dotnet_json_getter.cpp
 * @brief Methods of DotnetJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/simple_getter/dotnet_json_getter.h"

using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
DotnetJsonGetter::DotnetJsonGetter(FileInformation &fileInfo) : SimpleGetter(fileInfo)
{

}

/**
 * Destructor
 */
DotnetJsonGetter::~DotnetJsonGetter()
{

}

std::size_t DotnetJsonGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	desc.clear();
	info.clear();

	if (!fileinfo.isDotnetUsed())
	{
		return 0;
	}

	desc.push_back("runtimeVersion");
	desc.push_back("metadataHeaderAddress");
	info.push_back(fileinfo.getDotnetRuntimeVersion());
	info.push_back(fileinfo.getDotnetMetadataHeaderAddressStr(hexWithPrefix));

	desc.push_back("moduleVersionId");
	info.push_back(fileinfo.getDotnetModuleVersionId());
	if (fileinfo.hasDotnetTypeLibId())
	{
		desc.push_back("typeLibId");
		info.push_back(fileinfo.getDotnetTypeLibId());
	}

	return info.size();
}

} // namespace fileinfo
