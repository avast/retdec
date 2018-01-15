/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/dotnet_plain_getter.cpp
 * @brief Methods of DotnetPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/simple_getter/dotnet_plain_getter.h"

using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
DotnetPlainGetter::DotnetPlainGetter(FileInformation &fileInfo) : SimpleGetter(fileInfo)
{

}

/**
 * Destructor
 */
DotnetPlainGetter::~DotnetPlainGetter()
{

}

std::size_t DotnetPlainGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	desc.clear();
	info.clear();

	if (!fileinfo.isDotnetUsed())
	{
		return 0;
	}

	desc.push_back("Runtime version                                              : ");
	desc.push_back("Metadata header address                                      : ");
	info.push_back(fileinfo.getDotnetRuntimeVersion());
	info.push_back(fileinfo.getDotnetMetadataHeaderAddressStr(hexWithPrefix));

	if (fileinfo.hasDotnetMetadataStream())
	{
		desc.push_back("Metadata (#~) stream offset (relative to metadata header)    : ");
		desc.push_back("Metadata (#~) stream size                                    : ");
		info.push_back(fileinfo.getDotnetMetadataStreamOffsetStr(hexWithPrefix));
		info.push_back(fileinfo.getDotnetMetadataStreamSizeStr(hexWithPrefix));
	}
	if (fileinfo.hasDotnetStringStream())
	{
		desc.push_back("String (#Strings) stream offset (relative to metadata header): ");
		desc.push_back("String (#Strings) stream size                                : ");
		info.push_back(fileinfo.getDotnetStringStreamOffsetStr(hexWithPrefix));
		info.push_back(fileinfo.getDotnetStringStreamSizeStr(hexWithPrefix));
	}
	if (fileinfo.hasDotnetBlobStream())
	{
		desc.push_back("Blob (#Blob) stream offset (relative to metadata header)     : ");
		desc.push_back("Blob (#Blob) stream size                                     : ");
		info.push_back(fileinfo.getDotnetBlobStreamOffsetStr(hexWithPrefix));
		info.push_back(fileinfo.getDotnetBlobStreamSizeStr(hexWithPrefix));
	}
	if (fileinfo.hasDotnetGuidStream())
	{
		desc.push_back("GUID (#GUID) stream offset (relative to metadata header)     : ");
		desc.push_back("GUID (#GUID) stream size                                     : ");
		info.push_back(fileinfo.getDotnetGuidStreamOffsetStr(hexWithPrefix));
		info.push_back(fileinfo.getDotnetGuidStreamSizeStr(hexWithPrefix));
	}
	if (fileinfo.hasDotnetUserStringStream())
	{
		desc.push_back("User string (#US) stream offset (relative to metadata header): ");
		desc.push_back("User string (#US) stream size                                : ");
		info.push_back(fileinfo.getDotnetUserStringStreamOffsetStr(hexWithPrefix));
		info.push_back(fileinfo.getDotnetUserStringStreamSizeStr(hexWithPrefix));
	}

	desc.push_back("Module version ID                                            : ");
	info.push_back(fileinfo.getDotnetModuleVersionId());
	if (fileinfo.hasDotnetTypeLibId())
	{
		desc.push_back("TypeLib ID                                                   : ");
		info.push_back(fileinfo.getDotnetTypeLibId());
	}

	return info.size();
}

} // namespace fileinfo
