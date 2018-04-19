/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/basic_plain_getter.cpp
 * @brief Methods of BasicPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/simple_getter/basic_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
BasicPlainGetter::BasicPlainGetter(FileInformation &fileInfo) : SimpleGetter(fileInfo)
{

}

/**
 * Destructor
 */
BasicPlainGetter::~BasicPlainGetter()
{

}

std::size_t BasicPlainGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	const char * loaderErrorUserFriendly = fileinfo.getLoaderErrorInfo().loaderErrorUserFriendly;

	desc.clear();
	info.clear();

	desc.push_back("CRC32                    : ");
	desc.push_back("MD5                      : ");
	desc.push_back("SHA256                   : ");
	desc.push_back("File format              : ");
	desc.push_back("File class               : ");
	desc.push_back("File type                : ");

	// Save the title for loader error (if there was a loader error detected)
	if(loaderErrorUserFriendly != nullptr)
		desc.push_back("Loader error             : ");

	desc.push_back("Architecture             : ");
	desc.push_back("Endianness               : ");
	desc.push_back("Image base address       : ");
	desc.push_back("Entry point address      : ");
	desc.push_back("Entry point offset       : ");
	desc.push_back("Entry point section name : ");
	desc.push_back("Entry point section index: ");
	desc.push_back("Bytes on entry point     : ");

	info.push_back(fileinfo.getCrc32());
	info.push_back(fileinfo.getMd5());
	info.push_back(fileinfo.getSha256());
	info.push_back(fileinfo.getFileFormat());
	info.push_back(fileinfo.getFileClass());
	info.push_back(fileinfo.getFileType());

	// Save the text loader error
	if(loaderErrorUserFriendly != nullptr)
		info.push_back(loaderErrorUserFriendly);

	info.push_back(fileinfo.getTargetArchitecture());
	info.push_back(fileinfo.getEndianness());
	info.push_back(fileinfo.getImageBaseStr(hexWithPrefix));
	info.push_back(fileinfo.getEpAddressStr(hexWithPrefix));
	const auto epOffset = fileinfo.getEpOffsetStr(hexWithPrefix);
	info.push_back(epOffset);
	auto epSecName = replaceNonprintableChars(fileinfo.getEpSectionName());
	auto epSecIndex = fileinfo.getEpSectionIndex();
	if(!epOffset.empty())
	{
		if(epSecName.empty())
		{
			if(epSecIndex.empty())
			{
				epSecName = "(entry point does not belong to any section)";
			}
			else
			{
				epSecName = "(entry point section does not have a name)";
			}
		}
		if(epSecIndex.empty())
		{
			epSecIndex = "(entry point does not belong to any section)";
		}
	}
	info.push_back(epSecName);
	info.push_back(epSecIndex);
	info.push_back(toLower(fileinfo.getEpBytes()));

	return info.size();
}

} // namespace fileinfo
