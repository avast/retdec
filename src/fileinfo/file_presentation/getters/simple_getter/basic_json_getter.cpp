/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/basic_json_getter.cpp
 * @brief Methods of BasicJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/simple_getter/basic_json_getter.h"

using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
BasicJsonGetter::BasicJsonGetter(FileInformation &fileInfo) : SimpleGetter(fileInfo)
{

}

/**
 * Destructor
 */
BasicJsonGetter::~BasicJsonGetter()
{

}

std::size_t BasicJsonGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	desc.clear();
	info.clear();

	desc.push_back("crc32");
	desc.push_back("md5");
	desc.push_back("sha256");
	desc.push_back("fileFormat");
	desc.push_back("fileClass");
	desc.push_back("fileType");
	desc.push_back("architecture");
	desc.push_back("endianness");
	desc.push_back("imageBaseAddress");

	info.push_back(fileinfo.getCrc32());
	info.push_back(fileinfo.getMd5());
	info.push_back(fileinfo.getSha256());
	info.push_back(fileinfo.getFileFormat());
	info.push_back(fileinfo.getFileClass());
	info.push_back(fileinfo.getFileType());
	info.push_back(fileinfo.getTargetArchitecture());
	info.push_back(fileinfo.getEndianness());
	info.push_back(fileinfo.getImageBaseStr(hexWithPrefix));

	return info.size();
}

} // namespace fileinfo
