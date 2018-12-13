/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/visual_basic_plain_getter.cpp
 * @brief Methods of VisualBasicPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/simple_getter/visual_basic_plain_getter.h"

using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
VisualBasicPlainGetter::VisualBasicPlainGetter(FileInformation &fileInfo) : SimpleGetter(fileInfo)
{

}

/**
 * Destructor
 */
VisualBasicPlainGetter::~VisualBasicPlainGetter()
{

}

std::size_t VisualBasicPlainGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	desc.clear();
	info.clear();

	if (!fileinfo.isVisualBasicUsed())
	{
		return 0;
	}

	desc.push_back("Super Cool Info                                              : ");
	desc.push_back("More Super Cool Info                                         : ");
	info.push_back("TODO");
	info.push_back("TODO");

	return info.size();
}

} // namespace fileinfo
