/**
 * @file src/fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser64.cpp
 * @brief Methods of PeWrapperParser64 class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_wrapper/pe/pe_template.h"
#include "fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser64.h"

namespace fileinfo {

/**
 * Constructor
 */
PeWrapperParser64::PeWrapperParser64(PeLib::PeHeaderT<64> peHeader64) : PeWrapperParser(), peHeader(peHeader64)
{

}

/**
 * Destructor
 */
PeWrapperParser64::~PeWrapperParser64()
{

}

std::string PeWrapperParser64::getPeType() const
{
	return peFileStatus(peHeader);
}

bool PeWrapperParser64::getSection(const unsigned long long secIndex, FileSection &section) const
{
	return peSectionWithIndex(peHeader, section, secIndex);
}

} // namespace fileinfo
