/**
 * @file src/fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser32.cpp
 * @brief Methods of PeWrapperParser32 class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_wrapper/pe/pe_template.h"
#include "fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser32.h"

namespace fileinfo {

/**
 * Constructor
 */
PeWrapperParser32::PeWrapperParser32(PeLib::PeHeaderT<32> peHeader32) : PeWrapperParser(), peHeader(peHeader32)
{

}

/**
 * Destructor
 */
PeWrapperParser32::~PeWrapperParser32()
{

}

std::string PeWrapperParser32::getPeType() const
{
	return peFileStatus(peHeader);
}

bool PeWrapperParser32::getSection(const unsigned long long secIndex, FileSection &section) const
{
	return peSectionWithIndex(peHeader, section, secIndex);
}

} // namespace fileinfo
