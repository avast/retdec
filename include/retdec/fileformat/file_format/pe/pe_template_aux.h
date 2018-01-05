/**
 * @file include/retdec/fileformat/file_format/pe/pe_template_aux.h
 * @brief Auxiliary functions for PE files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_TEMPLATE_AUX_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_TEMPLATE_AUX_H

#include <pelib/PeLib.h>

namespace retdec {
namespace fileformat {

/**
 * Get name of selected section
 * @param peHeader PE reader
 * @param name Parameter for store the result
 * @param sectionIndex Index of selected section (indexed from 0)
 * @return @c true if section index is valid, @c false otherwise
 */
template<int bits> bool peSectionName(const PeLib::PeHeaderT<bits> &peHeader, std::string &name, unsigned long long sectionIndex)
{
	if(sectionIndex >= peHeader.getNumberOfSections())
	{
		return false;
	}

	name = peHeader.getSectionNameFromStringTable(sectionIndex);
	if(name.empty())
	{
		name = peHeader.getSectionName(sectionIndex);
	}

	return true;
}

} // namespace fileformat
} // namespace retdec

#endif
