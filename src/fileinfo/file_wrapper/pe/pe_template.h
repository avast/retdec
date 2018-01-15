/**
 * @file src/fileinfo/file_wrapper/pe/pe_template.h
 * @brief Template functions for PE files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_WRAPPER_PE_PE_TEMPLATE_H
#define FILEINFO_FILE_WRAPPER_PE_PE_TEMPLATE_H

#include "retdec/fileformat/file_format/pe/pe_template_aux.h"
#include "fileinfo/file_information/file_information_types/file_section.h"

namespace fileinfo {

/**
 * Get status of file
 * @param peHeader PE reader
 * @return Status of file ("PE32", "ROM image", "PE32+" or empty string if status of file is unknown)
 */
template<int bits> std::string peFileStatus(const PeLib::PeHeaderT<bits> &peHeader)
{
	switch(peHeader.getMagic())
	{
		case 0x10B:
			return "PE32";
		case 0x107:
			return "ROM image";
		case 0x20B:
			return "PE32+";
		default:
			return "";
	}
}

/**
 * Get information about section with index @a sectionIndex
 * @param peHeader PE reader
 * @param section Class for save information about section
 * @param sectionIndex Index of section (indexed from 0)
 * @return @c true if section index is valid and section was detected, @c false otherwise
 *
 * Only flag values and size are set. Function does not set flags descriptors or their abbreviations.
 * Previously set descriptors and abbreviations are deleted.
 */
template<int bits> bool peSectionWithIndex(const PeLib::PeHeaderT<bits> &peHeader, FileSection &section, unsigned long long sectionIndex)
{
	std::string sectionName;
	if(!retdec::fileformat::peSectionName(peHeader, sectionName, sectionIndex))
	{
		return false;
	}
	const unsigned long long sectionFlagsSize = 32;

	section.setIndex(sectionIndex);
	section.setName(sectionName);
	section.setStartAddress(peHeader.getVirtualAddress(sectionIndex) + peHeader.getImageBase());
	section.setSizeInMemory(peHeader.getVirtualSize(sectionIndex));
	section.setOffset(peHeader.getPointerToRawData(sectionIndex));
	section.setSizeInFile(peHeader.getSizeOfRawData(sectionIndex));
	section.setRelocationsOffset(peHeader.getPointerToRelocations(sectionIndex));
	section.setNumberOfRelocations(peHeader.getNumberOfRelocations(sectionIndex));
	section.setLineNumbersOffset(peHeader.getPointerToLinenumbers(sectionIndex));
	section.setNumberOfLineNumbers(peHeader.getNumberOfLinenumbers(sectionIndex));
	section.setFlagsSize(sectionFlagsSize);
	section.setFlags(peHeader.getCharacteristics(sectionIndex));
	section.clearFlagsDescriptors();
	return true;
}

} // namespace fileinfo

#endif
