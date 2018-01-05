/**
 * @file src/fileinfo/file_wrapper/elf_wrapper.h
 * @brief Definition of ElfWrapper class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_WRAPPER_ELF_WRAPPER_H
#define FILEINFO_FILE_WRAPPER_ELF_WRAPPER_H

#include "retdec/fileformat/file_format/elf/elf_format.h"

namespace fileinfo {

/**
 * Wrapper for parsing ELF files
 */
class ElfWrapper : public retdec::fileformat::ElfFormat
{
	public:
		ElfWrapper(std::string pathToFile, retdec::fileformat::LoadFlags loadFlags);
		virtual ~ElfWrapper() override;

		/// @name Detection methods
		/// @{
		ELFIO::segment* getFileSegment(unsigned long long segIndex) const;
		ELFIO::section* getFileSection(unsigned long long secIndex) const;
		ELFIO::symbol_section_accessor* getSymbolTable(unsigned long long secIndex) const;
		ELFIO::relocation_section_accessor* getRelocationTable(unsigned long long secIndex) const;
		ELFIO::dynamic_section_accessor* getDynamicSection(unsigned long long secIndex) const;
		/// @}
};

} // namespace fileinfo

#endif
