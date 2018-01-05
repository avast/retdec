/**
 * @file include/retdec/fileformat/types/sec_seg/elf_section.h
 * @brief Class for ELF section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_SEC_SEG_ELF_SECTION_H
#define RETDEC_FILEFORMAT_TYPES_SEC_SEG_ELF_SECTION_H

#include "retdec/fileformat/types/sec_seg/section.h"

namespace retdec {
namespace fileformat {

/**
 * Section in ELF file
 */
class ElfSection : public Section
{
	private:
		unsigned long long elfType;          ///< type of ELF section
		unsigned long long elfAlign;         ///< align of section in memory
		unsigned long long elfFlags;         ///< section flags
		unsigned long long elfLink;          ///< link to another section
		unsigned long long numberOfSections; ///< total number of sections in input file
		unsigned long long archByteSize;     ///< byte size of target architecture
	public:
		ElfSection();

		/// @name Virtual query methods
		/// @{
		virtual bool isValid(const FileFormat *sOwner) const override;
		/// @}

		/// @name Getters
		/// @{
		unsigned long long getElfType() const;
		unsigned long long getElfAlign() const;
		unsigned long long getElfFlags() const;
		unsigned long long getElfLink() const;
		unsigned long long getNumberOfSections() const;
		unsigned long long getArchByteSize() const;
		/// @}

		/// @name Setters
		/// @{
		void setElfType(unsigned long long sElfType);
		void setElfAlign(unsigned long long sElfAlign);
		void setElfFlags(unsigned long long sElfFlags);
		void setElfLink(unsigned long long sElfLink);
		void setNumberOfSections(unsigned long long sNumberOfSections);
		void setArchByteSize(unsigned long long sArchByteSize);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
