/**
 * @file include/retdec/fileformat/types/sec_seg/macho_section.h
 * @brief Class for Mach-O section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_SEC_SEG_MACHO_SECTION_H
#define RETDEC_FILEFORMAT_TYPES_SEC_SEG_MACHO_SECTION_H

#include "retdec/fileformat/types/sec_seg/section.h"

namespace retdec {
namespace fileformat {

/**
 * Section in Mach-O file
 */
class MachOSection : public Section
{
	private:
		std::string segname;          ///< Name of the segment this section is placed in
		unsigned long long align;     ///< Byte alignment as power of two
		unsigned long long reloff;    ///< File offset of first relocation entry
		unsigned long long nreloc;    ///< Number of relocations
		unsigned long long flags;     ///< Mach-O section flags
		unsigned long long reserved1; ///< Various interpretations (depends on flags)
		unsigned long long reserved2; ///< Various interpretations (depends on flags)
	public:
		MachOSection();

		/// @name Getters
		/// @{
		std::string getSegmentName() const;
		unsigned long long getAlignment() const;
		unsigned long long getRelocationOffset() const;
		unsigned long long getNumberOfRelocations() const;
		unsigned long long getMachOFlags() const;
		unsigned long long getReserved1() const;
		unsigned long long getReserved2() const;
		/// @}

		/// @name Setters
		/// @{
		void setSegmentName(const std::string& segmentName);
		void setAlignment(unsigned long long alignment);
		void setRelocationOffset(unsigned long long offset);
		void setNumberOfRelocations(unsigned long long number);
		void setMachOFlags(unsigned long long flags);
		void setReserved1(unsigned long long reserved1);
		void setReserved2(unsigned long long reserved2);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
