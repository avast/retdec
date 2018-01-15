/**
 * @file include/retdec/fileformat/types/sec_seg/elf_segment.h
 * @brief Class for ELF segment.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_SEC_SEG_ELF_SEGMENT_H
#define RETDEC_FILEFORMAT_TYPES_SEC_SEG_ELF_SEGMENT_H

#include "retdec/fileformat/types/sec_seg/segment.h"

namespace retdec {
namespace fileformat {

/**
 * Segment in ELF file
 */
class ElfSegment : public Segment
{
	private:
		unsigned long long elfType;  ///< type of ELF segment
		unsigned long long elfAlign; ///< align of segment in memory
		unsigned long long elfFlags; ///< segment flags
	public:
		ElfSegment();

		/// @name Getters
		/// @{
		unsigned long long getElfType() const;
		unsigned long long getElfAlign() const;
		unsigned long long getElfFlags() const;
		/// @}

		/// @name Setters
		/// @{
		void setElfType(unsigned long long sElfType);
		void setElfAlign(unsigned long long sElfAlign);
		void setElfFlags(unsigned long long sElfFlags);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
