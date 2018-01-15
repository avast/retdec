/**
 * @file include/retdec/fileformat/types/sec_seg/pe_coff_section.h
 * @brief Class for PE and COFF section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_SEC_SEG_PE_COFF_SECTION_H
#define RETDEC_FILEFORMAT_TYPES_SEC_SEG_PE_COFF_SECTION_H

#include "retdec/fileformat/types/sec_seg/section.h"

namespace retdec {
namespace fileformat {

/**
 * Section in PE and COFF file
 */
class PeCoffSection : public Section
{
	private:
		unsigned long long peCoffFlags; ///< section flags
	public:
		PeCoffSection();

		/// @name Getters
		/// @{
		unsigned long long getPeCoffFlags() const;
		/// @}

		/// @name Setters
		/// @{
		void setPeCoffFlags(unsigned long long sPeCoffFlags);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
