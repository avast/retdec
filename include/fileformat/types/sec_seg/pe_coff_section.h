/**
 * @file include/fileformat/types/sec_seg/pe_coff_section.h
 * @brief Class for PE and COFF section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_TYPES_SEC_SEG_PE_COFF_SECTION_H
#define FILEFORMAT_TYPES_SEC_SEG_PE_COFF_SECTION_H

#include "fileformat/types/sec_seg/section.h"

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

#endif
