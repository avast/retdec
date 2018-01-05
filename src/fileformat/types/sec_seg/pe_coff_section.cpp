/**
 * @file src/fileformat/types/sec_seg/pe_coff_section.cpp
 * @brief Class for PE and COFF section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/sec_seg/pe_coff_section.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
PeCoffSection::PeCoffSection() : Section(), peCoffFlags(0)
{

}

/**
 * Get flags of PE/COFF section
 * @return Flags of PE/COFF section
 */
unsigned long long PeCoffSection::getPeCoffFlags() const
{
	return peCoffFlags;
}

/**
 * Set flags
 * @param sPeCoffFlags Flags of PE/COFF section
 */
void PeCoffSection::setPeCoffFlags(unsigned long long sPeCoffFlags)
{
	peCoffFlags = sPeCoffFlags;
}

} // namespace fileformat
} // namespace retdec
