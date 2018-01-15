/**
 * @file src/fileformat/types/sec_seg/elf_segment.cpp
 * @brief Class for ELF segment.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <elfio/elf_types.hpp>

#include "retdec/fileformat/types/sec_seg/elf_segment.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
ElfSegment::ElfSegment() : Segment(), elfType(PT_NULL), elfAlign(0), elfFlags(0)
{

}

/**
 * Get type of ELF section
 * @return Type of ELF section
 */
unsigned long long ElfSegment::getElfType() const
{
	return elfType;
}

/**
 * Get align of section in memory
 * @return Align of section in memory
 */
unsigned long long ElfSegment::getElfAlign() const
{
	return elfAlign;
}

/**
 * Get flags of ELF section
 * @return Flags of ELF section
 */
unsigned long long ElfSegment::getElfFlags() const
{
	return elfFlags;
}

/**
 * Set type of ELF section
 * @param sElfType Type of ELF section
 */
void ElfSegment::setElfType(unsigned long long sElfType)
{
	elfType = sElfType;
}

/**
 * Set align in memory
 * @param sElfAlign Align of section in memory
 */
void ElfSegment::setElfAlign(unsigned long long sElfAlign)
{
	elfAlign = sElfAlign;
}

/**
 * Set flags
 * @param sElfFlags Flags of ELF section
 */
void ElfSegment::setElfFlags(unsigned long long sElfFlags)
{
	elfFlags = sElfFlags;
}

} // namespace fileformat
} // namespace retdec
