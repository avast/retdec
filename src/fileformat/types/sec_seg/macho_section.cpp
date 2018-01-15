/**
 * @file src/fileformat/types/sec_seg/macho_section.cpp
 * @brief Class for Mach-O section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/sec_seg/macho_section.h"

namespace retdec {
namespace fileformat {

MachOSection::MachOSection() : segname(), align(0), reloff(0), nreloc(0),
	flags(0), reserved1(0), reserved2(0)
{

}

/**
 * Get name of segment this section is placed in.
 * @return Segment name.
 */
std::string MachOSection::getSegmentName() const
{
	return segname;
}

/**
 * Get section's byte alignment
 * @return Byte alignment as power of 2
 */
unsigned long long MachOSection::getAlignment() const
{
	return align;
}

/**
 * Get offset of first relocation
 * @return Offset of first relocation
 */
unsigned long long MachOSection::getRelocationOffset() const
{
	return reloff;
}

/**
 * Get number of relocations
 * @return Number of relocations
 */
unsigned long long MachOSection::getNumberOfRelocations() const
{
	return nreloc;
}

/**
 * Get Mach-O flags
 * @return Mach-O flags
 */
unsigned long long MachOSection::getMachOFlags() const
{
	return flags;
}

/**
 * Get field reserved1
 * @return Field reserved1
 */
unsigned long long MachOSection::getReserved1() const
{
	return reserved1;
}

/**
 * Get field reserved2
 * @return Field reserved2
 */
unsigned long long MachOSection::getReserved2() const
{
	return reserved2;
}

/**
 * Set segment name this section is placed in.
 * @param segmentName Segment name.
 */
void MachOSection::setSegmentName(const std::string& segmentName)
{
	segname = segmentName;
}

/**
 * Set section's byte alignment
 * @param alignment Byte alignment as power of 2
 */
void MachOSection::setAlignment(unsigned long long alignment)
{
	align = alignment;
}

/**
 * Set offset of first relocation
 * @param offset Offset of first relocation
 */
void MachOSection::setRelocationOffset(unsigned long long offset)
{
	reloff = offset;
}

/**
 * Set number of relocations
 * @param number Number of relocations
 */
void MachOSection::setNumberOfRelocations(unsigned long long number)
{
	nreloc = number;
}

/**
 * Set Mach-O flags
 * @param flags Mach-O flags
 */
void MachOSection::setMachOFlags(unsigned long long flags)
{
	this->flags = flags;
}

/**
 * Set reserved1 field
 * @param reserved1 Reserved1 field
 */
void MachOSection::setReserved1(unsigned long long reserved1)
{
	this->reserved1 = reserved1;
}

/**
 * Set reserved2 field
 * @param reserved2 Reserved2 field
 */
void MachOSection::setReserved2(unsigned long long reserved2)
{
	this->reserved2 = reserved2;
}

} // namespace fileformat
} // namespace retdec
