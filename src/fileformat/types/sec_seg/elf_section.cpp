/**
 * @file src/fileformat/types/sec_seg/elf_section.cpp
 * @brief Class for ELF section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <elfio/elf_types.hpp>

#include "retdec/utils/math.h"
#include "retdec/fileformat/types/sec_seg/elf_section.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
ElfSection::ElfSection() : Section(), elfType(SHT_NULL), elfAlign(0), elfFlags(0), elfLink(0),
	numberOfSections(0), archByteSize(0)
{

}

bool ElfSection::isValid(const FileFormat *sOwner) const
{
	if(!Section::isValid(sOwner) || (getElfAlign() && (getAddress() % getElfAlign())) ||
		(getNumberOfSections() && getElfLink() >= getNumberOfSections()))
	{
		return false;
	}
	if(getElfFlags() & SHF_EXECINSTR)
	{
		if(getElfType() == SHT_DYNAMIC || (getElfType() == SHT_NULL && getIndex()) || getSizeInFile() < getArchByteSize())
		{
			return false;
		}
	}

	return isPowerOfTwoOrZero(getElfAlign());
}

/**
 * Get type of ELF section
 * @return Type of ELF section
 */
unsigned long long ElfSection::getElfType() const
{
	return elfType;
}

/**
 * Get align of section in memory
 * @return Align of section in memory
 */
unsigned long long ElfSection::getElfAlign() const
{
	return elfAlign;
}

/**
 * Get flags of ELF section
 * @return Flags of ELF section
 */
unsigned long long ElfSection::getElfFlags() const
{
	return elfFlags;
}

/**
 * Get link to another section in ELF file
 * @return Link to another section in ELF file
 */
unsigned long long ElfSection::getElfLink() const
{
	return elfLink;
}

/**
 * Get total number of sections in ELF file
 * @return Total number of sections in ELF file
 */
unsigned long long ElfSection::getNumberOfSections() const
{
	return numberOfSections;
}

/**
 * Get byte size of target architecture
 * @return Byte size of target architecture
 */
unsigned long long ElfSection::getArchByteSize() const
{
	return archByteSize;
}

/**
 * Set type of ELF section
 * @param sElfType Type of ELF section
 */
void ElfSection::setElfType(unsigned long long sElfType)
{
	elfType = sElfType;
}

/**
 * Set align in memory
 * @param sElfAlign Align of section in memory
 */
void ElfSection::setElfAlign(unsigned long long sElfAlign)
{
	elfAlign = sElfAlign;
}

/**
 * Set flags
 * @param sElfFlags Flags of ELF section
 */
void ElfSection::setElfFlags(unsigned long long sElfFlags)
{
	elfFlags = sElfFlags;
}

/**
 * Set link to another section
 * @param sElfLink Link to another section in ELF file
 */
void ElfSection::setElfLink(unsigned long long sElfLink)
{
	elfLink = sElfLink;
}

/**
 * Set total number of sections in input file
 * @param sNumberOfSections Total number of sections in input file
 */
void ElfSection::setNumberOfSections(unsigned long long sNumberOfSections)
{
	numberOfSections = sNumberOfSections;
}

/**
 * Set byte size of target architecture
 * @param sArchByteSize Byte size of target architecture
 */
void ElfSection::setArchByteSize(unsigned long long sArchByteSize)
{
	archByteSize = sArchByteSize;
}

} // namespace fileformat
} // namespace retdec
