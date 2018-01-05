/**
 * @file src/fileinfo/file_information/file_information_types/file_section.cpp
 * @brief Class for file section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/file_section.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
FileSection::FileSection() : index(std::numeric_limits<unsigned long long>::max()),
								offset(std::numeric_limits<unsigned long long>::max()),
								sizeInFile(std::numeric_limits<unsigned long long>::max()),
								entrySize(std::numeric_limits<unsigned long long>::max()),
								startAddress(std::numeric_limits<unsigned long long>::max()),
								sizeInMemory(std::numeric_limits<unsigned long long>::max()),
								relocationsOffset(std::numeric_limits<unsigned long long>::max()),
								numberOfRelocations(std::numeric_limits<unsigned long long>::max()),
								lineNumbersOffset(std::numeric_limits<unsigned long long>::max()),
								numberOfLineNumbers(std::numeric_limits<unsigned long long>::max()),
								memoryAlignment(std::numeric_limits<unsigned long long>::max()),
								linkToSection(std::numeric_limits<unsigned long long>::max()),
								extraInfo(std::numeric_limits<unsigned long long>::max()),
								lineOffset(std::numeric_limits<unsigned long long>::max()),
								relocationsLineOffset(std::numeric_limits<unsigned long long>::max())
{

}

/**
 * Destructor
 */
FileSection::~FileSection()
{

}

/**
 * Get section name
 * @return Section name
 */
std::string FileSection::getName() const
{
	return sectionName;
}

/**
 * Get section type
 * @return Section type
 */
std::string FileSection::getType() const
{
	return sectionType;
}

/**
 * Get CRC32
 * @return CRC32 of section content
 */
std::string FileSection::getCrc32() const
{
	return crc32;
}

/**
 * Get MD5
 * @return MD5 of section content
 */
std::string FileSection::getMd5() const
{
	return md5;
}

/**
 * Get SHA256
 * @return SHA256 of section content
 */
std::string FileSection::getSha256() const
{
	return sha256;
}

/**
 * Get section index
 * @return Index of file section
 */
std::string FileSection::getIndexStr() const
{
	return getNumberAsString(index);
}

/**
 * Get offset of section in file
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Offset of section
 */
std::string FileSection::getOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(offset, format);
}

/**
 * Get section size in file
 * @return Section size in file
 */
std::string FileSection::getSizeInFileStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(sizeInFile, format);
}

/**
 * Get size of one entry of section
 * @return Size of one entry of section
 */
std::string FileSection::getEntrySizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(entrySize, format);
}

/**
 * Get start address of section in memory
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Start address of section in memory
 */
std::string FileSection::getStartAddressStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(startAddress, format);
}

/**
 * Get size of section in memory
 * @return Size of section in memory
 */
std::string FileSection::getSizeInMemoryStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(sizeInMemory, format);
}

/**
 * Get offset of relocation entries for section
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Offset of relocation entries for section
 */
std::string FileSection::getRelocationsOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(relocationsOffset, format);
}

/**
 * Get number of relocation entries for section
 * @return Number of relocation entries for section
 */
std::string FileSection::getNumberOfRelocationsStr() const
{
	return getNumberAsString(numberOfRelocations);
}

/**
 * Get offset of line-number entries for section
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Offset of line-number entries for section
 */
std::string FileSection::getLineNumbersOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(lineNumbersOffset, format);
}

/**
 * Get number of line-number entries for section
 * @return Number of line-number entries for section
 */
std::string FileSection::getNumberOfLineNumbersStr() const
{
	return getNumberAsString(numberOfLineNumbers);
}

/**
 * Get section memory alignment
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Section memory alignmnet
 */
std::string FileSection::getMemoryAlignmentStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(memoryAlignment, format);
}

/**
 * Get link to another section
 * @return Link to another section
 */
std::string FileSection::getLinkToAnotherSectionStr() const
{
	return getNumberAsString(linkToSection);
}

/**
 * Get section extra information
 * @return Section extra information
 */
std::string FileSection::getExtraInfoStr() const
{
	return getNumberAsString(extraInfo);
}

/**
 * Get start line of section in file
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Start line of section in file
 */
std::string FileSection::getLineOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(lineOffset, format);
}

/**
 * Get start line of relocations for this section
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Start line of relocations for this section
 */
std::string FileSection::getRelocationsLineOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(relocationsLineOffset, format);
}

/**
 * Get flags size
 * @return Flags size
 */
unsigned long long FileSection::getFlagsSize() const
{
	return flags.getSize();
}

/**
 * Get flags of section
 * @return Flags as number
 */
unsigned long long FileSection::getFlags() const
{
	return flags.getFlags();
}

/**
 * Get flags of section
 * @return Flags as string
 */
std::string FileSection::getFlagsStr() const
{
	return flags.getFlagsStr();
}

/**
 * Get number of flags descriptors
 * @return Number of flags descriptors
 */
std::size_t FileSection::getNumberOfFlagsDescriptors() const
{
	return flags.getNumberOfDescriptors();
}

/**
 * Get flags descriptors and its abbreviations
 * @param desc Vector for save descriptors
 * @param abb Vector for save abbreviations of descriptors
 *
 * It is guaranteed that the number of stored descriptors and abbreviations are the same
 */
void FileSection::getFlagsDescriptors(std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	flags.getDescriptors(desc, abb);
}

/**
 * Set section name
 * @param name Section name
 */
void FileSection::setName(std::string name)
{
	sectionName = name;
}

/**
 * Set section type
 * @param type Section type
 */
void FileSection::setType(std::string type)
{
	sectionType = type;
}

/**
 * Set section CRC32
 * @param sectionCrc32 CRC32 of section content
 */
void FileSection::setCrc32(std::string sectionCrc32)
{
	crc32 = sectionCrc32;
}

/**
 * Set section MD5
 * @param sectionMd5 MD5 of section content
 */
void FileSection::setMd5(std::string sectionMd5)
{
	md5 = sectionMd5;
}

/**
 * Set section SHA256
 * @param sectionSha256 SHA256 of section content
 */
void FileSection::setSha256(std::string sectionSha256)
{
	sha256 = sectionSha256;
}

/**
 * Set index of section
 * @param sectionIndex Index of section
 */
void FileSection::setIndex(unsigned long long sectionIndex)
{
	index = sectionIndex;
}

/**
 * Set section offset
 * @param sectionOffset Section offset
 */
void FileSection::setOffset(unsigned long long sectionOffset)
{
	offset = sectionOffset;
}

/**
 * Set section size in file
 * @param size Section size in file
 */
void FileSection::setSizeInFile(unsigned long long size)
{
	sizeInFile = size;
}

/**
 * Set size of one entry in section
 * @param sizeOfOneEntry Size of one entry in section
 */
void FileSection::setEntrySize(unsigned long long sizeOfOneEntry)
{
	entrySize = sizeOfOneEntry;
}

/**
 * Set section memory address
 * @param memoryAddress Start address of section in memory
 */
void FileSection::setStartAddress(unsigned long long memoryAddress)
{
	startAddress = memoryAddress;
}

/**
 * Set size of section in memory
 * @param size Size of section in memory
 */
void FileSection::setSizeInMemory(unsigned long long size)
{
	sizeInMemory = size;
}

/**
 * Set offset of relocation entries for section
 * @param relocOffset Offset of relocation entries for section
 */
void FileSection::setRelocationsOffset(unsigned long long relocOffset)
{
	relocationsOffset = relocOffset;
}

/**
 * Set number of relocation entries for section
 * @param relocations Number of relocation entries for section
 */
void FileSection::setNumberOfRelocations(unsigned long long relocations)
{
	numberOfRelocations = relocations;
}

/**
 * Set offset of line-number entries for section
 * @param lineNumOffset Offset of line-number entries for section
 */
void FileSection::setLineNumbersOffset(unsigned long long lineNumOffset)
{
	lineNumbersOffset = lineNumOffset;
}

/**
 * Set number of line-number entries for section
 * @param lineNumbers Number of line-number entries for section
 */
void FileSection::setNumberOfLineNumbers(unsigned long long lineNumbers)
{
	numberOfLineNumbers = lineNumbers;
}

/**
 * Set section memory alignment
 * @param alignment Section nemory alignment
 */
void FileSection::setMemoryAlignment(unsigned long long alignment)
{
	memoryAlignment = alignment;
}

/**
 * Set link to another section
 * @param link Link to another file section
 */
void FileSection::setLinkToAnotherSection(unsigned long long link)
{
	linkToSection = link;
}

/**
 * Set section extra information
 * @param extraInformation Section extra information
 */
void FileSection::setExtraInfo(unsigned long long extraInformation)
{
	extraInfo = extraInformation;
}

/**
 * Set line offset
 * @param sectionOffset Line offset of section
 */
void FileSection::setLineOffset(unsigned long long sectionOffset)
{
	lineOffset = sectionOffset;
}

/**
 * Set relocations line offset
 * @param relocOffset Relocations line offset for this section
 */
void FileSection::setRelocationsLineOffset(unsigned long long relocOffset)
{
	relocationsLineOffset = relocOffset;
}

/**
 * Set number of section flags
 * @param flagsSize Number of section flags
 */
void FileSection::setFlagsSize(unsigned long long flagsSize)
{
	flags.setSize(flagsSize);
}

/**
 * Set section flags
 * @param flagsValue Section flags
 */
void FileSection::setFlags(unsigned long long flagsValue)
{
	flags.setFlags(flagsValue);
}

/**
 * Add flag descriptor
 * @param descriptor Descriptor (full description of flag)
 * @param abbreviation Abbreviation (short description of flag)
 */
void FileSection::addFlagsDescriptor(std::string descriptor, std::string abbreviation)
{
	flags.addDescriptor(descriptor, abbreviation);
}

/**
 * Delete all flags descriptors
 */
void FileSection::clearFlagsDescriptors()
{
	flags.clearDescriptors();
}

} // namespace fileinfo
