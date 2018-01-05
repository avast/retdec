/**
 * @file src/fileinfo/file_information/file_information_types/file_segment.cpp
 * @brief Class for file segment.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/file_segment.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
FileSegment::FileSegment() : index(std::numeric_limits<unsigned long long>::max()),
								offset(std::numeric_limits<unsigned long long>::max()),
								virtualAddress(std::numeric_limits<unsigned long long>::max()),
								physicalAddress(std::numeric_limits<unsigned long long>::max()),
								sizeInFile(std::numeric_limits<unsigned long long>::max()),
								sizeInMemory(std::numeric_limits<unsigned long long>::max()),
								alignment(std::numeric_limits<unsigned long long>::max())
{

}

/**
 * Destructor
 */
FileSegment::~FileSegment()
{

}

/**
 * Get segment type
 * @return Segment type
 */
std::string FileSegment::getType() const
{
	return segmentType;
}

/**
 * Get CRC32
 * @return CRC32 of segment content
 */
std::string FileSegment::getCrc32() const
{
	return crc32;
}

/**
 * Get MD5
 * @return MD5 of segment content
 */
std::string FileSegment::getMd5() const
{
	return md5;
}

/**
 * Get SHA256
 * @return SHA256 of segment content
 */
std::string FileSegment::getSha256() const
{
	return sha256;
}

/**
 * Get segment index
 * @return Segment index
 */
std::string FileSegment::getIndexStr() const
{
	return getNumberAsString(index);
}

/**
 * Get segment offset in file
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Segment file offset
 */
std::string FileSegment::getOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(offset, format);
}

/**
 * Get virtual address in memory
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Virtual address in memory
 */
std::string FileSegment::getVirtualAddressStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(virtualAddress, format);
}

/**
 * Get physical address in memory
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Physical address in memory
 */
std::string FileSegment::getPhysicalAddressStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(physicalAddress, format);
}

/**
 * Get size of segment in file
 * @return Size of segment in file
 */
std::string FileSegment::getSizeInFileStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(sizeInFile, format);
}

/**
 * Get size of segment in memory
 * @return Size of segment in memory
 */
std::string FileSegment::getSizeInMemoryStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(sizeInMemory, format);
}

/**
 * Get alignment
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Segment alignment
 */
std::string FileSegment::getAlignmentStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(alignment, format);
}

/**
 * Get segment flags size
 * @return Size of segment flags
 */
unsigned long long FileSegment::getFlagsSize() const
{
	return flags.getSize();
}

/**
 * Get segment flags as number
 * @return Flags as number
 */
unsigned long long FileSegment::getFlags() const
{
	return flags.getFlags();
}

/**
 * Get segment flags as string
 * @return Flags as string
 */
std::string FileSegment::getFlagsStr() const
{
	return flags.getFlagsStr();
}

/**
 * Get number of flags descriptors
 * @return Number of flags descriptors
 */
std::size_t FileSegment::getNumberOfFlagsDescriptors() const
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
void FileSegment::getFlagsDescriptors(std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	flags.getDescriptors(desc, abb);
}

/**
 * Set type of segment
 * @param type Type of segment
 */
void FileSegment::setType(std::string type)
{
	segmentType = type;
}

/**
 * Set segment CRC32
 * @param segmentCrc32 CRC32 of segment content
 */
void FileSegment::setCrc32(std::string segmentCrc32)
{
	crc32 = segmentCrc32;
}

/**
 * Set segment MD5
 * @param segmentMd5 MD5 of segment content
 */
void FileSegment::setMd5(std::string segmentMd5)
{
	md5 = segmentMd5;
}

/**
 * Set segment SHA256
 * @param segmentSha256 SHA256 of segment content
 */
void FileSegment::setSha256(std::string segmentSha256)
{
	sha256 = segmentSha256;
}

/**
 * Set segment index
 * @param segmentIndex Segment index
 */
void FileSegment::setIndex(unsigned long long segmentIndex)
{
	index = segmentIndex;
}

/**
 * Set segment offset in file
 * @param fileOffset Segment offset in file
 */
void FileSegment::setOffset(unsigned long long fileOffset)
{
	offset = fileOffset;
}

/**
 * Set segment virtual address
 * @param address Segment virtual address
 */
void FileSegment::setVirtualAddress(unsigned long long address)
{
	virtualAddress = address;
}

/**
 * Set segment physical address
 * @param address Segment physical address
 */
void FileSegment::setPhysicalAddress(unsigned long long address)
{
	physicalAddress = address;
}

/**
 * Set segment size in file
 * @param size Segment size in file
 */
void FileSegment::setSizeInFile(unsigned long long size)
{
	sizeInFile = size;
}

/**
 * Set segment size in memory
 * @param size Segment size in memory
 */
void FileSegment::setSizeInMemory(unsigned long long size)
{
	sizeInMemory = size;
}

/**
 * Set segment alignment
 * @param segmentAlignment Segment alignment
 */
void FileSegment::setAlignment(unsigned long long segmentAlignment)
{
	alignment = segmentAlignment;
}

/**
 * Set segment flags size
 * @param flagsSize Segment flags size
 */
void FileSegment::setFlagsSize(unsigned long long flagsSize)
{
	flags.setSize(flagsSize);
}

/**
 * Set segment flags
 * @param flagsArray Segment flags
 */
void FileSegment::setFlags(unsigned long long flagsArray)
{
	flags.setFlags(flagsArray);
}

/**
 * Add flag descriptor
 * @param descriptor Descriptor (full description of flag)
 * @param abbreviation Abbreviation (short description of flag)
 */
void FileSegment::addFlagsDescriptor(std::string descriptor, std::string abbreviation)
{
	flags.addDescriptor(descriptor, abbreviation);
}

/**
 * Delete all flags descriptors
 */
void FileSegment::clearFlagsDescriptors()
{
	flags.clearDescriptors();
}

} // namespace fileinfo
