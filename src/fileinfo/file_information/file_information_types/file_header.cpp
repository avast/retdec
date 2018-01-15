/**
 * @file src/fileinfo/file_information/file_information_types/file_header.cpp
 * @brief Class for file header
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/file_header.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
FileHeader::FileHeader() : numberOfBitsInByte(std::numeric_limits<unsigned long long>::max()),
							numberOfBitsInWord(std::numeric_limits<unsigned long long>::max()),
							fileHeaderSize(std::numeric_limits<unsigned long long>::max()),
							segmentTableOffset(std::numeric_limits<unsigned long long>::max()),
							segmentTableEntrySize(std::numeric_limits<unsigned long long>::max()),
							segmentTableSize(std::numeric_limits<unsigned long long>::max()),
							numberOfSegments(std::numeric_limits<unsigned long long>::max()),
							sectionTableOffset(std::numeric_limits<unsigned long long>::max()),
							sectionTableEntrySize(std::numeric_limits<unsigned long long>::max()),
							sectionTableSize(std::numeric_limits<unsigned long long>::max()),
							declNumberOfSections(std::numeric_limits<unsigned long long>::max()),
							coffFileHeaderSize(std::numeric_limits<unsigned long long>::max()),
							optionalHeaderSize(std::numeric_limits<unsigned long long>::max()),
							checksum(std::numeric_limits<unsigned long long>::max()),
							stackReserveSize(std::numeric_limits<unsigned long long>::max()),
							stackCommitSize(std::numeric_limits<unsigned long long>::max()),
							heapReserveSize(std::numeric_limits<unsigned long long>::max()),
							heapCommitSize(std::numeric_limits<unsigned long long>::max()),
							numberOfDataDirectories(std::numeric_limits<unsigned long long>::max()),
							numberOfSymbolTables(std::numeric_limits<unsigned long long>::max()),
							overlayOffset(std::numeric_limits<unsigned long long>::max()),
							overlaySize(std::numeric_limits<unsigned long long>::max())
{

}

/**
 * Destructor
 */
FileHeader::~FileHeader()
{

}

/**
 * Get time stamp
 * @return Time stamp
 */
std::string FileHeader::getTimeStamp() const
{
	return timeStamp;
}

/**
 * Get file status
 * @return Status of file (e.g. ROM image)
 */
std::string FileHeader::getFileStatus() const
{
	return fileStatus;
}

/**
 * Get file version
 * @return File version
 */
std::string FileHeader::getFileVersion() const
{
	return fileVersion;
}

/**
 * Get file header version
 * @return File header version
 */
std::string FileHeader::getFileHeaderVersion() const
{
	return fileHeaderVersion;
}

/**
 * Get operating system or ABI extension
 * @return Operating system or ABI extension
 */
std::string FileHeader::getOsAbi() const
{
	return osAbi;
}

/**
 * Get OS or ABI version
 * @return OS or ABI version
 */
std::string FileHeader::getOsAbiVersion() const
{
	return osAbiVersion;
}

/**
 * Get flags size
 * @return File flags size
 */
unsigned long long FileHeader::getFileFlagsSize() const
{
	return fileFlags.getSize();
}

/**
 * Get flags
 * @return File flags as number
 */
unsigned long long FileHeader::getFileFlags() const
{
	return fileFlags.getFlags();
}

/**
 * Get flags
 * @return File flags as string
 */
std::string FileHeader::getFileFlagsStr() const
{
	return fileFlags.getFlagsStr();
}

/**
 * Get number of file flags descriptors
 * @return Number of file flags descriptors
 */
std::size_t FileHeader::getNumberOfFileFlagsDescriptors() const
{
	return fileFlags.getNumberOfDescriptors();
}

/**
 * Get file flags descriptors and its abbreviations
 * @param desc Vector for save descriptors
 * @param abb Vector for save abbreviations of descriptors
 *
 * It is guaranteed that the number of stored descriptors and abbreviations are the same
 */
void FileHeader::getFileFlagsDescriptors(std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	fileFlags.getDescriptors(desc, abb);
}

/**
 * Get DLL flags size
 * @return DLL flags size
 */
unsigned long long FileHeader::getDllFlagsSize() const
{
	return dllFlags.getSize();
}

/**
 * Get DLL flags
 * @return DLL flags as number
 */
unsigned long long FileHeader::getDllFlags() const
{
	return dllFlags.getFlags();
}

/**
 * Get DLL flags
 * @return DLL flags as string
 */
std::string FileHeader::getDllFlagsStr() const
{
	return dllFlags.getFlagsStr();
}

/**
 * Get number of DLL flags descriptors
 * @return Number of DLL flags descriptors
 */
std::size_t FileHeader::getNumberOfDllFlagsDescriptors() const
{
	return dllFlags.getNumberOfDescriptors();
}

/**
 * Get DLL flags descriptors and its abbreviations
 * @param desc Vector for save descriptors
 * @param abb Vector for save abbreviations of descriptors
 *
 * It is guaranteed that the number of stored descriptors and abbreviations are the same
 */
void FileHeader::getDllFlagsDescriptors(std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	dllFlags.getDescriptors(desc, abb);
}

/**
 * Get number of bits in one byte
 * @return Number of bits in one byte
 */
std::string FileHeader::getNumberOfBitsInByteStr() const
{
	return getNumberAsString(numberOfBitsInByte);
}

/**
 * Get number of bits in one word
 * @return Number of bits in one word
 */
std::string FileHeader::getNumberOfBitsInWordStr() const
{
	return getNumberAsString(numberOfBitsInWord);
}

/**
 * Get size of file header
 * @return Size of file header
 */
std::string FileHeader::getFileHeaderSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(fileHeaderSize, format);
}

/**
 * Get segment table offset
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Segment table offset in file
 */
std::string FileHeader::getSegmentTableOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(segmentTableOffset, format);
}

/**
 * Get segment table one entry size
 * @return Size of one entry in segment table
 */
std::string FileHeader::getSegmentTableEntrySizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(segmentTableEntrySize, format);
}

/**
 * Get segment table size
 * @return Size of segment table
 */
std::string FileHeader::getSegmentTableSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(segmentTableSize, format);
}

/**
 * Get number of segments
 * @return Number of segments in file
 */
std::string FileHeader::getNumberOfSegmentsStr() const
{
	return getNumberAsString(numberOfSegments);
}

/**
 * Get section table offset
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Section table offset in file
 */
std::string FileHeader::getSectionTableOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(sectionTableOffset, format);
}

/**
 * Get section table one entry size
 * @return Size of one entry in section table
 */
std::string FileHeader::getSectionTableEntrySizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(sectionTableEntrySize, format);
}

/**
 * Get section table size
 * @return Size of section table
 */
std::string FileHeader::getSectionTableSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(sectionTableSize, format);
}

/**
 * Get declared number of sections
 * @return Declared number of sections in file
 */
std::string FileHeader::getDeclaredNumberOfSectionsStr() const
{
	return getNumberAsString(declNumberOfSections);
}

/**
 * Get size of COFF file header
 * @return Size of COFF file header
 */
std::string FileHeader::getCoffFileHeaderSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(coffFileHeaderSize, format);
}

/**
 * Get size of optional file header
 * @return Size of optional file header
 */
std::string FileHeader::getOptionalHeaderSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(optionalHeaderSize, format);
}

/**
 * Get file checksum
 * @return File checksum
 */
std::string FileHeader::getChecksumStr() const
{
	return getNumberAsString(checksum);
}

/**
 * Get size of the stack to reserve
 * @return Size of the stack to reserve
 */
std::string FileHeader::getStackReserveSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(stackReserveSize, format);
}

/**
 * Get size of the stack to commit
 * @return Size of the stack to commit
 */
std::string FileHeader::getStackCommitSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(stackCommitSize, format);
}

/**
 * Get size of the local heap space to reserve
 * @return Size of the local heap space to reserve
 */
std::string FileHeader::getHeapReserveSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(heapReserveSize, format);
}

/**
 * Get size of the local heap space to commit
 * @return Size of the local heap space to commit
 */
std::string FileHeader::getHeapCommitSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(heapCommitSize, format);
}

/**
 * Get number of data directories
 * @return Number of data directories
 */
std::string FileHeader::getNumberOfDataDirectoriesStr() const
{
	return getNumberAsString(numberOfDataDirectories);
}

/**
 * Get number of symbol tables
 * @return Number of symbol tables
 */
std::string FileHeader::getNumberOfSymbolTablesStr() const
{
	return getNumberAsString(numberOfSymbolTables);
}

/**
 * Get overlay offset
 * @return Offset of overlay
 */
std::string FileHeader::getOverlayOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(overlayOffset, format);
}

/**
 * Get overlay size
 * @return Size of overlay
 */
std::string FileHeader::getOverlaySizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(overlaySize, format);
}

/**
 * Set time stamp
 * @param timestamp Time stamp
 */
void FileHeader::setTimeStamp(std::string timestamp)
{
	timeStamp = timestamp;
}

/**
 * Set file status
 * @param status Status of file (e.g. ROM image)
 */
void FileHeader::setFileStatus(std::string status)
{
	fileStatus = status;
}

/**
 * Set file version
 * @param version Version of file
 */
void FileHeader::setFileVersion(std::string version)
{
	fileVersion = version;
}

/**
 * Set file version
 * @param version Version of file header
 */
void FileHeader::setFileHeaderVersion(std::string version)
{
	fileHeaderVersion = version;
}

/**
 * Set operating system or ABI extension
 * @param osabi OS or ABI extension
 */
void FileHeader::setOsAbi(std::string osabi)
{
	osAbi = osabi;
}

/**
 * Set OS or ABI version
 * @param abiversion Version of OS or ABI
 */
void FileHeader::setOsAbiVersion(std::string abiversion)
{
	osAbiVersion = abiversion;
}

/**
 * Set file flags size
 * @param size Number of file flags
 */
void FileHeader::setFileFlagsSize(unsigned long long size)
{
	fileFlags.setSize(size);
}

/**
 * Set file flags
 * @param flagsArray Bit flags as one number
 */
void FileHeader::setFileFlags(unsigned long long flagsArray)
{
	fileFlags.setFlags(flagsArray);
}

/**
 * Set DLL flags size
 * @param size Number of DLL flags
 */
void FileHeader::setDllFlagsSize(unsigned long long size)
{
	dllFlags.setSize(size);
}

/**
 * Set DLL flags
 * @param flagsArray Bit flags as one number
 */
void FileHeader::setDllFlags(unsigned long long flagsArray)
{
	dllFlags.setFlags(flagsArray);
}

/**
 * Set number of bits in one byte
 * @param bitsInByte Number of bits in one byte
 */
void FileHeader::setNumberOfBitsInByte(unsigned long long bitsInByte)
{
	numberOfBitsInByte = bitsInByte;
}

/**
 * Set number of bits in one word
 * @param bitsInWord Number of bits in one word
 */
void FileHeader::setNumberOfBitsInWord(unsigned long long bitsInWord)
{
	numberOfBitsInWord = bitsInWord;
}

/**
 * Set file header size
 * @param headerSize File header size
 */
void FileHeader::setFileHeaderSize(unsigned long long headerSize)
{
	fileHeaderSize = headerSize;
}

/**
 * Set segment table offset
 * @param offset Segment table offset
 */
void FileHeader::setSegmentTableOffset(unsigned long long offset)
{
	segmentTableOffset = offset;
}

/**
 * Set size of one entry in segment table
 * @param entrySize Size of one entry in segment table
 */
void FileHeader::setSegmentTableEntrySize(unsigned long long entrySize)
{
	segmentTableEntrySize = entrySize;
}

/**
 * Set segment table size
 * @param tableSize Size of segment table
 */
void FileHeader::setSegmentTableSize(unsigned long long tableSize)
{
	segmentTableSize = tableSize;
}

/**
 * Set number of segments
 * @param noOfSegments Number of segments in file
 */
void FileHeader::setNumberOfSegments(unsigned long long noOfSegments)
{
	numberOfSegments = noOfSegments;
}

/**
 * Set section table offset
 * @param offset Section table offset
 */
void FileHeader::setSectionTableOffset(unsigned long long offset)
{
	sectionTableOffset = offset;
}

/**
 * Set size of one entry in section table
 * @param entrySize Size of one entry in section table
 */
void FileHeader::setSectionTableEntrySize(unsigned long long entrySize)
{
	sectionTableEntrySize = entrySize;
}

/**
 * Set section table size
 * @param tableSize Size of section table
 */
void FileHeader::setSectionTableSize(unsigned long long tableSize)
{
	sectionTableSize = tableSize;
}

/**
 * Set declared number of sections
 * @param noOfSections Number of sections in file
 */
void FileHeader::setDeclaredNumberOfSections(unsigned long long noOfSections)
{
	declNumberOfSections = noOfSections;
}

/**
 * Set size of COFF file header
 * @param headerSize Size of COFF file header
 */
void FileHeader::setCoffFileHeaderSize(unsigned long long headerSize)
{
	coffFileHeaderSize = headerSize;
}

/**
 * Set size of optional file header
 * @param headerSize Size of optional file header
 */
void FileHeader::setOptionalHeaderSize(unsigned long long headerSize)
{
	optionalHeaderSize = headerSize;
}

/**
 * Set file checksum
 * @param fileChecksum Checksum of file
 */
void FileHeader::setChecksum(unsigned long long fileChecksum)
{
	checksum = fileChecksum;
}

/**
 * Set size of the stack to reserve
 * @param size Size of the stack to reserve
 */
void FileHeader::setStackReserveSize(unsigned long long size)
{
	stackReserveSize = size;
}

/**
 * Set size of the stack to commit
 * @param size Size of the stack to commit
 */
void FileHeader::setStackCommitSize(unsigned long long size)
{
	stackCommitSize = size;
}

/**
 * Set size of the local heap space to reserve
 * @param size Size of the local heap space to reserve
 */
void FileHeader::setHeapReserveSize(unsigned long long size)
{
	heapReserveSize = size;
}

/**
 * Set size of the local heap space to commit
 * @param size Size of the local heap space to commit
 */
void FileHeader::setHeapCommitSize(unsigned long long size)
{
	heapCommitSize = size;
}

/**
 * Set number of data directories
 * @param directories Number of data directories
 */
void FileHeader::setNumberOfDataDirectories(unsigned long long directories)
{
	numberOfDataDirectories = directories;
}

/**
 * Set number of symbol tables
 * @param tables Number of symbol tables
 */
void FileHeader::setNumberOfSymbolTables(unsigned long long tables)
{
	numberOfSymbolTables = tables;
}

/**
 * Set offset of overlay
 * @param offset Offset of overlay
 */
void FileHeader::setOverlayOffset(unsigned long long offset)
{
	overlayOffset = offset;
}

/**
 * Set size of overlay
 * @param size Size of overlay
 */
void FileHeader::setOverlaySize(unsigned long long size)
{
	overlaySize = size;
}

/**
 * Add file flag descriptor
 * @param descriptor Descriptor (full description of flag)
 * @param abbreviation Abbreviation (short description of flag)
 */
void FileHeader::addFileFlagsDescriptor(std::string descriptor, std::string abbreviation)
{
	fileFlags.addDescriptor(descriptor, abbreviation);
}

/**
 * Clear file flags descriptors
 */
void FileHeader::clearFileFlagsDescriptors()
{
	fileFlags.clearDescriptors();
}

/**
 * Add DLL flag descriptor
 * @param descriptor Descriptor (full description of flag)
 * @param abbreviation Abbreviation (short description of flag)
 */
void FileHeader::addDllFlagsDescriptor(std::string descriptor, std::string abbreviation)
{
	dllFlags.addDescriptor(descriptor, abbreviation);
}

/**
 * Clear DLL flags descriptors
 */
void FileHeader::clearDllFlagsDescriptors()
{
	dllFlags.clearDescriptors();
}

} // namespace fileinfo
