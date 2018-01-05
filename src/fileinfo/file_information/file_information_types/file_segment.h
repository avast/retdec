/**
 * @file src/fileinfo/file_information/file_information_types/file_segment.h
 * @brief Class for file segment.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_FILE_SEGMENT_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_FILE_SEGMENT_H

#include "fileinfo/file_information/file_information_types/flags.h"

namespace fileinfo {

/**
 * Class for save information about segment
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for numeric types.
 */
class FileSegment
{
	private:
		std::string segmentType;            ///< type of segment
		std::string crc32;                  ///< CRC32 of segment content
		std::string md5;                    ///< MD5 of segment content
		std::string sha256;                 ///< SHA256 of segment content
		unsigned long long index;           ///< index of segment
		unsigned long long offset;          ///< offset in file
		unsigned long long virtualAddress;  ///< virtual address in memory
		unsigned long long physicalAddress; ///< physical address in memory
		unsigned long long sizeInFile;      ///< size of segment in file
		unsigned long long sizeInMemory;    ///< size of segment in memory
		unsigned long long alignment;       ///< alignment in memory and in file
		Flags flags;                        ///< segment flags
	public:
		FileSegment();
		~FileSegment();

		/// @name Getters
		/// @{
		std::string getType() const;
		std::string getCrc32() const;
		std::string getMd5() const;
		std::string getSha256() const;
		std::string getIndexStr() const;
		std::string getOffsetStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getVirtualAddressStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getPhysicalAddressStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getSizeInFileStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getSizeInMemoryStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getAlignmentStr(std::ios_base &(* format)(std::ios_base &)) const;
		unsigned long long getFlagsSize() const;
		unsigned long long getFlags() const;
		std::string getFlagsStr() const;
		std::size_t getNumberOfFlagsDescriptors() const;
		void getFlagsDescriptors(std::vector<std::string> &desc, std::vector<std::string> &abb) const;
		/// @}

		/// @name Setters
		/// @{
		void setType(std::string type);
		void setCrc32(std::string segmentCrc32);
		void setMd5(std::string segmentMd5);
		void setSha256(std::string segmentSha256);
		void setIndex(unsigned long long segmentIndex);
		void setOffset(unsigned long long fileOffset);
		void setVirtualAddress(unsigned long long address);
		void setPhysicalAddress(unsigned long long address);
		void setSizeInFile(unsigned long long size);
		void setSizeInMemory(unsigned long long size);
		void setAlignment(unsigned long long segmentAlignment);
		void setFlagsSize(unsigned long long flagsSize);
		void setFlags(unsigned long long flags);
		/// @}

		/// @name Other methods
		/// @{
		void addFlagsDescriptor(std::string descriptor, std::string abbreviation);
		void clearFlagsDescriptors();
		/// @}
};

} // namespace fileinfo

#endif
