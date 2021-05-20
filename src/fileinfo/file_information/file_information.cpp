/**
 * @file src/fileinfo/file_information/file_information.cpp
 * @brief Methods of FileInformation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <memory>

#include "retdec/common/address.h"
#include "fileinfo/file_information/file_information.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

using namespace retdec::common;
using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

/**
 * Check if pattern @a b is subdetection of pattern @a a
 * @return @c true if pattern @a b is subdetection of pattern @a a, @c false otherwise
 */
bool isSubpattern(const Pattern &a, const Pattern &b)
{
	unsigned long long res1, res2;
	AddressRangeContainer aCont;

	for(const auto &match : a.getMatches())
	{
		if(!match.getOffset(res1) || !match.getDataSize(res2) || !res2)
		{
			continue;
		}
		aCont.insert(AddressRange(res1, res1 + res2));
	}

	if(aCont.empty())
	{
		return false;
	}

	bool atLeastOneBMatch = false;

	for(const auto &match : b.getMatches())
	{
		if(!match.getOffset(res1) || !match.getDataSize(res2) || !res2)
		{
			continue;
		}
		auto bRange = AddressRange(res1, res1 + res2);
		if(std::none_of(aCont.begin(), aCont.end(),
			[&] (const auto &aRange)
			{
				return aRange.contains(bRange);
			}
		))
		{
			return false;
		}

		atLeastOneBMatch = true;
	}

	return atLeastOneBMatch;
}

/**
 * Sort pattern matches based on their offsets
 * @param patterns Vector of detected patterns
 */
void sortPatternMatches(std::vector<Pattern> &patterns)
{
	for(auto &pattern : patterns)
	{
		std::sort(pattern.begin(), pattern.end(),
		[] (auto &a, auto &b)
		{
			unsigned long long aRes, bRes;
			return a.getOffset(aRes) && b.getOffset(bRes) && aRes <= bRes;
		});
	}
}

} // anonymous namespace

/**
 * Get status
 * @return Status of instance
 */
ReturnCode FileInformation::getStatus() const
{
	return status;
}

/**
 * Get path to input file
 * @return Path to input file
 */
std::string FileInformation::getPathToFile() const
{
	return filePath;
}

std::string FileInformation::getTelfhash() const 
{
	return telfhash;
}

/**
 * Get CRC32 of input file
 * @return CRC32 of input file
 */
std::string FileInformation::getCrc32() const
{
	return crc32;
}

/**
 * Get MD5 of input file
 * @return MD5 of input file
 */
std::string FileInformation::getMd5() const
{
	return md5;
}

/**
 * Get SHA256 of input file
 * @return SHA256 of input file
 */
std::string FileInformation::getSha256() const
{
	return sha256;
}

/**
 * Get CRC32 of section table
 * @return CRC32 of section table
 */
std::string FileInformation::getSectionTableCrc32() const
{
	return secCrc32;
}

/**
 * Get MD5 of section table
 * @return MD5 of section table
 */
std::string FileInformation::getSectionTableMd5() const
{
	return secMd5;
}

/**
 * Get SHA256 of section table
 * @return SHA256 of section table
 */
std::string FileInformation::getSectionTableSha256() const
{
	return secSha256;
}

/**
 * Get fileFormatEnum
 * @return Detected file format in his enum representation
 */
Format FileInformation::getFileFormatEnum() const
{
	return fileFormatEnum;
}

/**
 * Get fileFormat
 * @return Detected file format in his string representation
 */
std::string FileInformation::getFileFormat() const
{
	return fileFormat;
}

/**
 * Get fileClass
 * @return Detected file class
 */
std::string FileInformation::getFileClass() const
{
	return fileClass;
}

/**
 * Get fileType
 * @return Detected file type
 */
std::string FileInformation::getFileType() const
{
	return fileType;
}

/**
 * Get targetArchitecture
 * @return Detected target architecture
 */
std::string FileInformation::getTargetArchitecture() const
{
	return targetArchitecture;
}

/**
 * Get endianness
 * @return File endianness
 */
std::string FileInformation::getEndianness() const
{
	return endianness;
}

/**
 * Get manifest
 * @return File manifest
 */
std::string FileInformation::getManifest() const
{
	return manifest;
}

/**
 * Get compact version of manifest
 * @return Compact version of manifest
 */
std::string FileInformation::getCompactManifest() const
{
	return compactManifest;
}

/**
 * Get number of stored data directories
 * @return Number of stored data directories
 */
std::size_t FileInformation::getNumberOfStoredDataDirectories() const
{
	return directories.size();
}

/**
 * Get number of stored segments
 * @return Number of stored segments
 */
std::size_t FileInformation::getNumberOfStoredSegments() const
{
	return segments.size();
}

/**
 * Get number of stored sections
 * @return Number of stored sections
 */
std::size_t FileInformation::getNumberOfStoredSections() const
{
	return sections.size();
}

/**
 * Get number of stored symbol tables
 * @return Number of stored symbol tables
 */
std::size_t FileInformation::getNumberOfStoredSymbolTables() const
{
	return symbolTables.size();
}

/**
 * Get number of stored relocation tables
 * @return Number of stored relocation tables
 */
std::size_t FileInformation::getNumberOfStoredRelocationTables() const
{
	return relocationTables.size();
}

/**
 * Get number of stored dynamic sections
 * @return Number of stored dynamic sections
 */
std::size_t FileInformation::getNumberOfStoredDynamicSections() const
{
	return dynamicSections.size();
}

/**
 * Get number of stored crypto patterns
 * @return Number of stored crypto patterns
 */
std::size_t FileInformation::getNumberOfCryptoPatterns() const
{
	return cryptoPatterns.size();
}

/**
 * Get number of stored crypto patterns
 * @return Number of stored crypto patterns
 */
std::size_t FileInformation::getNumberOfMalwarePatterns() const
{
	return malwarePatterns.size();
}

/**
 * Get number of stored crypto patterns
 * @return Number of stored crypto patterns
 */
std::size_t FileInformation::getNumberOfOtherPatterns() const
{
	return otherPatterns.size();
}

/**
 * Get time stamp
 * @return Time stamp
 */
std::string FileInformation::getTimeStamp() const
{
	return header.getTimeStamp();
}

/**
 * Get file status
 * @return File status (e.g. ROM image)
 */
std::string FileInformation::getFileStatus() const
{
	return header.getFileStatus();
}

/**
 * Get file version
 * @return File version
 */
std::string FileInformation::getFileVersion() const
{
	return header.getFileVersion();
}

/**
 * Get file header version
 * @return File header version
 */
std::string FileInformation::getFileHeaderVersion() const
{
	return header.getFileHeaderVersion();
}

/**
 * Get operating system or ABI extension
 * @return Operating system or ABI extension
 */
std::string FileInformation::getOsAbi() const
{
	return header.getOsAbi();
}

/**
 * Get OS or ABI version
 * @return OS or ABI version
 */
std::string FileInformation::getOsAbiVersion() const
{
	return header.getOsAbiVersion();
}

/**
 * Get flags size
 * @return File flags size
 */
unsigned long long FileInformation::getFileFlagsSize() const
{
	return header.getFileFlagsSize();
}

/**
 * Get flags
 * @return File flags as number
 */
unsigned long long FileInformation::getFileFlags() const
{
	return header.getFileFlags();
}

/**
 * Get flags
 * @return File flags as string
 */
std::string FileInformation::getFileFlagsStr() const
{
	return header.getFileFlagsStr();
}

/**
 * Get number of file flags descriptors
 * @return Number of file flags descriptors
 */
std::size_t FileInformation::getNumberOfFileFlagsDescriptors() const
{
	return header.getNumberOfFileFlagsDescriptors();
}

/**
 * Get file flags descriptors and its abbreviations
 * @param desc Vector for save descriptors
 * @param abb Vector for save abbreviations of descriptors
 *
 * It is guaranteed that the number of stored descriptors and abbreviations are the same
 */
void FileInformation::getFileFlagsDescriptors(std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	header.getFileFlagsDescriptors(desc, abb);
}

/**
 * Get DLL flags size
 * @return Number of DLL flags
 */
unsigned long long FileInformation::getDllFlagsSize() const
{
	return header.getDllFlagsSize();
}

/**
 * Get DLL flags
 * @return DLL flags as one number
 */
unsigned long long FileInformation::getDllFlags() const
{
	return header.getDllFlags();
}

/**
 * Get DLL flags
 * @return DLL flags as string
 */
std::string FileInformation::getDllFlagsStr() const
{
	return header.getDllFlagsStr();
}

/**
 * Get number of DLL flags descriptors
 * @return Number of DLL flags descriptors
 */
std::size_t FileInformation::getNumberOfDllFlagsDescriptors() const
{
	return header.getNumberOfDllFlagsDescriptors();
}

/**
 * Get DLL flags descriptors and its abbreviations
 * @param desc Vector for save descriptors
 * @param abb Vector for save abbreviations of descriptors
 *
 * It is guaranteed that the number of stored descriptors and abbreviations are the same
 */
void FileInformation::getDllFlagsDescriptors(std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	header.getDllFlagsDescriptors(desc, abb);
}

/**
 * Get number of bits in one byte
 * @return Number of bits in one byte
 */
std::string FileInformation::getNumberOfBitsInByteStr() const
{
	return header.getNumberOfBitsInByteStr();
}

/**
 * Get number of bits in one word
 * @return Number of bits in one word
 */
std::string FileInformation::getNumberOfBitsInWordStr() const
{
	return header.getNumberOfBitsInWordStr();
}

/**
 * Get size of file header
 * @return Size of file header
 */
std::string FileInformation::getFileHeaderSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getFileHeaderSizeStr(format);
}

/**
 * Get segment table offset
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Segment table offset in file
 */
std::string FileInformation::getSegmentTableOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getSegmentTableOffsetStr(format);
}

/**
 * Get segment table one entry size
 * @return Size of one entry in segment table
 */
std::string FileInformation::getSegmentTableEntrySizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getSegmentTableEntrySizeStr(format);
}

/**
 * Get segment table size
 * @return Size of segment table
 */
std::string FileInformation::getSegmentTableSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getSegmentTableSizeStr(format);
}

/**
 * Get declared number of segments in file
 * @return Declared number of segments in file
 */
std::string FileInformation::getNumberOfDeclaredSegmentsStr() const
{
	return header.getNumberOfSegmentsStr();
}

/**
 * Get section table offset
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Section table offset in file
 */
std::string FileInformation::getSectionTableOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getSectionTableOffsetStr(format);
}

/**
 * Get section table one entry size
 * @return Size of one entry in section table
 */
std::string FileInformation::getSectionTableEntrySizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getSectionTableEntrySizeStr(format);
}

/**
 * Get section table size
 * @return Size of section table
 */
std::string FileInformation::getSectionTableSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getSectionTableSizeStr(format);
}

/**
 * Get declared number of sections in file
 * @return Declared number of sections in file
 */
std::string FileInformation::getNumberOfDeclaredSectionsStr() const
{
	return header.getDeclaredNumberOfSectionsStr();
}

/**
 * Get size of COFF file header
 * @return Size of COFF file header
 */
std::string FileInformation::getCoffFileHeaderSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getCoffFileHeaderSizeStr(format);
}

/**
 * Get size of optional file header
 * @return Size of optional file header
 */
std::string FileInformation::getOptionalHeaderSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getOptionalHeaderSizeStr(format);
}

/**
 * Get checksum of file
 * @return Checksum of file
 */
std::string FileInformation::getChecksumStr() const
{
	return header.getChecksumStr();
}

/**
 * Get size of the stack to reserve
 * @return Size of the stack to reserve
 */
std::string FileInformation::getStackReserveSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getStackReserveSizeStr(format);
}

/**
 * Get size of the stack to commit
 * @return Size of the stack to commit
 */
std::string FileInformation::getStackCommitSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getStackCommitSizeStr(format);
}

/**
 * Get size of the local heap space to reserve
 * @return Size of the local heap space to reserve
 */
std::string FileInformation::getHeapReserveSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getHeapReserveSizeStr(format);
}

/**
 * Get size of the local heap space to commit
 * @return Size of the local heap space to commit
 */
std::string FileInformation::getHeapCommitSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getHeapCommitSizeStr(format);
}

/**
 * Get declared number of data directories in file
 * @return Declared number of data directories in file
 */
std::string FileInformation::getNumberOfDeclaredDataDirectoriesStr() const
{
	return header.getNumberOfDataDirectoriesStr();
}

/**
 * Get declared number of symbol tables in file
 * @return Declared number of symbol tables in file
 */
std::string FileInformation::getNumberOfDeclaredSymbolTablesStr() const
{
	return header.getNumberOfSymbolTablesStr();
}

/**
 * Get overlay offset
 * @return Overlay offset
 */
std::string FileInformation::getOverlayOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getOverlayOffsetStr(format);
}

/**
 * Get overlay size
 * @return Overlay size
 */
std::string FileInformation::getOverlaySizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getOverlaySizeStr(format);
}

/**
 * Get overlay entropy
 * @return Overlay entropy
 */
std::string FileInformation::getOverlayEntropyStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return header.getOverlayEntropyStr(format);
}

/**
 * Get number of records in rich header
 * @return Number of records in rich header
 */
std::size_t FileInformation::getNumberOfStoredRecordsInRichHeader() const
{
	return richHeader.getNumberOfStoredRecords();
}

/**
 * Gets the number of loaded segments.
 * @return Number of loaded segments.
 */
std::size_t FileInformation::getNumberOfLoadedSegments() const
{
	return loaderInfo.getNumberOfLoadedSegments();
}

/**
 * Get decrypted header as string
 * @return Decrypted header as string
 */
std::string FileInformation::getRichHeaderSignature() const
{
	return richHeader.getSignature();
}

/**
 * Get offset of header in file
 * @return Offset of header in file
 */
std::string FileInformation::getRichHeaderOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return richHeader.getOffsetStr(format);
}

/**
 * Get key for decryption of header
 * @return Key for decryption of header
 */
std::string FileInformation::getRichHeaderKeyStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return richHeader.getKeyStr(format);
}

/**
 * Get major version
 * @param position Index of selected record from header (indexed from 0)
 * @return Major version of linker
 */
std::string FileInformation::getRichHeaderRecordProductIdStr(std::size_t position) const
{
	return richHeader.getRecordProductIdStr(position);
}

/**
 * Get minor version
 * @param position Index of selected record from header (indexed from 0)
 * @return Minor version of linker
 */
std::string FileInformation::getRichHeaderRecordProductBuildStr(std::size_t position) const
{
	return richHeader.getRecordProductBuildStr(position);
}

/**
 * Get number of uses
 * @param position Index of selected record from header (indexed from 0)
 * @return Number of uses
 */
std::string FileInformation::getRichHeaderRecordNumberOfUsesStr(std::size_t position) const
{
	return richHeader.getRecordNumberOfUsesStr(position);
}

/**
 * Retrieve the product name
 * @param position Index of selected record from header (indexed from 0)
 * @return Product name as std::string
 */
std::string FileInformation::getRichHeaderRecordProductNameStr(std::size_t position) const
{
	return richHeader.getRecordProductNameStr(position);
}

/**
 * Retrieve the Visual Studio name
 * @param position Index of selected record from header (indexed from 0)
 * @return Visual Studio name as std::string
 */
std::string FileInformation::getRichHeaderRecordVisualStudioNameStr(std::size_t position) const
{
	return richHeader.getRecordVisualStudioNameStr(position);
}

/**
 * Get rich header raw bytes as string
 * @return Raw bytes of rich header as string
 */
std::string FileInformation::getRichHeaderRawBytesStr() const
{
	auto rawBytes = richHeader.getRawBytes();
	return std::string{rawBytes.begin(), rawBytes.end()};
}

/**
 * Find out if there are any records in rich header
 * @return @c true if rich header is not empty, @c false otherwise
 */
bool FileInformation::hasRichHeaderRecords() const
{
	return richHeader.hasRecords();
}

std::string FileInformation::getRichHeaderSha256() const
{
	return richHeader.getSha256();
}
std::string FileInformation::getRichHeaderCrc32() const
{
	return richHeader.getCrc32();
}
std::string FileInformation::getRichHeaderMd5() const
{
	return richHeader.getMd5();
}

/**
 * Check whether visual basic informations are used.
 * @return @c true if it is used, otherwise @c false/
 */
bool FileInformation::isVisualBasicUsed() const
{
	return visualBasicInfo.isUsed();
}

/**
 * Check whether visual basic uses P-Code.
 * @return @c true if it does, otherwise @c false/
 */
bool FileInformation::getVisualBasicIsPcode() const
{
	return visualBasicInfo.isPcode();
}

/**
 * Get visual basic language DLL
 * @return Visual basic language DLL
 */
std::string FileInformation::getVisualBasicLanguageDLL() const
{
	return visualBasicInfo.getLanguageDLL();
}

/**
 * Get visual basic backup language DLL
 * @return Visual basic backup language DLL
 */
std::string FileInformation::getVisualBasicBackupLanguageDLL() const
{
	return visualBasicInfo.getBackupLanguageDLL();
}

/**
 * Get visual basic project exe name
 * @return Visual basic project exe name
 */
std::string FileInformation::getVisualBasicProjectExeName() const
{
	return visualBasicInfo.getProjectExeName();
}

/**
 * Get visual basic project description
 * @return Visual basic project description
 */
std::string FileInformation::getVisualBasicProjectDescription() const
{
	return visualBasicInfo.getProjectDescription();
}

/**
 * Get visual basic project help file
 * @return Visual basic project help file
 */
std::string FileInformation::getVisualBasicProjectHelpFile() const
{
	return visualBasicInfo.getProjectHelpFile();
}

/**
 * Get visual basic project name
 * @return Visual basic project name
 */
std::string FileInformation::getVisualBasicProjectName() const
{
	return visualBasicInfo.getProjectName();
}

/**
 * Get visual basic language DLL primary LCID
 * @return Visual basic language DLL primary LCID
 */
std::string FileInformation::getVisualBasicLanguageDLLPrimaryLCIDStr() const
{
	return visualBasicInfo.getLanguageDLLPrimaryLCIDStr();
}

/**
 * Get visual basic language DLL secondary LCID
 * @return Visual basic language DLL secondary LCID
 */
std::string FileInformation::getVisualBasicLanguageDLLSecondaryLCIDStr() const
{
	return visualBasicInfo.getLanguageDLLSecondaryLCIDStr();
}

/**
 * Get visual basic project path
 * @return Visual basic project path
 */
std::string FileInformation::getVisualBasicProjectPath() const
{
	return visualBasicInfo.getProjectPath();
}

/**
 * Get visual basic project primary LCID
 * @return Visual basic project primary LCID
 */
std::string FileInformation::getVisualBasicProjectPrimaryLCIDStr() const
{
	return visualBasicInfo.getProjectPrimaryLCIDStr();
}

/**
 * Get visual basic project secondary LCID
 * @return Visual basic project secondary LCID
 */
std::string FileInformation::getVisualBasicProjectSecondaryLCIDStr() const
{
	return visualBasicInfo.getProjectSecondaryLCIDStr();
}

/**
 * Get visual basic object
 * @param position Index of selected object (indexed from 0)
 * @return Visual basic object
 */
const retdec::fileformat::VisualBasicObject *FileInformation::getVisualBasicObject(std::size_t position) const
{
	return visualBasicInfo.getObject(position);
}

/**
 * Get visual basic extern
 * @param position Index of selected extern (indexed from 0)
 * @return Visual basic extern
 */
const retdec::fileformat::VisualBasicExtern *FileInformation::getVisualBasicExtern(std::size_t position) const
{
	return visualBasicInfo.getExtern(position);
}

/**
 * Get visual basic number of objects
 * @return Visual basic number of objects
 */
std::size_t FileInformation::getVisualBasicNumberOfObjects() const
{
	return visualBasicInfo.getNumberOfObjects();
}

/**
 * Get visual basic number of externs
 * @return Visual basic number of externs
 */
std::size_t FileInformation::getVisualBasicNumberOfExterns() const
{
	return visualBasicInfo.getNumberOfExterns();
}

/**
 * Get visual basic extern module name
 * @param position Index of selected extern (indexed from 0)
 * @return Visual basic extern module name
 */
std::string FileInformation::getVisualBasicExternModuleName(std::size_t position) const
{
	return visualBasicInfo.getExternModuleName(position);
}

/**
 * Get visual basic extern api name
 * @param position Index of selected extern (indexed from 0)
 * @return Visual basic extern api name
 */
std::string FileInformation::getVisualBasicExternApiName(std::size_t position) const
{
	return visualBasicInfo.getExternApiName(position);
}

/**
 * Get visual basic object table GUID
 * @return Object table GUID as string
 */
std::string FileInformation::getVisualBasicObjectTableGUID() const
{
	return visualBasicInfo.getObjectTableGUID();
}

/**
 * Get visual basic typeLib CLSID
 * @return typeLib CLSID as string
 */
std::string FileInformation::getVisualBasicTypeLibCLSID() const
{
	return visualBasicInfo.getTypeLibCLSID();
}

/**
 * Get visual basic typeLib major version
 * @return TypeLib major version
 */
std::string FileInformation::getVisualBasicTypeLibMajorVersionStr() const
{
	return visualBasicInfo.getTypeLibMajorVersionStr();
}

/**
 * Get visual basic typeLib minor version
 * @return TypeLib minor version
 */
std::string FileInformation::getVisualBasicTypeLibMinorVersionStr() const
{
	return visualBasicInfo.getTypeLibMinorVersionStr();
}

/**
 * Get visual basic typeLib LCID
 * @return Visual basic typeLib LCID
 */
std::string FileInformation::getVisualBasicTypeLibLCIDStr() const
{
	return visualBasicInfo.getTypeLibLCIDStr();
}

/**
 * Get visual basic COM object name
 * @return Visual basic COM object name
 */
std::string FileInformation::getVisualBasicCOMObjectName() const
{
	return visualBasicInfo.getCOMObjectName();
}

/**
 * Get visual basic COM object description
 * @return Visual basic COM object description
 */
std::string FileInformation::getVisualBasicCOMObjectDescription() const
{
	return visualBasicInfo.getCOMObjectDescription();
}

/**
 * Get visual basic COM object CLSID
 * @return Visual basic COM object CLSID
 */
std::string FileInformation::getVisualBasicCOMObjectCLSID() const
{
	return visualBasicInfo.getCOMObjectCLSID();
}

/**
 * Get visual basic COM object interface CLSID
 * @return Visual basic COM object interface CLSID
 */
std::string FileInformation::getVisualBasicCOMObjectInterfaceCLSID() const
{
	return visualBasicInfo.getCOMObjectInterfaceCLSID();
}

/**
 * Get visual basic COM object events CLSID
 * @return Visual basic COM object events CLSID
 */
std::string FileInformation::getVisualBasicCOMObjectEventsCLSID() const
{
	return visualBasicInfo.getCOMObjectEventsCLSID();
}

/**
 * Get visual basic COM object type
 * @return Visual basic COM object type
 */
std::string FileInformation::getVisualBasicCOMObjectType() const
{
	return visualBasicInfo.getCOMObjectType();
}

/**
 * Get visual basic extern table hash as Crc32
 * @return Visual basic extern table hash
 */
std::string FileInformation::getVisualBasicExternTableHashCrc32() const
{
	return visualBasicInfo.getExternTableHashCrc32();
}

/**
 * Get visual basic extern table hash as Md5
 * @return Visual basic extern table hash
 */
std::string FileInformation::getVisualBasicExternTableHashMd5() const
{
	return visualBasicInfo.getExternTableHashMd5();
}

/**
 * Get visual basic extern table hash as Sha256
 * @return Visual basic extern table hash
 */
std::string FileInformation::getVisualBasicExternTableHashSha256() const
{
	return visualBasicInfo.getExternTableHashSha256();
}

/**
 * Get visual basic object table hash as Crc32
 * @return Visual basic object table hash
 */
std::string FileInformation::getVisualBasicObjectTableHashCrc32() const
{
	return visualBasicInfo.getObjectTableHashCrc32();
}

/**
 * Get visual basic object table hash as Md5
 * @return Visual basic object table hash
 */
std::string FileInformation::getVisualBasicObjectTableHashMd5() const
{
	return visualBasicInfo.getObjectTableHashMd5();
}

/**
 * Get visual basic object table hash as Sha256
 * @return Visual basic object table hash
 */
std::string FileInformation::getVisualBasicObjectTableHashSha256() const
{
	return visualBasicInfo.getObjectTableHashSha256();
}

/**
 * Get type of related PDB file
 * @return Type of related PDB file
 */
std::string FileInformation::getPdbType() const
{
	return pdbInfo.getType();
}

/**
 * Get original path to related PDB file
 * @return Original path to related PDB file
 */
std::string FileInformation::getPdbPath() const
{
	return pdbInfo.getPath();
}

/**
 * Get GUID of related PDB file
 * @return GUID of related PDB file
 */
std::string FileInformation::getPdbGuid() const
{
	return pdbInfo.getGuid();
}

/**
 * Get age of related PDB file
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Age of related PDB file
 */
std::string FileInformation::getPdbAgeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return pdbInfo.getAgeStr(format);
}

/**
 * Get timestamp of related PDB file
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Timestamp of related PDB file
 */
std::string FileInformation::getPdbTimeStampStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return pdbInfo.getTimeStampStr(format);
}

/**
 * Get number of stored import libraries
 * @return Number of stored import libraries
 */
std::size_t FileInformation::getNumberOfStoredImportLibraries() const
{
	return importTable.getNumberOfLibraries();
}

/**
 * Get number of stored imports
 * @return Number of stored imports
 */
std::size_t FileInformation::getNumberOfStoredImports() const
{
	return importTable.getNumberOfImports();
}

/**
 * Get imphash as CRC32
 * @return Imphash as CRC32
 */
std::string FileInformation::getImphashCrc32() const
{
	return importTable.getImphashCrc32();
}

/**
 * Get imphash as MD5
 * @return Imphash as MD5
 */
std::string FileInformation::getImphashMd5() const
{
	return importTable.getImphashMd5();
}

/**
 * Get imphash as SHA256
 * @return Imphash as SHA256
 */
std::string FileInformation::getImphashSha256() const
{
	return importTable.getImphashSha256();
}
/**
 * Get imphash as Tlsh
 * @return Imphash as Tlsh
 */
std::string FileInformation::getImphashTlsh() const
{
	return importTable.getImphashTlsh();
}

/**
 * Get import
 * @param position Index of selected import (indexed from 0)
 * @return Name of selected import
 */
const retdec::fileformat::Import* FileInformation::getImport(std::size_t position) const
{
	return importTable.getImport(position);
}

/**
 * Get import name
 * @param position Index of selected import (indexed from 0)
 * @return Name of selected import
 */
std::string FileInformation::getImportName(std::size_t position) const
{
	return importTable.getImportName(position);
}

/**
 * Get import library name
 * @param position Index of selected import (indexed from 0)
 * @return Name of library of selected import
 */
std::string FileInformation::getImportLibraryName(std::size_t position) const
{
	return importTable.getImportLibraryName(position);
}

/**
 * Get import type
 * @param position Index of selected import (indexed from 0)
 * @return Symbol type
 */
std::string FileInformation::getImportUsageType(std::size_t position) const
{
	return importTable.getImportUsageType(position);
}

/**
 * Get import address
 * @param position Index of selected import (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Address of selected import
 */
std::string FileInformation::getImportAddressStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return importTable.getImportAddressStr(position, format);
}

/**
 * Get import ordinal number
 * @param position Index of selected import (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)m
 * @return Ordinal number of selected import
 */
std::string FileInformation::getImportOrdinalNumberStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return importTable.getImportOrdinalNumberStr(position, format);
}

/**
 * Find out if there are any records in import table
 * @return @c true if import table is not empty, @c false otherwise
 */
bool FileInformation::hasImportTableRecords() const
{
	return importTable.hasRecords();
}

/**
 * Get number of missing dependencies
 * @return Number of missing dependencies
 */
std::size_t FileInformation::getNumberOfMissingDeps() const
{
	return importTable.getNumberOfMissingDeps();
}

/**
 * Get missing dependency name
 * @param position Index of selected dependency (indexed from 0)
 * @return Name of the missing dependency
 */
std::string FileInformation::getMissingDepName(std::size_t position) const
{
	return importTable.getMissingDepName(position);
}

/**
 * Get the name of the dependency file that failed to load
 * @return Name of the failed-to-load dependency listfile
 */
std::string FileInformation::getDepsListFailedToLoad() const
{
	return failedDepsList;
}

/**
 * Sets the name of the dependency file that failed to load
 * @return Nothing
 */
void FileInformation::setDepsListFailedToLoad(const std::string & depsList)
{
	failedDepsList = depsList;
}

/**
 * Get number of stored exports
 * @return Number of stored exports
 */
std::size_t FileInformation::getNumberOfStoredExports() const
{
	return exportTable.getNumberOfExports();
}

/**
 * Get exphash as CRC32
 * @return Exphash as CRC32
 */
std::string FileInformation::getExphashCrc32() const
{
	return exportTable.getExphashCrc32();
}

/**
 * Get exphash as MD5
 * @return Exphash as MD5
 */
std::string FileInformation::getExphashMd5() const
{
	return exportTable.getExphashMd5();
}

/**
 * Get exphash as SHA256
 * @return Exphash as SHA256
 */
std::string FileInformation::getExphashSha256() const
{
	return exportTable.getExphashSha256();
}

/**
 * Get export name
 * @param position Index of selected export (indexed from 0)
 * @return Name of selected export
 */
std::string FileInformation::getExportName(std::size_t position) const
{
	return exportTable.getExportName(position);
}

/**
 * Get export address
 * @param position Index of selected export (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Address of selected export
 */
std::string FileInformation::getExportAddressStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return exportTable.getExportAddressStr(position, format);
}

/**
 * Get export ordinal number
 * @param position Index of selected export (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Ordinal number of selected export
 */
std::string FileInformation::getExportOrdinalNumberStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return exportTable.getExportOrdinalNumberStr(position, format);
}

/**
 * Find out if there are any records in export table
 * @return @c true if export table is not empty, @c false otherwise
 */
bool FileInformation::hasExportTableRecords() const
{
	return exportTable.hasRecords();
}

/**
 * Get number of resources stored in resource table
 * @return Number of resources stored in resource table
 */
std::size_t FileInformation::getNumberOfStoredResources() const
{
	return resourceTable.getNumberOfResources();
}

/**
 * Get number of supported version info languages
 * @return Number of supported version info languages
 */
std::size_t FileInformation::getNumberOfVersionInfoLanguages() const
{
	return resourceTable.getNumberOfLanguages();
}

/**
 * Get number of version info strings
 * @return Number of version info strings
 */
std::size_t FileInformation::getNumberOfVersionInfoStrings() const
{
	return resourceTable.getNumberOfStrings();
}

/**
 * Get CRC32 of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return CRC32 of selected resource
 */
std::string FileInformation::getResourceCrc32(std::size_t index) const
{
	return resourceTable.getResourceCrc32(index);
}

/**
 * Get MD5 of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return MD5 of selected resource
 */
std::string FileInformation::getResourceMd5(std::size_t index) const
{
	return resourceTable.getResourceMd5(index);
}

/**
 * Get SHA256 of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return SHA256 of selected resource
 */
std::string FileInformation::getResourceSha256(std::size_t index) const
{
	return resourceTable.getResourceSha256(index);
}

/**
 * Get iconhash as CRC32
 * @return ResourceIconhash as CRC32
 */
std::string FileInformation::getResourceIconhashCrc32() const
{
	return resourceTable.getResourceIconhashCrc32();
}

/**
 * Get iconhash as MD5
 * @return ResourceIconhash as MD5
 */
std::string FileInformation::getResourceIconhashMd5() const
{
	return resourceTable.getResourceIconhashMd5();
}

/**
 * Get iconhash as SHA256
 * @return ResourceIconhash as SHA256
 */
std::string FileInformation::getResourceIconhashSha256() const
{
	return resourceTable.getResourceIconhashSha256();
}

/**
 * Get icon perceptual hash as AvgHash
 * @return Icon perceptual hash as AvgHash
 */
std::string FileInformation::getResourceIconPerceptualAvgHash() const
{
	return resourceTable.getResourceIconPerceptualAvgHash();
}

/**
 * Get name of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return Name of selected resource
 */
std::string FileInformation::getResourceName(std::size_t index) const
{
	return resourceTable.getResourceName(index);
}

/**
 * Get type of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return Type of selected resource
 */
std::string FileInformation::getResourceType(std::size_t index) const
{
	return resourceTable.getResourceType(index);
}

/**
 * Get language of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return Language of selected resource
 */
std::string FileInformation::getResourceLanguage(std::size_t index) const
{
	return resourceTable.getResourceLanguage(index);
}

/**
 * Get LCID of selected version info language
 * @param index Index of selected version info language (indexed from 0)
 * @return LCID of selected version info language
 */
std::string FileInformation::getVersionInfoLanguageLcid(std::size_t index) const
{
	return resourceTable.getLanguageLcid(index);
}

/**
 * Get code page of selected version info language
 * @param index Index of selected version info language (indexed from 0)
 * @return Code page of selected version info language
 */
std::string FileInformation::getVersionInfoLanguageCodePage(std::size_t index) const
{
	return resourceTable.getLanguageCodePage(index);
}

/**
 * Get name of selected version info string
 * @param index Index of selected version info string (indexed from 0)
 * @return Name of selected version info string
 */
std::string FileInformation::getVersionInfoStringName(std::size_t index) const
{
	return resourceTable.getStringName(index);
}

/**
 * Get value of selected version info string
 * @param index Index of selected version info string (indexed from 0)
 * @return Value of selected version info string
 */
std::string FileInformation::getVersionInfoStringValue(std::size_t index) const
{
	return resourceTable.getStringValue(index);
}

/**
 * Get name ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Name ID of selected resource
 */
std::string FileInformation::getResourceNameIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return resourceTable.getResourceNameIdStr(index, format);
}

/**
 * Get type ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Type ID of selected resource
 */
std::string FileInformation::getResourceTypeIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return resourceTable.getResourceTypeIdStr(index, format);
}

/**
 * Get language ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Language ID of selected resource
 */
std::string FileInformation::getResourceLanguageIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return resourceTable.getResourceLanguageIdStr(index, format);
}

/**
 * Get sublanguage ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Sublanguage ID of selected resource
 */
std::string FileInformation::getResourceSublanguageIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return resourceTable.getResourceSublanguageIdStr(index, format);
}

/**
 * Get offset of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Offset of selected resource
 */
std::string FileInformation::getResourceOffsetStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return resourceTable.getResourceOffsetStr(index, format);
}

/**
 * Get size of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Size of selected resource
 */
std::string FileInformation::getResourceSizeStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return resourceTable.getResourceSizeStr(index, format);
}

/**
 * Find out if there are any records in resource table
 * @return @c true if resource table is not empty, @c false otherwise
 */
bool FileInformation::hasResourceTableRecords() const
{
	return resourceTable.hasRecords();
}


/**
 * Get start address of raw data of TLS
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Start address of raw data of TLS
 */
std::string FileInformation::getTlsRawDataStartAddrStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return tlsInfo.getRawDataStartAddrStr(format);
}

/**
 * Get end address of raw data of TLS
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return End address of raw data of TLS
 */
std::string FileInformation::getTlsRawDataEndAddrStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return tlsInfo.getRawDataEndAddrStr(format);
}

/**
 * Get address of index of TLS
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Address of index of TLS
 */
std::string FileInformation::getTlsIndexAddrStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return tlsInfo.getIndexAddrStr(format);
}

/**
 * Get address of callbacks of TLS
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Address of callbacks of TLS
 */
std::string FileInformation::getTlsCallBacksAddrStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return tlsInfo.getCallBacksAddrStr(format);
}

/**
 * Get size of zero fill of TLS
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Size of zero fill of TLS
 */
std::string FileInformation::getTlsZeroFillSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return tlsInfo.getZeroFillSizeStr(format);
}

/**
 * Get characteristics of TLS
 * @return Characteristics of TLS
 */
std::string FileInformation::getTlsCharacteristicsStr() const
{
	return tlsInfo.getCharacteristicsStr();
}

/**
 * Get number of callbacks of TLS
 * @return Number of callbacks of TLS
 */
std::size_t FileInformation::getTlsNumberOfCallBacks() const
{
	return tlsInfo.getNumberOfCallBacks();
}

/**
 * Get TLS callback
 * @param position Position of directory in internal list of directories (0..x)
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return TLS callback
 */
std::string FileInformation::getTlsCallBackAddrStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return tlsInfo.getCallBackAddrStr(position, format);
}

/**
 * Check whether TLS is used
 * @return @c true if TLS is used, @c false otherwise
 */
bool FileInformation::isTlsUsed() const
{
	return tlsInfo.isUsed();
}

/**
 * Get type of data directory
 * @param position Position of directory in internal list of directories (0..x)
 * @return Type of data directory
 */
std::string FileInformation::getDataDirectoryType(std::size_t position) const
{
	return directories[position].getType();
}

/**
 * Get start address of data directory
 * @param position Position of directory in internal list of directories (0..x)
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Start address of data directory
 */
std::string FileInformation::getDataDirectoryAddressStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return directories[position].getAddressStr(format);
}

/**
 * Get size of data directory
 * @param position Position of directory in internal list of directories (0..x)
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Size of data directory
 */
std::string FileInformation::getDataDirectorySizeStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return directories[position].getSizeStr(format);
}

/**
 * Get type of segment
 * @param position Position of segment in internal list of segments (0..x)
 * @return Type of segment
 */
std::string FileInformation::getSegmentType(std::size_t position) const
{
	return segments[position].getType();
}

/**
 * Get segment CRC32
 * @param position Position of segment in internal list of segments (0..x)
 * @return CRC32 of segment
 */
std::string FileInformation::getSegmentCrc32(std::size_t position) const
{
	return segments[position].getCrc32();
}

/**
 * Get segment MD5
 * @param position Position of segment in internal list of segments (0..x)
 * @return MD5 of segment
 */
std::string FileInformation::getSegmentMd5(std::size_t position) const
{
	return segments[position].getMd5();
}

/**
 * Get segment SHA256
 * @param position Position of segment in internal list of segments (0..x)
 * @return SHA256 of segment
 */
std::string FileInformation::getSegmentSha256(std::size_t position) const
{
	return segments[position].getSha256();
}

/**
 * Get segment index
 * @param position Position of segment in internal list of segments (0..x)
 * @return Segment index
 */
std::string FileInformation::getSegmentIndexStr(std::size_t position) const
{
	return segments[position].getIndexStr();
}

/**
 * Get offset of segment in file
 * @param position Position of segment in internal list of segments (0..x)
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Offset of segment in file
 */
std::string FileInformation::getSegmentOffsetStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return segments[position].getOffsetStr(format);
}

/**
 * Get segment virtual address
 * @param position Position of segment in internal list of segments (0..x)
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Segment virtual address
 */
std::string FileInformation::getSegmentVirtualAddressStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return segments[position].getVirtualAddressStr(format);
}

/**
 * Get segment physical address
 * @param position Position of segment in internal list of segments (0..x)
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Segment physical address
 */
std::string FileInformation::getSegmentPhysicalAddressStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return segments[position].getPhysicalAddressStr(format);
}

/**
 * Get size of segment in file
 * @param position Position of segment in internal list of segments (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Size of segment in file
 */
std::string FileInformation::getSegmentSizeInFileStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return segments[position].getSizeInFileStr(format);
}

/**
 * Get size of segment in memory
 * @param position Position of segment in internal list of segments (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Size of segment in memory
 */
std::string FileInformation::getSegmentSizeInMemoryStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return segments[position].getSizeInMemoryStr(format);
}

/**
 * Get segment alignment
 * @param position Position of segment in internal list of segments (0..x)
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Segment alignment
 */
std::string FileInformation::getSegmentAlignmentStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return segments[position].getAlignmentStr(format);
}

/**
 * Get size of segment flags
 * @param position Position of segment in internal list of segments (0..x)
 * @return Size of segment flags
 */
unsigned long long FileInformation::getSegmentFlagsSize(std::size_t position) const
{
	return segments[position].getFlagsSize();
}

/**
 * Get segment flags
 * @param position Position of segment in internal list of segments (0..x)
 * @return Segment flags as number
 */
unsigned long long FileInformation::getSegmentFlags(std::size_t position) const
{
	return segments[position].getFlags();
}

/**
 * Get segment flags
 * @param position Position of segment in internal list of segments (0..x)
 * @return Segment flags as string
 */
std::string FileInformation::getSegmentFlagsStr(std::size_t position) const
{
	return segments[position].getFlagsStr();
}

/**
 * Get number of segment flags descriptors
 * @param position Position of segment in internal list of segments (0..x)
 * @return Number of segment flags descriptors
 */
std::size_t FileInformation::getNumberOfSegmentFlagsDescriptors(std::size_t position) const
{
	return segments[position].getNumberOfFlagsDescriptors();
}

/**
 * Get segment flags descriptors
 * @param position Position of segment in internal list of segments (0..x)
 * @param desc Vector for save descriptors
 * @param abb Vector for save abbreviations of descriptors
 */
void FileInformation::getSegmentFlagsDescriptors(std::size_t position, std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	segments[position].getFlagsDescriptors(desc, abb);
}

/**
 * Get section name
 * @param position Position of section in internal list of sections (0..x)
 * @return Section name
 */
std::string FileInformation::getSectionName(std::size_t position) const
{
	return sections[position].getName();
}

/**
 * Get section type
 * @param position Position of section in internal list of sections (0..x)
 * @return Type of section
 */
std::string FileInformation::getSectionType(std::size_t position) const
{
	return sections[position].getType();
}

/**
 * Get section entropy
 * @param position Position of section in internal list of sections (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Entropy of section
 */
std::string FileInformation::getSectionEntropy(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return sections[position].getEntropyStr(format);
}

/**
 * Get section CRC32
 * @param position Position of section in internal list of sections (0..x)
 * @return CRC32 of section
 */
std::string FileInformation::getSectionCrc32(std::size_t position) const
{
	return sections[position].getCrc32();
}

/**
 * Get section MD5
 * @param position Position of section in internal list of sections (0..x)
 * @return MD5 of section
 */
std::string FileInformation::getSectionMd5(std::size_t position) const
{
	return sections[position].getMd5();
}

/**
 * Get section SHA256
 * @param position Position of section in internal list of sections (0..x)
 * @return SHA256 of section
 */
std::string FileInformation::getSectionSha256(std::size_t position) const
{
	return sections[position].getSha256();
}

/**
 * Get number of section flags
 * @param position Position of section in internal list of sections (0..x)
 * @return Number of section flags
 */
unsigned long long FileInformation::getSectionFlagsSize(std::size_t position) const
{
	return sections[position].getFlagsSize();
}

/**
 * Get section flags
 * @param position Position of section in internal list of sections (0..x)
 * @return Section flags
 */
unsigned long long FileInformation::getSectionFlags(std::size_t position) const
{
	return sections[position].getFlags();
}

/**
 * Get section flags as string
 * @param position Position of section in internal list of sections (0..x)
 * @return Section flags in string representation
 */
std::string FileInformation::getSectionFlagsStr(std::size_t position) const
{
	return sections[position].getFlagsStr();
}

/**
 * Get number of section flags descriptors
 * @param position Position of section in internal list of sections (0..x)
 * @return Number of section flags descriptors
 */
std::size_t FileInformation::getNumberOfSectionFlagsDescriptors(std::size_t position) const
{
	return sections[position].getNumberOfFlagsDescriptors();
}

/**
 * Get section flags descriptors
 * @param position Position of section in internal list of sections (0..x)
 * @param desc Vector for save descriptors
 * @param abb Vector for save abbreviations of descriptors
 */
void FileInformation::getSectionFlagsDescriptors(std::size_t position, std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	sections[position].getFlagsDescriptors(desc, abb);
}

/**
 * Get section index as string
 * @param position Position of section in internal list of sections (0..x)
 * @return Section index in string representation
 */
std::string FileInformation::getSectionIndexStr(std::size_t position) const
{
	return sections[position].getIndexStr();
}

/**
 * Get section offset as string
 * @param position Position of section in internal list of sections (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Section offset in string representation
 */
std::string FileInformation::getSectionOffsetStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return sections[position].getOffsetStr(format);
}

/**
 * Get section size in file as string
 * @param position Position of section in internal list of sections (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Section size in string representation
 */
std::string FileInformation::getSectionSizeInFileStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return sections[position].getSizeInFileStr(format);
}

/**
 * Get size of one entry in section as string
 * @param position Position of section in internal list of sections (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Size of one entry in section as string
 */
std::string FileInformation::getSectionEntrySizeStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return sections[position].getEntrySizeStr(format);
}

/**
 * Get section address in memory as string
 * @param position Position of section in internal list of sections (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Section address in memory as string
 */
std::string FileInformation::getSectionAddressStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return sections[position].getStartAddressStr(format);
}

/**
 * Get section size in memory as string
 * @param position Position of section in internal list of sections (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Size of section in memory as string
 */
std::string FileInformation::getSectionSizeInMemoryStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return sections[position].getSizeInMemoryStr(format);
}

/**
 * Get offset of relocation entries for section
 * @param position Position of section in internal list of sections (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Offset of relocation entries for section
 */
std::string FileInformation::getSectionRelocationsOffsetStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return sections[position].getRelocationsOffsetStr(format);
}

/**
 * Get number of relocation entries for section
 * @param position Position of section in internal list of sections (0..x)
 * @return Number of relocation entries for section
 */
std::string FileInformation::getSectionNumberOfRelocationsStr(std::size_t position) const
{
	return sections[position].getNumberOfRelocationsStr();
}

/**
 * Get offset of line-number entries for section
 * @param position Position of section in internal list of sections (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Offset of line-number entries for section
 */
std::string FileInformation::getSectionLineNumbersOffsetStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return sections[position].getLineNumbersOffsetStr(format);
}

/**
 * Get number of line-number entries for section
 * @param position Position of section in internal list of sections (0..x)
 * @return Number of line-number entries for section
 */
std::string FileInformation::getSectionNumberOfLineNumbersStr(std::size_t position) const
{
	return sections[position].getNumberOfLineNumbersStr();
}

/**
 * Get section memory alignment as string
 * @param position Position of section in internal list of sections (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Section memory alignment in string representation
 */
std::string FileInformation::getSectionMemoryAlignmentStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return sections[position].getMemoryAlignmentStr(format);
}

/**
 * Get link to another section as string
 * @param position Position of section in internal list of sections (0..x)
 * @return Link to another section in string representation
 */
std::string FileInformation::getSectionLinkToOtherSectionStr(std::size_t position) const
{
	return sections[position].getLinkToAnotherSectionStr();
}

/**
 * Get section extra info as string
 * @param position Position of section in internal list of sections (0..x)
 * @return Section extra info in string representation
 */
std::string FileInformation::getSectionExtraInfoStr(std::size_t position) const
{
	return sections[position].getExtraInfoStr();
}

/**
 * Get line offset of selected section
 * @param position Position of section in internal list of sections (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Line offset of selected section
 */
std::string FileInformation::getSectionLineOffsetStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return sections[position].getLineOffsetStr(format);
}

/**
 * Get line offset of relocation entries which are related to section
 * @param position Position of section in internal list of sections (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Line offset of relocation entries which are related to section
 */
std::string FileInformation::getSectionRelocationsLineOffsetStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return sections[position].getRelocationsLineOffsetStr(format);
}

/**
 * Get number of symbols stored in symbol table
 * @param position Position of table in internal list of symbol tables (0..x)
 * @return Number of symbols in selected symbol table
 *
 * Returned value indicates the number of symbols really stored in selected dynamic section
 *    (in selected instance of class SymbolTable).
 * This number may not be as large as result of method @a getNumberOfDeclaredSymbolsInTable().
 */
std::size_t FileInformation::getNumberOfStoredSymbolsInTable(std::size_t position) const
{
	return symbolTables[position].getNumberOfStoredSymbols();
}

/**
 * Get number of symbols stored in symbol table
 * @param position Position of table in internal list of symbol tables (0..x)
 * @return Number of symbols in selected symbol table
 *
 * Returned value indicates the declared number of symbols stored in file table.
 * This number may not be as large as result of method @a getNumberOfStoredSymbolsInTable().
 */
std::string FileInformation::getNumberOfDeclaredSymbolsInTableStr(std::size_t position) const
{
	return symbolTables[position].getNumberOfDeclaredSymbolsStr();
}

/**
 * Get name of symbol table
 * @param position Position of table in internal list of symbol tables (0..x)
 * @return Name of selected symbol table
 */
std::string FileInformation::getSymbolTableName(std::size_t position) const
{
	return symbolTables[position].getTableName();
}

/**
 * Get offset of symbol table
 * @param position Position of table in internal list of symbol tables (0..x)
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Offset of selected symbol table
 */
std::string FileInformation::getSymbolTableOffsetStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return symbolTables[position].getTableOffsetStr(format);
}

/**
 * Get symbol name
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param symbolIndex Position of symbol in selected symbol table (0..x)
 * @return Symbol name
 */
std::string FileInformation::getSymbolName(std::size_t tableIndex, std::size_t symbolIndex) const
{
	return symbolTables[tableIndex].getSymbolName(symbolIndex);
}

/**
 * Get symbol type
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param symbolIndex Position of symbol in selected symbol table (0..x)
 * @return Symbol type
 */
std::string FileInformation::getSymbolType(std::size_t tableIndex, std::size_t symbolIndex) const
{
	return symbolTables[tableIndex].getSymbolType(symbolIndex);
}

/**
 * Get symbol bind
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param symbolIndex Position of symbol in selected symbol table (0..x)
 * @return Symbol bind
 */
std::string FileInformation::getSymbolBind(std::size_t tableIndex, std::size_t symbolIndex) const
{
	return symbolTables[tableIndex].getSymbolBind(symbolIndex);
}

/**
 * Get other information about symbol
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param symbolIndex Position of symbol in selected symbol table (0..x)
 * @return Other information about symbol
 */
std::string FileInformation::getSymbolOther(std::size_t tableIndex, std::size_t symbolIndex) const
{
	return symbolTables[tableIndex].getSymbolOther(symbolIndex);
}

/**
 * Get symbol link
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param symbolIndex Position of symbol in selected symbol table (0..x)
 * @return Symbol link
 */
std::string FileInformation::getSymbolLinkToSection(std::size_t tableIndex, std::size_t symbolIndex) const
{
	return symbolTables[tableIndex].getSymbolLinkToSection(symbolIndex);
}

/**
 * Get symbol index
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param symbolIndex Position of symbol in selected symbol table (0..x)
 * @return Symbol index
 */
std::string FileInformation::getSymbolIndexStr(std::size_t tableIndex, std::size_t symbolIndex) const
{
	return symbolTables[tableIndex].getSymbolIndexStr(symbolIndex);
}

/**
 * Get symbol value
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param symbolIndex Position of symbol in selected symbol table (0..x)
 * @return Symbol value
 */
std::string FileInformation::getSymbolValueStr(std::size_t tableIndex, std::size_t symbolIndex) const
{
	return symbolTables[tableIndex].getSymbolValueStr(symbolIndex);
}

/**
 * Get symbol address
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param symbolIndex Position of symbol in selected symbol table (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Symbol address
 */
std::string FileInformation::getSymbolAddressStr(std::size_t tableIndex, std::size_t symbolIndex, std::ios_base &(* format)(std::ios_base &)) const
{
	return symbolTables[tableIndex].getSymbolAddressStr(symbolIndex, format);
}

/**
 * Get size associated with symbol
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param symbolIndex Position of symbol in selected symbol table (0..x)
 * @return Size associated with symbol
 */
std::string FileInformation::getSymbolSizeStr(std::size_t tableIndex, std::size_t symbolIndex) const
{
	return symbolTables[tableIndex].getSymbolSizeStr(symbolIndex);
}

/**
 * Get number of stored special information in symbol table
 * @param position Position of table in internal list of symbol tables (0..x)
 * @return Number of special information in selected symbol table
 */
std::size_t FileInformation::getSymbolTableNumberOfStoredSpecialInformation(std::size_t position) const
{
	return symbolTables[position].getNumberOfStoredSpecialInformation();
}

/**
 * Get number of values in selected special information
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param specInfoIndex Position of special information in selected symbol table (0..x)
 * @return Number of values in selected special information
 */
std::size_t FileInformation::getSymbolTableNumberOfSpecialInformationValues(std::size_t tableIndex, std::size_t specInfoIndex) const
{
	return symbolTables[tableIndex].getNumberOfSpecialInformationValues(specInfoIndex);
}

/**
 * Get description of selected special information
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param specInfoIndex Position of special information in selected symbol table (0..x)
 * @return Description of selected special information
 */
std::string FileInformation::getSymbolTableSpecialInformationDescription(std::size_t tableIndex, std::size_t specInfoIndex) const
{
	return symbolTables[tableIndex].getSpecialInformationDescription(specInfoIndex);
}

/**
 * Get short description of selected special information
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param specInfoIndex Position of special information in selected symbol table (0..x)
 * @return Short description of selected special information
 */
std::string FileInformation::getSymbolTableSpecialInformationAbbreviation(std::size_t tableIndex, std::size_t specInfoIndex) const
{
	return symbolTables[tableIndex].getSpecialInformationAbbreviation(specInfoIndex);
}

/**
 * Get value of one record from special information
 * @param tableIndex Position of table in internal list of symbol tables (0..x)
 * @param specInfoIndex Position of special information in selected symbol table (0..x)
 * @param recordIndex Position of record in selected special information (0..x)
 * @return Value of selected record
 */
std::string FileInformation::getSymbolTableSpecialInformationValue(std::size_t tableIndex, std::size_t specInfoIndex, std::size_t recordIndex) const
{
	return symbolTables[tableIndex].getSpecialInformationValue(specInfoIndex, recordIndex);
}

/**
 * Get number of relocation entries in selected relocation table
 * @param position Position of table in internal list of relocation tables (0..x)
 * @return Number of relocation entries in selected relocation table
 *
 * Returned value indicates the number of relocations really stored in selected table.
 * This number may not be as large as result of method @a getNumberOfDeclaredRelocationsInTable().
 */
std::size_t FileInformation::getNumberOfStoredRelocationsInTable(std::size_t position) const
{
	return relocationTables[position].getNumberOfStoredRelocations();
}

/**
 * Get number of stored relocation entries in selected relocation table
 * @param position Position of table in internal list of relocation tables (0..x)
 * @return Number of relocation entries in selected relocation table
 */
std::string FileInformation::getNumberOfStoredRelocationsInTableStr(std::size_t position) const
{
	return relocationTables[position].getNumberOfStoredRelocationsStr();
}

/**
 * Get number of delcared relocation entries in selected relocation table
 * @param position Position of table in internal list of relocation tables (0..x)
 * @return Number of relocation entries in selected relocation table
 *
 * Returned value indicates the declared number of relocations stored in file table.
 * This number may not be as large as result of method @a getNumberOfStoredRelocationsInTable().
 */
std::string FileInformation::getNumberOfDeclaredRelocationsInTableStr(std::size_t position) const
{
	return relocationTables[position].getNumberOfDeclaredRelocationsStr();
}

/**
 * Get name of relocation table
 * @param position Position of relocation table in internal list of relocation tables (0..x)
 * @return Name of selected relocation table
 */
std::string FileInformation::getRelocationTableName(std::size_t position) const
{
	return relocationTables[position].getTableName();
}

/**
 * Get name of symbol table associated with selected relocation table
 * @param position Position of relocation table in internal list of relocation tables (0..x)
 * @return Name of symbol table associated with selected relocation table
 */
std::string FileInformation::getRelocationTableAssociatedSymbolTableName(std::size_t position) const
{
	return relocationTables[position].getAssociatedSymbolTableName();
}

/**
 * Get name of section to which the relocation applies
 * @param position Position of relocation table in internal list of relocation tables (0..x)
 * @return Name of section to which the relocation applies
 */
std::string FileInformation::getRelocationTableAppliesSectionName(std::size_t position) const
{
	return relocationTables[position].getAppliesSectionName();
}

/**
 * Get index of symbol table associated with selected relocation table
 * @param position Position of relocation table in internal list of relocation tables (0..x)
 * @return Index (in the midst of file sections) of symbol table associated with selected relocation table
 */
std::string FileInformation::getRelocationTableAssociatedSymbolTableIndex(std::size_t position) const
{
	return relocationTables[position].getAssociatedSymbolTableIndex();
}

/**
 * Get index of section to which the relocation applies
 * @param position Position of relocation table in internal list of relocation tables (0..x)
 * @return Index (in the midst of file sections) of section to which the relocation applies
 */
std::string FileInformation::getRelocationTableAppliesSectionIndex(std::size_t position) const
{
	return relocationTables[position].getAppliesSectionIndex();
}

/**
 * Get name of symbol associated with relocation
 * @param tableIndex Position of table in internal list of relocation tables (0..x)
 * @param relocationIndex Position of relocation in selected relocation table (0..x)
 * @return Name of symbol associated with relocation
 */
std::string FileInformation::getRelocationSymbolName(std::size_t tableIndex, std::size_t relocationIndex) const
{
	return relocationTables[tableIndex].getRelocationSymbolName(relocationIndex);
}

/**
 * Get relocation offset
 * @param tableIndex Position of table in internal list of relocation tables (0..x)
 * @param relocationIndex Position of relocation in selected relocation table (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Relocation offset
 */
std::string FileInformation::getRelocationOffsetStr(std::size_t tableIndex, std::size_t relocationIndex, std::ios_base &(* format)(std::ios_base &)) const
{
	return relocationTables[tableIndex].getRelocationOffsetStr(relocationIndex, format);
}

/**
 * Get value of symbol associated with relocation
 * @param tableIndex Position of table in internal list of relocation tables (0..x)
 * @param relocationIndex Position of relocation in selected relocation table (0..x)
 * @return Value of symbol associated with relocation
 */
std::string FileInformation::getRelocationSymbolValueStr(std::size_t tableIndex, std::size_t relocationIndex) const
{
	return relocationTables[tableIndex].getRelocationSymbolValueStr(relocationIndex);
}

/**
 * Get relocation type
 * @param tableIndex Position of table in internal list of relocation tables (0..x)
 * @param relocationIndex Position of relocation in selected relocation table (0..x)
 * @return Relocation type
 */
std::string FileInformation::getRelocationTypeStr(std::size_t tableIndex, std::size_t relocationIndex) const
{
	return relocationTables[tableIndex].getRelocationTypeStr(relocationIndex);
}

/**
 * Get relocation addend
 * @param tableIndex Position of table in internal list of relocation tables (0..x)
 * @param relocationIndex Position of relocation in selected relocation table (0..x)
 * @return Relocation addend
 */
std::string FileInformation::getRelocationAddendStr(std::size_t tableIndex, std::size_t relocationIndex) const
{
	return relocationTables[tableIndex].getRelocationAddendStr(relocationIndex);
}

/**
 * Get relocation calculated value
 * @param tableIndex Position of table in internal list of relocation tables (0..x)
 * @param relocationIndex Position of relocation in selected relocation table (0..x)
 * @return Relocation calculated value
 */
std::string FileInformation::getRelocationCalculatedValueStr(std::size_t tableIndex, std::size_t relocationIndex) const
{
	return relocationTables[tableIndex].getRelocationCalculatedValueStr(relocationIndex);
}

/**
 * Get number of entries in selected dynamic section
 * @param position Position of dynamic section in internal list of dynamic sections (0..x)
 * @return Number of entries in selected dynamic section
 *
 * Returned value indicates the number of entries really stored in selected dynamic section.
 * This number may not be as large as result of method @a getNumberOfDeclaredDynamicEntriesInSection().
 */
std::size_t FileInformation::getNumberOfStoredDynamicEntriesInSection(std::size_t position) const
{
	return dynamicSections[position].getNumberOfStoredEntries();
}

/**
 * Get number of entries in selected dynamic section
 * @param position Position of dynamic section in internal list of dynamic sections (0..x)
 * @return Number of entries in selected dynamic section
 *
 * Returned value indicates the declared number of entries stored in file section.
 * This number may not be as large as result of method @a getNumberOfStoredDynamicEntriesInSection().
 */
std::string FileInformation::getNumberOfDeclaredDynamicEntriesInSectionStr(std::size_t position) const
{
	return dynamicSections[position].getNumberOfDeclaredEntriesStr();
}

/**
 * Get name of selected dynamic section
 * @param position Position of dynamic section in internal list of dynamic sections (0..x)
 * @return Name of dynamic section
 */
std::string FileInformation::getDynamicSectionName(std::size_t position) const
{
	return dynamicSections[position].getSectionName();
}

/**
 * Get type of selected dynamic entry
 * @param sectionIndex Position of dynamic section in internal list of dynamic sections (0..x)
 * @param entryIndex Position of dynamic entry in selected dynamic section
 * @return Type of selected dynamic entry
 */
std::string FileInformation::getDynamicEntryType(std::size_t sectionIndex, std::size_t entryIndex) const
{
	return dynamicSections[sectionIndex].getEntryType(entryIndex);
}

/**
 * Get description related to selected dynamic entry
 * @param sectionIndex Position of dynamic section in internal list of dynamic sections (0..x)
 * @param entryIndex Position of dynamic entry in selected dynamic section
 * @return Description related to selected dynamic entry
 */
std::string FileInformation::getDynamicEntryDescription(std::size_t sectionIndex, std::size_t entryIndex) const
{
	return dynamicSections[sectionIndex].getEntryDescription(entryIndex);
}

/**
 * Get value of selected dynamic entry
 * @param sectionIndex Position of dynamic section in internal list of dynamic sections (0..x)
 * @param entryIndex Position of dynamic entry in selected dynamic section
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Value of selected dynamic entry
 */
std::string FileInformation::getDynamicEntryValueStr(std::size_t sectionIndex, std::size_t entryIndex, std::ios_base &(* format)(std::ios_base &)) const
{
	return dynamicSections[sectionIndex].getEntryValueStr(entryIndex, format);
}

/**
 * Get number of flags in selected dynamic entry
 * @param sectionIndex Position of dynamic section in internal list of dynamic sections (0..x)
 * @param entryIndex Position of dynamic entry in selected dynamic section
 * @return Number of flags in selected dynamic entry
 */
unsigned long long FileInformation::getDynamicEntryFlagsSize(std::size_t sectionIndex, std::size_t entryIndex) const
{
	return dynamicSections[sectionIndex].getEntryFlagsSize(entryIndex);
}

/**
 * Get flags of selected dynamic entry as number
 * @param sectionIndex Position of dynamic section in internal list of dynamic sections (0..x)
 * @param entryIndex Position of dynamic entry in selected dynamic section
 * @return Flags of selected dynamic entry as number
 */
unsigned long long FileInformation::getDynamicEntryFlags(std::size_t sectionIndex, std::size_t entryIndex) const
{
	return dynamicSections[sectionIndex].getEntryFlags(entryIndex);
}

/**
 * Get flags of selected dynamic entry as string
 * @param sectionIndex Position of dynamic section in internal list of dynamic sections (0..x)
 * @param entryIndex Position of dynamic entry in selected dynamic section
 * @return Flags of selected dynamic entry as string
 */
std::string FileInformation::getDynamicEntryFlagsStr(std::size_t sectionIndex, std::size_t entryIndex) const
{
	return dynamicSections[sectionIndex].getEntryFlagsStr(entryIndex);
}

/**
 * Get number of flags descriptors of selected dynamic entry
 * @param sectionIndex Position of dynamic section in internal list of dynamic sections (0..x)
 * @param entryIndex Position of dynamic entry in selected dynamic section
 * @return Number of flags descriptors of selected dynamic entry
 */
std::size_t FileInformation::getNumberOfDynamicEntryFlagsDescriptors(std::size_t sectionIndex, std::size_t entryIndex) const
{
	return dynamicSections[sectionIndex].getNumberOfEntryFlagsDescriptors(entryIndex);
}

/**
 * Get flags descriptors of selected dynamic entry
 * @param sectionIndex Position of dynamic section in internal list of dynamic sections (0..x)
 * @param entryIndex Position of dynamic entry in selected dynamic section
 * @param desc Vector for save descriptors
 * @param abb Vector for save abbreviations of descriptors
 */
void FileInformation::getDynamicEntryFlagsDescriptors(std::size_t sectionIndex, std::size_t entryIndex, std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	return dynamicSections[sectionIndex].getEntryFlagsDescriptors(entryIndex, desc, abb);
}

/**
 * Get selected crypto pattern
 * @param position Index of pattern in internal list of crypto patterns (0..x)
 * @return Selected crypto pattern or @c nullptr if index of pattern is invalid
 */
const Pattern* FileInformation::getCryptoPattern(std::size_t position) const
{
	return position < getNumberOfCryptoPatterns() ? &cryptoPatterns[position] : nullptr;
}

/**
 * Get selected malware pattern
 * @param position Index of pattern in internal list of malware patterns (0..x)
 * @return Selected malware pattern or @c nullptr if index of pattern is invalid
 */
const Pattern* FileInformation::getMalwarePattern(std::size_t position) const
{
	return position < getNumberOfMalwarePatterns() ? &malwarePatterns[position] : nullptr;
}

/**
 * Get selected other pattern
 * @param position Index of pattern in internal list of other patterns (0..x)
 * @return Selected other pattern or @c nullptr if index of pattern is invalid
 */
const Pattern* FileInformation::getOtherPattern(std::size_t position) const
{
	return position < getNumberOfOtherPatterns() ? &otherPatterns[position] : nullptr;
}

/**
 * Get all detected crypto patterns
 * @return All detected crypto patterns
 */
const std::vector<Pattern>& FileInformation::getCryptoPatterns() const
{
	return cryptoPatterns;
}

/**
 * Get all detected malware patterns
 * @return All detected malware patterns
 */
const std::vector<Pattern>& FileInformation::getMalwarePatterns() const
{
	return malwarePatterns;
}

/**
 * Get all detected other patterns
 * @return All detected other patterns
 */
const std::vector<Pattern>& FileInformation::getOtherPatterns() const
{
	return otherPatterns;
}

/**
 * Get number of detected strings in input file
 * @return Number of detected strings in input file
 */
std::size_t FileInformation::getNumberOfDetectedStrings() const
{
	return strings.getNumberOfStrings();
}

/**
 * Get detected strings
 * @return Pointer to detected strings
 */
const Strings& FileInformation::getStrings() const
{
	return strings;
}

/**
 * Check if some strings in input file was detected
 * @return @c true if at least one string was detected, @c false otherwise
 */
bool FileInformation::hasStrings() const
{
	return getNumberOfDetectedStrings();
}

/**
 * Get whether the signature is present in the file
 * @return @c true if present, otherwise @c false.
 */
bool FileInformation::isSignaturePresent() const
{
	return signatureVerified.has_value();
}

/**
 * Get whether the signature is verified
 * @return @c true if present, otherwise @c false.
 */
bool FileInformation::isSignatureVerified() const
{
	return signatureVerified.has_value() && signatureVerified.value();
}

/**
 * Get whether the signature is verified in string representation
 * @param t String to return if verified.
 * @param f String to return if not verified.
 * @return @c t if verified, otherwise @c f.
 */
std::string FileInformation::isSignatureVerifiedStr(const std::string& t, const std::string& f) const
{
	return isSignatureVerified() ? t : f;
}

/**
 * Get ELF notes
 * @return vector with ELF notes
 */
const std::vector<ElfNotes>& FileInformation::getElfNotes() const
{
	return elfNotes;
}

/**
 * Get ELF core info
 * @return ELF core info
 */
const ElfCore& FileInformation::getElfCoreInfo() const
{
	return elfCoreInfo;
}

/**
 * Get number of detected compilers or packers
 * @return Number of detected compilers or packers
 */
std::size_t FileInformation::getNumberOfDetectedCompilers() const
{
	return toolInfo.detectedTools.size();
}

/**
 * Get image base address as string
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Image base address in string representation
 */
std::string FileInformation::getImageBaseStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return toolInfo.entryPointAddress ? getNumberAsString(toolInfo.imageBase, format) : "";
}

/**
 * Get EP virtual address as string
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Virtual address of EP in string representation
 */
std::string FileInformation::getEpAddressStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return toolInfo.entryPointAddress ? getNumberAsString(toolInfo.epAddress, format) : "";
}

/**
 * Get EP offset as string
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Offset of EP in string representation
 */
std::string FileInformation::getEpOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return toolInfo.entryPointOffset ? getNumberAsString(toolInfo.epOffset, format) : "";
}

/**
 * Get bytes on EP
 * @return Bytes on entry point in hexadecimal representation
 */
std::string FileInformation::getEpBytes() const
{
	return toolInfo.epBytes;
}

/**
 * Get index of entry point section
 * @return Index of entry point section
 */
std::string FileInformation::getEpSectionIndex() const
{
	return toolInfo.entryPointSection ? getNumberAsString(toolInfo.epSection.getIndex()) : "";
}

/**
 * Get name of entry point section
 * @return Name of entry point section
 */
std::string FileInformation::getEpSectionName() const
{
	return toolInfo.entryPointSection ? toolInfo.epSection.getName() : "";
}

/**
 * Gets loaded image base address.
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Loaded address in string form.
 */
std::string FileInformation::getLoadedBaseAddressStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return loaderInfo.getBaseAddressStr(format);
}

/**
 * Gets number of loaded segments.
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Number of loaded segments in string form.
 */
std::string FileInformation::getNumberOfLoadedSegmentsStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return loaderInfo.getNumberOfLoadedSegmentsStr(format);
}

/**
 * Gets loaded segment in the loaded image.
 * @param index Index of the segment.
 * @return Loaded segment.
 */
const LoadedSegment& FileInformation::getLoadedSegment(std::size_t index) const
{
	return loaderInfo.getLoadedSegment(index);
}

/**
 * Gets loader status message.
 * @return The status message of the loader.
 */
const std::string& FileInformation::getLoaderStatusMessage() const
{
	return loaderInfo.getStatusMessage();
}

/**
* Gets loader error message.
* @return The error message of the loader.
*/
const retdec::fileformat::LoaderErrorInfo & FileInformation::getLoaderErrorInfo() const
{
	return loaderInfo.getLoaderErrorInfo();
}

/**
 * Checks whether .NET information are used.
 * @return @c true if it is used, otherwise @c false/
 */
bool FileInformation::isDotnetUsed() const
{
	return dotnetInfo.isUsed();
}

/**
 * Returns .NET runtime version.
 * @return .NET runtime version.
 */
const std::string& FileInformation::getDotnetRuntimeVersion() const
{
	return dotnetInfo.getRuntimeVersion();
}

/**
 * Get imported class name
 * @param position Index of selected imported class (indexed from 0)
 * @return Name of selected imported class
 */
std::string FileInformation::getDotnetImportedClassName(std::size_t position) const
{
	return dotnetInfo.getImportedClassName(position);
}

/**
 * Get imported class nested name
 * @param position Index of selected imported class (indexed from 0)
 * @return Nested name of selected imported class
 */
std::string FileInformation::getDotnetImportedClassNestedName(std::size_t position) const
{
	return dotnetInfo.getImportedClassNestedName(position);
}

/**
 * Get imported class name with parent class presentation index
 * @param position Index of selected imported class (indexed from 0)
 * @return Name of selected imported class with parent class presentation index
 */
std::string FileInformation::getDotnetImportedClassNameWithParentClassIndex(std::size_t position) const
{
	return dotnetInfo.getImportedClassNameWithParentClassIndex(position);
}

/**
 * Get imported class library name
 * @param position Index of selected imported class (indexed from 0)
 * @return Library name of selected imported class
 */
std::string FileInformation::getDotnetImportedClassLibName(std::size_t position) const
{
	return dotnetInfo.getImportedClassLibName(position);
}

/**
 * Get imported class namespace
 * @param position Index of selected imported class (indexed from 0)
 * @return Namespace of selected imported class
 */
std::string FileInformation::getDotnetImportedClassNameSpace(std::size_t position) const
{
	return dotnetInfo.getImportedClassNameSpace(position);
}

/**
 * Get dotnet typeref hash as CRC32
 * @return Typeref hash as CRC32
 */
std::string FileInformation::getDotnetTypeRefhashCrc32() const
{
	return dotnetInfo.getTypeRefhashCrc32();
}

/**
 * Get dotnet typeref hash as MD5
 * @return Typeref hash as MD5
 */
std::string FileInformation::getDotnetTypeRefhashMd5() const
{
	return dotnetInfo.getTypeRefhashMd5();
}

/**
 * Get dotnet typeref hash as SHA256
 * @return Typeref hash as SHA256
 */
std::string FileInformation::getDotnetTypeRefhashSha256() const
{
	return dotnetInfo.getTypeRefhashSha256();
}

/**
 * Get number of stored imported dotnet classes
 * @return Number of stored imported dotnet classes
 */
std::size_t FileInformation::getNumberOfStoredDotnetImportedClasses() const
{
	return dotnetInfo.getNumberOfImportedClasses();
}

/**
 * Returns .NET metadata header address in string representation in specified format.
 * @param format Format.
 * @return Metadata header address in string representation.
 */
std::string FileInformation::getDotnetMetadataHeaderAddressStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return dotnetInfo.getMetadataHeaderAddressStr(format);
}

/**
 * Returns .NET metadata stream offset in string representation in specified format.
 * @param format Format.
 * @return Metadata stream offset in string representation.
 */
std::string FileInformation::getDotnetMetadataStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return dotnetInfo.getMetadataStreamOffsetStr(format);
}

/**
 * Returns .NET metadata stream size in string representation in specified format.
 * @param format Format.
 * @return Metadata stream size in string representation.
 */
std::string FileInformation::getDotnetMetadataStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return dotnetInfo.getMetadataStreamSizeStr(format);
}

/**
 * Returns .NET string stream offset in string representation in specified format.
 * @param format Format.
 * @return String stream offset in string representation.
 */
std::string FileInformation::getDotnetStringStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return dotnetInfo.getStringStreamOffsetStr(format);
}

/**
 * Returns .NET string stream size in string representation in specified format.
 * @param format Format.
 * @return String stream size in string representation.
 */
std::string FileInformation::getDotnetStringStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return dotnetInfo.getStringStreamSizeStr(format);
}

/**
 * Returns .NET blob stream offset in string representation in specified format.
 * @param format Format.
 * @return Blob stream offset in string representation.
 */
std::string FileInformation::getDotnetBlobStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return dotnetInfo.getBlobStreamOffsetStr(format);
}

/**
 * Returns .NET blob stream size in string representation in specified format.
 * @param format Format.
 * @return Blob stream size in string representation.
 */
std::string FileInformation::getDotnetBlobStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return dotnetInfo.getBlobStreamSizeStr(format);
}

/**
 * Returns .NET GUID stream offset in string representation in specified format.
 * @param format Format.
 * @return GUID stream offset in string representation.
 */
std::string FileInformation::getDotnetGuidStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return dotnetInfo.getGuidStreamOffsetStr(format);
}

/**
 * Returns .NET GUID stream size in string representation in specified format.
 * @param format Format.
 * @return GUID stream size in string representation.
 */
std::string FileInformation::getDotnetGuidStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return dotnetInfo.getGuidStreamSizeStr(format);
}

/**
 * Returns .NET user string stream offset in string representation in specified format.
 * @param format Format.
 * @return GUID stream offset in string representation.
 */
std::string FileInformation::getDotnetUserStringStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return dotnetInfo.getUserStringStreamOffsetStr(format);
}

/**
 * Returns .NET user string stream size in string representation in specified format.
 * @param format Format.
 * @return GUID stream size in string representation.
 */
std::string FileInformation::getDotnetUserStringStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return dotnetInfo.getUserStringStreamSizeStr(format);
}

/**
 * Returns .NET module version ID.
 * @return Module version ID.
 */
const std::string& FileInformation::getDotnetModuleVersionId() const
{
	return dotnetInfo.getModuleVersionId();
}

/**
 * Returns .NET TypeLib ID.
 * @return TypeLib ID.
 */
const std::string& FileInformation::getDotnetTypeLibId() const
{
	return dotnetInfo.getTypeLibId();
}

/**
 * Returns .NET defined class list.
 * @return Defined .NET classes.
 */
const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& FileInformation::getDotnetDefinedClassList() const
{
	return dotnetInfo.getDefinedClassList();
}

/**
 * Returns .NET imported class list.
 * @return Imported .NET classes.
 */
const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& FileInformation::getDotnetImportedClassList() const
{
	return dotnetInfo.getImportedClassList();
}

/**
 * Checks whether .NET information contain metadata stream.
 * @return @c true if contains, otherwise @c false.
 */
bool FileInformation::hasDotnetMetadataStream() const
{
	return dotnetInfo.hasMetadataStream();
}

/**
 * Checks whether .NET information contain string stream.
 * @return @c true if contains, otherwise @c false.
 */
bool FileInformation::hasDotnetStringStream() const
{
	return dotnetInfo.hasStringStream();
}

/**
 * Checks whether .NET information contain blob stream.
 * @return @c true if contains, otherwise @c false.
 */
bool FileInformation::hasDotnetBlobStream() const
{
	return dotnetInfo.hasBlobStream();
}

/**
 * Checks whether .NET information contain GUID stream.
 * @return @c true if contains, otherwise @c false.
 */
bool FileInformation::hasDotnetGuidStream() const
{
	return dotnetInfo.hasGuidStream();
}

/**
 * Checks whether .NET information contain user string stream.
 * @return @c true if contains, otherwise @c false.
 */
bool FileInformation::hasDotnetUserStringStream() const
{
	return dotnetInfo.hasUserStringStream();
}

/**
 * Checks whether .NET information contain TypeLib ID.
 * @return @c true if contains, otherwise @c false.
 */
bool FileInformation::hasDotnetTypeLibId() const
{
	return dotnetInfo.hasTypeLibId();
}

/**
 * Find out if there are any records in typeref table
 * @return @c true if typeref is not empty, @c false otherwise
 */
bool FileInformation::hasDotnetTypeRefTableRecords() const
{
	return dotnetInfo.hasImportedClassListRecords();
}

/**
 * Get number of anomalies
 * @return Number of anomalies
 */
std::size_t FileInformation::getNumberOfAnomalies() const
{
	return anomalies.size();
}

/**
 * Get identifier of anomaly
 * @param position Index of selected anomaly (indexed from 0)
 * @return Identifier of selected anomaly
 */
std::string FileInformation::getAnomalyIdentifier(std::size_t position) const
{
	return (position < getNumberOfAnomalies()) ? anomalies[position].first : "";
}

/**
 * Get description of anomaly
 * @param position Index of selected anomaly (indexed from 0)
 * @return Description of selected anomaly
 */
std::string FileInformation::getAnomalyDescription(std::size_t position) const
{
	return (position < getNumberOfAnomalies()) ? anomalies[position].second : "";
}

/**
 * Set instance status
 * @param state New status of this instance
 */
void FileInformation::setStatus(ReturnCode state)
{
	status = state;
}

/**
 * Set binary file name
 * @param filepath Path to input file
 */
void FileInformation::setPathToFile(const std::string &filepath)
{
	filePath = filepath;
}

void FileInformation::setTelfhash(const std::string &hash)
{
	telfhash = hash;
}

/**
 * Get CRC32 of input file
 * @param fileCrc32 CRC32 of input file
 */
void FileInformation::setCrc32(const std::string &fileCrc32)
{
	crc32 = fileCrc32;
}

/**
 * Set MD5 of input file
 * @param fileMd5 MD5 of input file
 */
void FileInformation::setMd5(const std::string &fileMd5)
{
	md5 = fileMd5;
}

/**
 * Set SHA256 of input file
 * @param fileSha256 SHA256 of input file
 */
void FileInformation::setSha256(const std::string &fileSha256)
{
	sha256 = fileSha256;
}

/**
 * Set CRC32 of section table
 * @param sCrc32 CRC32 of section table
 */
void FileInformation::setSectionTableCrc32(const std::string &sCrc32)
{
	secCrc32 = sCrc32;
}

/**
 * Set MD5 of section table
 * @param sMd5 MD5 of section table
 */
void FileInformation::setSectionTableMd5(const std::string &sMd5)
{
	secMd5 = sMd5;
}

/**
 * Set SHA256 of section table
 * @param sSha256 SHA256 of section table
 */
void FileInformation::setSectionTableSha256(const std::string &sSha256)
{
	secSha256 = sSha256;
}

/**
 * Set file format
 * @param format File format in enumeration representation
 */
void FileInformation::setFileFormatEnum(retdec::fileformat::Format format)
{
	fileFormatEnum = format;
}

/**
 * Set file format
 * @param fileformat File format in string representation
 */
void FileInformation::setFileFormat(const std::string &fileformat)
{
	fileFormat = fileformat;
}

/**
 * Set file class
 * @param fileclass File class
 */
void FileInformation::setFileClass(const std::string &fileclass)
{
	fileClass = fileclass;
}

/**
 * Set file type
 * @param filetype File type
 */
void FileInformation::setFileType(const std::string &filetype)
{
	fileType = filetype;
}

/**
 * Set file target architecture
 * @param architecture File target architecture
 */
void FileInformation::setTargetArchitecture(const std::string &architecture)
{
	targetArchitecture = architecture;
}

/**
 * Set endianness
 * @param fileEndianness File endianness
 */
void FileInformation::setEndianness(const std::string &fileEndianness)
{
	endianness = fileEndianness;
}

/**
 * Set manifest
 * @param fileManifest File manifest
 */
void FileInformation::setManifest(const std::string &fileManifest)
{
	manifest = fileManifest;
}

/**
 * Set compact version of manifest
 * @param fileCompactManifest Compact version of manifest
 */
void FileInformation::setCompactManifest(const std::string &fileCompactManifest)
{
	compactManifest = fileCompactManifest;
}

/**
 * Set time stamp
 * @param timestamp Time stamp
 */
void FileInformation::setTimeStamp(const std::string &timestamp)
{
	header.setTimeStamp(timestamp);
}

/**
 * Set file status
 * @param fileStatus File status
 */
void FileInformation::setFileStatus(const std::string &fileStatus)
{
	header.setFileStatus(fileStatus);
}

/**
 * Set file version
 * @param version Version of file
 */
void FileInformation::setFileVersion(const std::string &version)
{
	header.setFileVersion(version);
}

/**
 * Set file header version
 * @param version Version of file header
 */
void FileInformation::setFileHeaderVersion(const std::string &version)
{
	header.setFileHeaderVersion(version);
}

/**
 * Set operating system or ABI extension
 * @param osabi OS or ABI extension
 */
void FileInformation::setOsAbi(const std::string &osabi)
{
	header.setOsAbi(osabi);
}

/**
 * Set OS or ABI version
 * @param abiversion Version of OS or ABI
 */
void FileInformation::setOsAbiVersion(const std::string &abiversion)
{
	header.setOsAbiVersion(abiversion);
}

/**
 * Set flags size
 * @param size Number of file flags
 */
void FileInformation::setFileFlagsSize(unsigned long long size)
{
	header.setFileFlagsSize(size);
}

/**
 * Set file flags
 * @param flagsArray Bit flags as one number
 */
void FileInformation::setFileFlags(unsigned long long flagsArray)
{
	header.setFileFlags(flagsArray);
}

/**
 * Set size of DLL flags
 * @param size Size od DLL flags
 */
void FileInformation::setDllFlagsSize(unsigned long long size)
{
	header.setDllFlagsSize(size);
}

/**
 * Set DLL flags
 * @param flagsArray Bit flags as one number
 */
void FileInformation::setDllFlags(unsigned long long flagsArray)
{
	header.setDllFlags(flagsArray);
}

/**
 * Set number of bits in one byte
 * @param bitsInByte Number of bits in one byte
 */
void FileInformation::setNumberOfBitsInByte(unsigned long long bitsInByte)
{
	header.setNumberOfBitsInByte(bitsInByte);
}

/**
 * Set number of bits in one word
 * @param bitsInWord Number of bits in one word
 */
void FileInformation::setNumberOfBitsInWord(unsigned long long bitsInWord)
{
	header.setNumberOfBitsInWord(bitsInWord);
}

/**
 * Set size of file header
 * @param size Size of file header
 */
void FileInformation::setFileHeaderSize(unsigned long long size)
{
	header.setFileHeaderSize(size);
}

/**
 * Set segment table offset
 * @param offset Segment table offset
 */
void FileInformation::setSegmentTableOffset(unsigned long long offset)
{
	header.setSegmentTableOffset(offset);
}

/**
 * Set size of one entry in segment table
 * @param entrySize Size of one entry in segment table
 */
void FileInformation::setSegmentTableEntrySize(unsigned long long entrySize)
{
	header.setSegmentTableEntrySize(entrySize);
}

/**
 * Set segment table size
 * @param tableSize Size of segment table
 */
void FileInformation::setSegmentTableSize(unsigned long long tableSize)
{
	header.setSegmentTableSize(tableSize);
}

/**
 * Set declared number of segments in file
 * @param noOfSegments Declared number of segments in file
 */
void FileInformation::setNumberOfDeclaredSegments(unsigned long long noOfSegments)
{
	header.setNumberOfSegments(noOfSegments);
}

/**
 * Set section table offset
 * @param offset Section table offset
 */
void FileInformation::setSectionTableOffset(unsigned long long offset)
{
	header.setSectionTableOffset(offset);
}

/**
 * Set size of one entry in section table
 * @param entrySize Size of one entry in section table
 */
void FileInformation::setSectionTableEntrySize(unsigned long long entrySize)
{
	header.setSectionTableEntrySize(entrySize);
}

/**
 * Set section table size
 * @param tableSize Size of section table
 */
void FileInformation::setSectionTableSize(unsigned long long tableSize)
{
	header.setSectionTableSize(tableSize);
}

/**
 * Set declared number of sections in file
 * @param noOfSections Declared number of sections in file
 */
void FileInformation::setNumberOfDeclaredSections(unsigned long long noOfSections)
{
	header.setDeclaredNumberOfSections(noOfSections);
}

/**
 * Set size of COFF file header
 * @param headerSize Size of COFF file header
 */
void FileInformation::setCoffFileHeaderSize(unsigned long long headerSize)
{
	header.setCoffFileHeaderSize(headerSize);
}

/**
 * Set size of optional file header
 * @param headerSize Size of optional file header
 */
void FileInformation::setOptionalHeaderSize(unsigned long long headerSize)
{
	header.setOptionalHeaderSize(headerSize);
}

/**
 * Set file checksum
 * @param fileChecksum File checksum
 */
void FileInformation::setChecksum(unsigned long long fileChecksum)
{
	header.setChecksum(fileChecksum);
}

/**
 * Set size of the stack to reserve
 * @param size Size of the stack to reserve
 */
void FileInformation::setStackReserveSize(unsigned long long size)
{
	header.setStackReserveSize(size);
}

/**
 * Set size of the stack to commit
 * @param size Size of the stack to commit
 */
void FileInformation::setStackCommitSize(unsigned long long size)
{
	header.setStackCommitSize(size);
}

/**
 * Set size of the local heap space to reserve
 * @param size Size of the local heap space to reserve
 */
void FileInformation::setHeapReserveSize(unsigned long long size)
{
	header.setHeapReserveSize(size);
}

/**
 * Set size of the local heap space to commit
 * @param size Size of the local heap space to commit
 */
void FileInformation::setHeapCommitSize(unsigned long long size)
{
	header.setHeapCommitSize(size);
}

/**
 * Set declared number of data directories in file
 * @param noOfDirectories Declared number of data directories in file
 */
void FileInformation::setNumberOfDeclaredDataDirectories(unsigned long long noOfDirectories)
{
	header.setNumberOfDataDirectories(noOfDirectories);
}

/**
 * Set declared number of symbol tables in file
 * @param noOfTables Declared number of symbol tables in file
 */
void FileInformation::setNumberOfDeclaredSymbolTables(unsigned long long noOfTables)
{
	header.setNumberOfSymbolTables(noOfTables);
}

/**
 * Set overlay offset
 * @param offset Overlay offset
 */
void FileInformation::setOverlayOffset(unsigned long long offset)
{
	header.setOverlayOffset(offset);
}

/**
 * Set overlay size
 * @param size Size of overlay
 */
void FileInformation::setOverlaySize(unsigned long long size)
{
	header.setOverlaySize(size);
}

/**
 * Set overlay entropy
 * @param entropy Entropy of overlay
 */
void FileInformation::setOverlayEntropy(double entropy)
{
	header.setOverlayEntropy(entropy);
}

/**
 * Set rich header
 * @param rHeader Information about rich header
 */
void FileInformation::setRichHeader(const retdec::fileformat::RichHeader *rHeader)
{
	richHeader.setHeader(rHeader);
}

/**
 * Set visual basic information
 * @param vbInfo Information about visual basic
 */
void FileInformation::setVisualBasicInfo(const retdec::fileformat::VisualBasicInfo *vbInfo)
{
	visualBasicInfo.setInfo(vbInfo);
}

/**
 * Sets whether visual basic informations are used.
 * @param set @c true if used, otherwise @c false.
 */
void FileInformation::setVisualBasicUsed(bool set)
{
	visualBasicInfo.setUsed(set);
}

/**
 * Set type of related PDB file
 * @param sType Type of related PDB file
 */
void FileInformation::setPdbType(const std::string &sType)
{
	pdbInfo.setType(sType);
}

/**
 * Set original path to related PDB file
 * @param sPath Original path to related PDB file
 */
void FileInformation::setPdbPath(const std::string &sPath)
{
	pdbInfo.setPath(sPath);
}

/**
 * Set GUID of related PDB file
 * @param sGuid GUID of related PDB file
 */
void FileInformation::setPdbGuid(const std::string &sGuid)
{
	pdbInfo.setGuid(sGuid);
}

/**
 * Set age of related PDB file
 * @param sAge Age of related PDB file
 */
void FileInformation::setPdbAge(std::size_t sAge)
{
	pdbInfo.setAge(sAge);
}

/**
 * Set timestamp of related PDB file
 * @param sTimeStamp Timestamp of related PDB file
 */
void FileInformation::setPdbTimeStamp(std::size_t sTimeStamp)
{
	pdbInfo.setTimeStamp(sTimeStamp);
}

/**
 * Set import table
 * @param sTable Information about import table
 */
void FileInformation::setImportTable(const retdec::fileformat::ImportTable *sTable)
{
	importTable.setTable(sTable);
}

/**
 * Set export table
 * @param sTable Information about export table
 */
void FileInformation::setExportTable(const retdec::fileformat::ExportTable *sTable)
{
	exportTable.setTable(sTable);
}

/**
 * Set resource table
 * @param sTable Information about resource table
 */
void FileInformation::setResourceTable(const retdec::fileformat::ResourceTable *sTable)
{
	resourceTable.setTable(sTable);
}

/**
 * Set pointer to detected strings
 * @param sStrings Pointer to detected strings
 */
void FileInformation::setStrings(const std::vector<retdec::fileformat::String> *sStrings)
{
	strings.setStrings(sStrings);
}

/**
 * Set certificate table
 * @param sTable Information about certificate table
 */
void FileInformation::setCertificateTable(const retdec::fileformat::CertificateTable*  sTable)
{
	certificateTable = sTable;
}

/**
 * Set TLS information
 * @param info Information TLS
 */
void FileInformation::setTlsInfo(const retdec::fileformat::TlsInfo *info)
{
	tlsInfo.setTlsInfo(info);
}

/**
 * Set whether the signature is verified
 * @param verified @c true if verified, otherwise @c false.
 */
void FileInformation::setSignatureVerified(bool verified)
{
	signatureVerified = verified;
}

/**
 * Sets loaded image base address.
 * @param baseAddress Base address of image.
 */
void FileInformation::setLoadedBaseAddress(unsigned long long baseAddress)
{
	loaderInfo.setBaseAddress(baseAddress);
}

/**
 * Sets loader status message.
 * @param statusMessage The status message of the loader.
 */
void FileInformation::setLoaderStatusMessage(const std::string& statusMessage)
{
	loaderInfo.setStatusMessage(statusMessage);
}

/**
* Sets loader error message.
* @param ldrErrInfo The loader error message.
*/
void FileInformation::setLoaderErrorInfo(const retdec::fileformat::LoaderErrorInfo & ldrErrInfo)
{
	loaderInfo.setLoaderErrorInfo(ldrErrInfo);
}

/**
 * Sets whether .NET information are used.
 * @param set @c true if used, otherwise @c false.
 */
void FileInformation::setDotnetUsed(bool set)
{
	dotnetInfo.setUsed(set);
}

/**
 * Sets .NET runtime version.
 * @param majorVersion .NET major runtime version.
 * @param minorVersion .NET minor runtime version.
 */
void FileInformation::setDotnetRuntimeVersion(std::uint64_t majorVersion, std::uint64_t minorVersion)
{
	dotnetInfo.setRuntimeVersion(majorVersion, minorVersion);
}

/**
 * Sets .NET metadata header address.
 * @param address .NET metadata header address.
 */
void FileInformation::setDotnetMetadataHeaderAddress(std::uint64_t address)
{
	dotnetInfo.setMetadataHeaderAddress(address);
}

/**
 * Sets .NET metadata stream information.
 * @param streamOffset Stream offset.
 * @param streamSize Stream size.
 */
void FileInformation::setDotnetMetadataStreamInfo(std::uint64_t streamOffset, std::uint64_t streamSize)
{
	dotnetInfo.setMetadataStreamInfo(streamOffset, streamSize);
}

/**
 * Sets .NET string stream information.
 * @param streamOffset Stream offset.
 * @param streamSize Stream size.
 */
void FileInformation::setDotnetStringStreamInfo(std::uint64_t streamOffset, std::uint64_t streamSize)
{
	dotnetInfo.setStringStreamInfo(streamOffset, streamSize);
}

/**
 * Sets .NET blob stream information.
 * @param streamOffset Stream offset.
 * @param streamSize Stream size.
 */
void FileInformation::setDotnetBlobStreamInfo(std::uint64_t streamOffset, std::uint64_t streamSize)
{
	dotnetInfo.setBlobStreamInfo(streamOffset, streamSize);
}

/**
 * Sets .NET GUID stream information.
 * @param streamOffset Stream offset.
 * @param streamSize Stream size.
 */
void FileInformation::setDotnetGuidStreamInfo(std::uint64_t streamOffset, std::uint64_t streamSize)
{
	dotnetInfo.setGuidStreamInfo(streamOffset, streamSize);
}

/**
 * Sets .NET user string stream information.
 * @param streamOffset Stream offset.
 * @param streamSize Stream size.
 */
void FileInformation::setDotnetUserStringStreamInfo(std::uint64_t streamOffset, std::uint64_t streamSize)
{
	dotnetInfo.setUserStringStreamInfo(streamOffset, streamSize);
}

/**
 * Sets .NET module version ID.
 * @param moduleVersionId Module version ID.
 */
void FileInformation::setDotnetModuleVersionId(const std::string& moduleVersionId)
{
	dotnetInfo.setModuleVersionId(moduleVersionId);
}

/**
 * Sets .NET typelib ID.
 * @param typeLibId TypeLib ID.
 */
void FileInformation::setDotnetTypeLibId(const std::string& typeLibId)
{
	dotnetInfo.setTypeLibId(typeLibId);
}

/**
 * Sets .NET defined class list.
 * @param dotnetClassList Defined .NET classes.
 */
void FileInformation::setDotnetDefinedClassList(const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& dotnetClassList)
{
	dotnetInfo.setDefinedClassList(dotnetClassList);
}

/**
 * Sets .NET imported class list.
 * @param dotnetClassList Imported .NET classes.
 */
void FileInformation::setDotnetImportedClassList(const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& dotnetClassList)
{
	dotnetInfo.setImportedClassList(dotnetClassList);
}

/**
 * Sets .NET typeref hash as CRC32.
 * @param crc32 Hash as CRC32.
 */
void FileInformation::setDotnetTypeRefhashCrc32(const std::string& crc32)
{
	dotnetInfo.setTypeRefhashCrc32(crc32);
}

/**
 * Sets .NET typeref hash as MD5.
 * @param md5 Hash as MD5.
 */
void FileInformation::setDotnetTypeRefhashMd5(const std::string& md5)
{
	dotnetInfo.setTypeRefhashMd5(md5);
}

/**
 * Sets .NET typeref hash as SHA256.
 * @param sha256 Hash as SHA256.
 */
void FileInformation::setDotnetTypeRefhashSha256(const std::string& sha256)
{
	dotnetInfo.setTypeRefhashSha256(sha256);
}

/**
 * Sets anomalies
 * @param anom Anomalies
 */
void FileInformation::setAnomalies(const std::vector<std::pair<std::string,std::string>> &anom)
{
	anomalies = anom;
}

/**
 * Add file flag descriptor
 * @param descriptor Descriptor (full description of flag)
 * @param abbreviation Abbreviation (short description of flag)
 */
void FileInformation::addFileFlagsDescriptor(std::string descriptor, std::string abbreviation)
{
	header.addFileFlagsDescriptor(descriptor, abbreviation);
}

/**
 * Clear file flags descriptors
 */
void FileInformation::clearFileFlagsDescriptors()
{
	header.clearFileFlagsDescriptors();
}

/**
 * Add DLL flag descriptor
 * @param descriptor Descriptor (full description of flag)
 * @param abbreviation Abbreviation (short description of flag)
 */
void FileInformation::addDllFlagsDescriptor(std::string descriptor, std::string abbreviation)
{
	header.addDllFlagsDescriptor(descriptor, abbreviation);
}

/**
 * Clear DLL flags descriptors
 */
void FileInformation::clearDllFlagsDescriptors()
{
	header.clearDllFlagsDescriptors();
}

/**
 * Add data directory
 * @param dataDirectory File data directory
 */
void FileInformation::addDataDirectory(DataDirectory &dataDirectory)
{
	directories.push_back(dataDirectory);
}

/**
 * Add segment
 * @param fileSegment Segment of file
 */
void FileInformation::addSegment(FileSegment &fileSegment)
{
	segments.push_back(fileSegment);
}

/**
 * Add section
 * @param fileSection File section
 */
void FileInformation::addSection(FileSection &fileSection)
{
	sections.push_back(fileSection);
}

/**
 * Add symbol table
 * @param table Symbol table
 */
void FileInformation::addSymbolTable(SymbolTable &table)
{
	symbolTables.push_back(table);
}

/**
 * Add relocation table
 * @param table Relocation table
 */
void FileInformation::addRelocationTable(RelocationTable &table)
{
	relocationTables.push_back(table);
}

/**
 * Add dynamic section
 * @param section Dynamic section
 */
void FileInformation::addDynamicSection(DynamicSection &section)
{
	dynamicSections.push_back(section);
}

/**
 * Add ELF notes
 * @param notes Loaded ELF notes
 */
void FileInformation::addElfNotes(ElfNotes& notes)
{
	elfNotes.push_back(notes);
}

void FileInformation::addFileMapEntry(const FileMapEntry& entry)
{
	elfCoreInfo.addFileMapEntry(entry);
}

void FileInformation::addAuxVectorEntry(const std::string& name, std::size_t value)
{
	elfCoreInfo.addAuxVectorEntry(name, value);
}

/**
 * Add crypto pattern
 * @param pattern Crypto pattern
 */
void FileInformation::addCryptoPattern(Pattern &pattern)
{
	cryptoPatterns.push_back(pattern);
}

/**
 * Remove redundant detected crypto patterns
 */
void FileInformation::removeRedundantCryptoRules()
{
	for(std::size_t i = 0, noOfPatterns = getNumberOfCryptoPatterns(); i < noOfPatterns; ++i)
	{
		const auto &first = cryptoPatterns[i];

		for(std::size_t j = i + 1; j < noOfPatterns; ++j)
		{
			const auto &second = cryptoPatterns[j];
			if(isSubpattern(first, second))
			{
				cryptoPatterns.erase(cryptoPatterns.begin() + j);
				--noOfPatterns;
				--j;
			}
			else if(isSubpattern(second, first))
			{
				cryptoPatterns.erase(cryptoPatterns.begin() + i);
				--noOfPatterns;
				--i;
				break;
			}
		}
	}
}

/**
 * Sort detected crypto pattern matches based on their offset
 */
void FileInformation::sortCryptoPatternMatches()
{
	sortPatternMatches(cryptoPatterns);
}

/**
 * Add malware pattern
 * @param pattern Malware pattern
 */
void FileInformation::addMalwarePattern(Pattern &pattern)
{
	malwarePatterns.push_back(pattern);
}

/**
 * Sort detected malware pattern matches based on their offset
 */
void FileInformation::sortMalwarePatternMatches()
{
	sortPatternMatches(malwarePatterns);
}

/**
 * Add other pattern
 * @param pattern Other pattern
 */
void FileInformation::addOtherPattern(Pattern &pattern)
{
	otherPatterns.push_back(pattern);
}

/**
 * Sort detected other pattern matches based on their offset
 */
void FileInformation::sortOtherPatternMatches()
{
	sortPatternMatches(otherPatterns);
}

/**
 * Add information about detected tool to the list
 * @param tool Information about detected tool
 */
void FileInformation::addTool(DetectResult &tool)
{
	toolInfo.detectedTools.push_back(tool);
}

/**
 * Adds loaded segment.
 * @param segment Loaded segment to add.
 */
void FileInformation::addLoadedSegment(const LoadedSegment& segment)
{
	loaderInfo.addLoadedSegment(segment);
}

} // namespace fileinfo
} // namespace retdec
