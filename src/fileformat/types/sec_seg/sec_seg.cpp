/**
 * @file src/fileformat/types/sec_seg/sec_seg.cpp
 * @brief Basic class for section and segment.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "retdec/crypto/crypto.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/types/sec_seg/sec_seg.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/fileformat/utils/file_io.h"
#include "retdec/fileformat/utils/other.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
SecSeg::SecSeg() : type(Type::UNDEFINED_SEC_SEG), index(0), offset(0), fileSize(0),
	address(0), memorySize(0), entrySize(0), memorySizeIsValid(false),
	entrySizeIsValid(false), isInMemory(false), loaded(false)
{

}

/**
 * Destructor (default implementation)
 */
SecSeg::~SecSeg()
{

}

/**
 * Compute all supported hashes
 */
void SecSeg::computeHashes()
{
	const auto *hashData = reinterpret_cast<const unsigned char*>(bytes.data());
	crc32 = retdec::crypto::getCrc32(hashData, bytes.size());
	md5 = retdec::crypto::getMd5(hashData, bytes.size());
	sha256 = retdec::crypto::getSha256(hashData, bytes.size());
}

/**
 * Check if section type is undefined
 * @return @c true if section type is undefined, @c false otherwise
 */
bool SecSeg::isUndefined() const
{
	return getType() == Type::UNDEFINED_SEC_SEG;
}

/**
 * Check if section is code section
 * @return @c true if section is code section, @c false otherwise
 */
bool SecSeg::isCode() const
{
	return getType() == Type::CODE;
}

/**
 * Check if section is data section
 * @return @c true if section is data section, @c false otherwise
 */
bool SecSeg::isData() const
{
	return getType() == Type::DATA;
}

/**
 * Check if section is code_data section
 * @return @c true if section is code_data section, @c false otherwise
 */
bool SecSeg::isCodeAndData() const
{
	return getType() == Type::CODE_DATA;
}

/**
 * Check if section is const data section
 * @return @c true if section is const data section, @c false otherwise
 */
bool SecSeg::isConstData() const
{
	return getType() == Type::CONST_DATA;
}

/**
 * Check if section is BSS section
 * @return @c true if section is BSS section, @c false otherwise
 */
bool SecSeg::isBss() const
{
	return getType() == Type::BSS;
}

/**
 * Check if section is debug section
 * @return @c true if section is debug section, @c false otherwise
 */
bool SecSeg::isDebug() const
{
	return getType() == Type::DEBUG;
}

/**
 * Check if section is info section
 * @return @c true if section is info section, @c false otherwise
 */
bool SecSeg::isInfo() const
{
	return getType() == Type::INFO;
}

/**
 * @return @c true if isData() or isCodeAndData() or isConstData(), @c false otherwise.
 */
bool SecSeg::isSomeData() const
{
	return isData() || isCodeAndData() || isConstData();
}

/**
 * @return @c true if isCode() or isCodeAndData(), @c false otherwise.
 */
bool SecSeg::isSomeCode() const
{
	return isCode() || isCodeAndData();
}

/**
 * @return @c true if isData() or isConstData(), @c false otherwise.
 */
bool SecSeg::isDataOnly() const
{
	return isData() || isConstData();
}

/**
 * @return @c true if isCode() or isConstData(), @c false otherwise.
 */
bool SecSeg::isReadOnly() const
{
	return isCode() || isConstData();
}

/**
 * Does this section appear to be valid in the context of the provided input file?
 * @param sOwner Pointer to input file
 * @return @c true if section is valid, @c false otherwise
 */
bool SecSeg::isValid(const FileFormat *sOwner) const
{
	if(!sOwner || getOffset() >= sOwner->getLoadedFileLength())
	{
		return false;
	}
	if(!isBss() && !getSizeInFile())
	{
		return false;
	}
	if(!isBss() && entrySizeIsValid && entrySize > getSizeInFile())
	{
		return false;
	}

	return true;
}

/**
 * Get CRC32
 * @return CRC32 of section content
 */
std::string SecSeg::getCrc32() const
{
	return crc32;
}

/**
 * Get MD5
 * @return MD5 of section content
 */
std::string SecSeg::getMd5() const
{
	return md5;
}

/**
 * Get SHA256
 * @return SHA256 of section content
 */
std::string SecSeg::getSha256() const
{
	return sha256;
}

/**
 * Get name
 * @return Name
 */
std::string SecSeg::getName() const
{
	return name;
}

/**
 * Returns the name as a null-terminated C string.
 *
 * This version of getName() is useful when communicating with C APIs because
 * the following code has undefined behavior (getName() returns a temporary):
 * @code
 * const char *name = sec->getName().c_str();
 * @endcode
 * Instead, use this function:
 * @code
 * const char *name = sec->getNameAsCStr();
 * @endcode
 *
 * The returned pointer is valid as long as (1) the section/segment exists and
 * (2) its name has not been changed.
 */
const char* SecSeg::getNameAsCStr() const
{
	return name.c_str();
}

/**
 * Get section or segment content as reference to string
 * @param sOffset First byte of the section or segment data to get (0 means
 *    first byte of section or segment data)
 * @param sSize Number of bytes to get. If this parameter is set to zero, method
 *    returns all bytes from @a sOffset until end of section or segment data.
 * @return Section or segment content as reference to string
 */
const llvm::StringRef SecSeg::getBytes(unsigned long long sOffset, unsigned long long sSize) const
{
	if(sOffset >= bytes.size())
	{
		return StringRef("");
	}

	return StringRef(bytes.data() + sOffset, getRealSizeInRegion(sOffset, sSize, bytes.size()));
}

/**
 * Get type
 * @return Type
 */
SecSeg::Type SecSeg::getType() const
{
	return type;
}

/**
 * Get index
 * @return Index
 */
unsigned long long SecSeg::getIndex() const
{
	return index;
}

/**
 * Get offset
 * @return Offset
 */
unsigned long long SecSeg::getOffset() const
{
	return offset;
}

/**
 * Get end offset
 * @return End offset of section or segment in file
 */
unsigned long long SecSeg::getEndOffset() const
{
	const auto size = getSizeInFile();
	return size ? getOffset() + size : getOffset() + 1;
}

/**
 * Get size in file
 * @return Size in file
 */
unsigned long long SecSeg::getSizeInFile() const
{
	return fileSize;
}

/**
 * Get real file size of section or segment
 * @return Real file size of section or segment
 */
unsigned long long SecSeg::getLoadedSize() const
{
	return bytes.size();
}

/**
 * Get address
 * @return Address
 */
unsigned long long SecSeg::getAddress() const
{
	return address;
}

/**
 * Get end address
 * @return End address of section or segment in memory
 */
unsigned long long SecSeg::getEndAddress() const
{
	unsigned long long size = 0;
	if(!getSizeInMemory(size) || size < getSizeInFile())
	{
		size = getSizeInFile();
	}

	return size ? getAddress() + size : getAddress() + 1;
}

/**
 * Get size of section or segment in memory
 * @param sMemorySize Into this parameter is stored section or segment memory size
 * @return @c true if memory size is valid, @c false otherwise
 *
 * If method returns @c false, @a sMemorySize is left unchanged
 */
bool SecSeg::getSizeInMemory(unsigned long long &sMemorySize) const
{
	if(memorySizeIsValid)
	{
		sMemorySize = memorySize;
	}

	return memorySizeIsValid;
}

/**
 * Get size of one entry in section or segment
 * @param sEntrySize Into this parameter is stored section or segment entry size
 * @return @c true if section or segment entry size is valid, @c false otherwise
 *
 * If method returns @c false, @a sEntrySize is left unchanged
 */
bool SecSeg::getSizeOfOneEntry(unsigned long long &sEntrySize) const
{
	if(entrySizeIsValid)
	{
		sEntrySize = entrySize;
	}

	return entrySizeIsValid;
}

/**
 * Return @c true if the section or segment will appear in the memory image of a process,
 *    @c false otherwise
 */
bool SecSeg::getMemory() const
{
	return isInMemory;
}

/**
 * Get content of section or segment as bits
 * @param sResult Read bits in string representation
 * @return @c true if operation went OK, @c false otherwise
 */
bool SecSeg::getBits(std::string &sResult) const
{
	sResult = bytesToBits(bytes.data(), bytes.size());
	return loaded;
}

/**
 * Get content of section or segment as bytes
 * @param sResult Read bytes in integer representation
 * @param sOffset First byte of the section or segment to be loaded (0 means
 *    first byte of section or segment)
 * @param sSize Number of bytes for read. If this parameter is set to zero,
 *    method will read all bytes from @a sOffset until end of section or segment.
 * @return @c true if operation went OK, @c false otherwise
 */
bool SecSeg::getBytes(std::vector<unsigned char> &sResult, unsigned long long sOffset, unsigned long long sSize) const
{
	if(sOffset >= bytes.size())
	{
		return false;
	}

	sSize = getRealSizeInRegion(sOffset, sSize, bytes.size());
	sResult.reserve(sSize);
	sResult.assign(bytes.begin() + sOffset, bytes.begin() + sOffset + sSize);
	return loaded;
}

/**
 * Get content of section or segment as plain string
 * @param sResult Into this parameter is stored content of section or segment as plain string
 * @param sOffset First byte of the section or segment to be loaded (0 means
 *    first byte of section or segment)
 * @param sSize Number of bytes for read. If this parameter is set to zero,
 *    method will read all bytes from @a sOffset until end of section or segment.
 * @return @c true if operation went OK, @c false otherwise
 */
bool SecSeg::getString(std::string &sResult, unsigned long long sOffset, unsigned long long sSize) const
{
	if(sOffset >= bytes.size())
	{
		return false;
	}

	bytesToString(bytes.data(), bytes.size(), sResult, sOffset, sSize);
	return loaded;
}

/**
 * Get content of section or segment as bytes
 * @param sResult Read bytes in hexadecimal string representation
 * @return @c true if operation went OK, @c false otherwise
 */
bool SecSeg::getHexBytes(std::string &sResult) const
{
	bytesToHexString(bytes.data(), bytes.size(), sResult);
	return loaded;
}

/**
 * Set name
 * @param sName Name
 */
void SecSeg::setName(std::string sName)
{
	name = sName;
}

/**
 * Set type
 * @param sType Type
 */
void SecSeg::setType(SecSeg::Type sType)
{
	type = sType;
}

/**
 * Set index
 * @param sIndex Index
 */
void SecSeg::setIndex(unsigned long long sIndex)
{
	index = sIndex;
}

/**
 * Set offset
 * @param sOffset Offset
 */
void SecSeg::setOffset(unsigned long long sOffset)
{
	offset = sOffset;
}

/**
 * Set size in file
 * @param sFileSize Size in file
 */
void SecSeg::setSizeInFile(unsigned long long sFileSize)
{
	fileSize = sFileSize;
}

/**
 * Set address
 * @param sAddress Address
 */
void SecSeg::setAddress(unsigned long long sAddress)
{
	address = sAddress;
}

/**
 * Set size of section or segment in memory
 * @param sMemorySize Size of section or segment in memory
 */
void SecSeg::setSizeInMemory(unsigned long long sMemorySize)
{
	memorySize = sMemorySize;
	memorySizeIsValid = true;
}

/**
 * Set size of one entry in section or segment
 * @param sEntrySize Size of one entry in section or segment
 */
void SecSeg::setSizeOfOneEntry(unsigned long long sEntrySize)
{
	entrySize = sEntrySize;
	entrySizeIsValid = true;
}

/**
 * Set @c true if the section or segment will appear in the memory image of a process,
 *    @c false otherwise
 */
void SecSeg::setMemory(bool sMemory)
{
	isInMemory = sMemory;
}

/**
 * Invalidate size of section or segment in memory
 *
 * Instance method @a getSizeInMemory() returns @c false after invocation of
 * this method. Size in memory is possible to revalidate by invocation
 * of method @a setMemorySize().
 */
void SecSeg::invalidateMemorySize()
{
	memorySizeIsValid = false;
}

/**
 * Invalidate size of one entry in section or segment
 *
 * Instance method @a getSizeOfOneEntry() returns @c false after invocation of
 * this method. Size of one entry is possible to revalidate by invocation
 * of method @a setSizeOfOneEntry().
 */
void SecSeg::invalidateEntrySize()
{
	entrySizeIsValid = false;
}

/**
 * Load content of section or segment from input file
 * @param sOwner Pointer to input file
 *
 * This method must be called before getters of section or segment content
 */
void SecSeg::load(const FileFormat *sOwner)
{
	if(!fileSize || !sOwner || offset >= sOwner->getLoadedFileLength())
	{
		bytes = "";
		loaded = sOwner && offset < sOwner->getLoadedFileLength();
		return;
	}

	bytes = StringRef(reinterpret_cast<const char*>(sOwner->getLoadedBytesData() + offset), std::min(fileSize, sOwner->getLoadedFileLength() - offset));
	loaded = true;

	if (!(sOwner->getLoadFlags() & LoadFlags::NO_VERBOSE_HASHES))
	{
		computeHashes();
	}
}

/**
 * Dump information about instance
 * @param sDump Into this parameter is stored dump of instance in an LLVM style
 */
void SecSeg::dump(std::string &sDump) const
{
	std::stringstream ret;
	std::string sType, sName = replaceNonprintableChars(getName());

	switch(getType())
	{
		case SecSeg::Type::CODE:
			sType = "CODE";
			break;
		case SecSeg::Type::DATA:
			sType = "DATA";
			break;
		case SecSeg::Type::CODE_DATA:
			sType = "CODE_DATA";
			break;
		case SecSeg::Type::CONST_DATA:
			sType = "CONST_DATA";
			break;
		case SecSeg::Type::BSS:
			sType = "BSS";
			break;
		case SecSeg::Type::DEBUG:
			sType = "DEBUG";
			break;
		case SecSeg::Type::INFO:
			sType = "INFO";
			break;
		default:
			sType = "UNDEF";
	}

	ret << "; ------------ SecSeg ------------\n";
	ret << "; Index: " << getIndex() << "\n";
	if(!sName.empty())
	{
		ret << "; Name: " << sName << "\n";
	}
	ret << "; Type: " << sType << "\n";
	ret << "; Offset in file: " << std::hex << getOffset() << "\n";
	ret << "; Size in file: " << getSizeInFile() << "\n";
	ret << "; Loaded size: " << getLoadedSize() << "\n";
	ret << "; Address: " << getAddress() << "\n";
	ret << "; Is in memory: " << getMemory() << "\n";
	if(memorySizeIsValid)
	{
		ret << "; Size in memory: " << memorySize << "\n";
	}
	if(entrySizeIsValid)
	{
		ret << "; Size of one entry: " << entrySize << "\n";
	}
	if(hasCrc32())
	{
		ret << "; CRC32: " << getCrc32() << "\n";
	}
	if(hasMd5())
	{
		ret << "; MD5: " << getMd5() << "\n";
	}
	if(hasSha256())
	{
		ret << "; SHA256: " << getSha256() << "\n";
	}

	sDump = ret.str() + "\n";
}

/**
 * Check if CRC32 was computed
 * @return @c true if CRC32 was computed, @c false otherwise
 */
bool SecSeg::hasCrc32() const
{
	return !crc32.empty();
}

/**
 * Check if MD5 was computed
 * @return @c true if MD5 was computed, @c false otherwise
 */
bool SecSeg::hasMd5() const
{
	return !md5.empty();
}

/**
 * Check if SHA256 was computed
 * @return @c true if SHA256 was computed, @c false otherwise
 */
bool SecSeg::hasSha256() const
{
	return !sha256.empty();
}

/**
 * @return @c true if section or segment has empty name, @c false otherwise
 */
bool SecSeg::hasEmptyName() const
{
	return name.empty();
}

/**
 * @return @c true if the provided address @c sAddress belongs to this section
 *    or segment, @c false otherwise.
 */
bool SecSeg::belong(unsigned long long sAddress) const
{
	return sAddress >= getAddress() && sAddress < getEndAddress();
}

/**
 * @return @c true if this section or segment is less than the provided
 *    section or segment @c sOther, @c false otherwise.
 */
bool SecSeg::operator<(const SecSeg &sOther) const
{
	return getAddress() < sOther.getAddress();
}

} // namespace fileformat
} // namespace retdec
