/**
 * @file src/fileformat/types/resource_table/resource.cpp
 * @brief Class for one resource.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "retdec/crypto/crypto.h"
#include "retdec/utils/conversion.h"
#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/types/resource_table/resource.h"
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
Resource::Resource() : offset(0), size(0), nameId(0), typeId(0), languageId(0), sublanguageId(0),
	nameIdIsValid(false), typeIdIsValid(false), languageIdIsValid(false),
	sublanguageIdIsValid(false), loaded(false)
{

}

/**
 * Destructor
 */
Resource::~Resource()
{

}

/**
 * Get CRC32
 * @return CRC32 of resource content
 */
std::string Resource::getCrc32() const
{
	return crc32;
}

/**
 * Get MD5
 * @return MD5 of resource content
 */
std::string Resource::getMd5() const
{
	return md5;
}

/**
 * Get SHA256
 * @return SHA256 of resource content
 */
std::string Resource::getSha256() const
{
	return sha256;
}

/**
 * Get resource name
 * @return Resource name
 */
std::string Resource::getName() const
{
	return name;
}

/**
 * Get resource type
 * @return Resource type
 */
std::string Resource::getType() const
{
	return type;
}

/**
 * Get resource language
 * @return Resource language
 */
std::string Resource::getLanguage() const
{
	return language;
}

/**
 * Get resource content as reference to string
 * @param sOffset First byte of the resource data to get (0 means first
 *    byte of resource data)
 * @param sSize Number of resource bytes to get. If this parameter is set to
 *    zero, method returns all bytes from @a sOffset until end of resource data.
 * @return Resource content as reference to string
 */
const llvm::StringRef Resource::getBytes(std::size_t sOffset, std::size_t sSize) const
{
	if(sOffset >= bytes.size())
	{
		return StringRef("");
	}

	return StringRef(bytes.data() + sOffset, getRealSizeInRegion(sOffset, sSize, bytes.size()));
}

/**
 * Get resource offset
 * @return Offset of resource in input file
 */
std::size_t Resource::getOffset() const
{
	return offset;
}

/**
 * Get resource size in file
 * @return Size of resource data in file
 */
std::size_t Resource::getSizeInFile() const
{
	return size;
}

/**
 * Get real file size of resource
 * @return Real file size of resource
 */
std::size_t Resource::getLoadedSize() const
{
	return bytes.size();
}

/**
 * Get resource name ID
 * @param rId Into this parameter is stored resource name ID
 * @return @c true if name ID of resource is valid, @c false otherwise
 *
 * If method returns @c false, @a rId is left unchanged
 */
bool Resource::getNameId(std::size_t &rId) const
{
	if(nameIdIsValid)
	{
		rId = nameId;
	}

	return nameIdIsValid;
}

/**
 * Get resource type ID
 * @param rId Into this parameter is stored resource type ID
 * @return @c true if type ID of resource is valid, @c false otherwise
 *
 * If method returns @c false, @a rId is left unchanged
 */
bool Resource::getTypeId(std::size_t &rId) const
{
	if(typeIdIsValid)
	{
		rId = typeId;
	}

	return typeIdIsValid;
}

/**
 * Get resource language ID
 * @param rId Into this parameter is stored resource language ID
 * @return @c true if language ID of resource is valid, @c false otherwise
 *
 * If method returns @c false, @a rId is left unchanged
 */
bool Resource::getLanguageId(std::size_t &rId) const
{
	if(languageIdIsValid)
	{
		rId = languageId;
	}

	return languageIdIsValid;
}

/**
 * Get resource sublanguage ID
 * @param rId Into this parameter is stored resource sublanguage ID
 * @return @c true if sublanguage ID of resource is valid, @c false otherwise
 *
 * If method returns @c false, @a rId is left unchanged
 */
bool Resource::getSublanguageId(std::size_t &rId) const
{
	if(sublanguageIdIsValid)
	{
		rId = sublanguageId;
	}

	return sublanguageIdIsValid;
}

/**
 * Get content of resource as bits
 * @param sResult Read bits in string representation
 * @return @c true if operation went OK, @c false otherwise
 */
bool Resource::getBits(std::string &sResult) const
{
	sResult = bytesToBits(bytes.data(), bytes.size());
	return loaded;
}

/**
 * Get content of resource as bytes
 * @param sResult Read bytes in integer representation
 * @param sOffset First byte of the resource data to be loaded (0 means
 *    first byte of resource data)
 * @param sSize Number of bytes for read. If this parameter is set to zero,
 *    method will read all bytes from @a sOffset until end of resource data.
 * @return @c true if operation went OK, @c false otherwise
 */
bool Resource::getBytes(std::vector<unsigned char> &sResult, std::size_t sOffset, std::size_t sSize) const
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
 * Get content of resource as plain string
 * @param sResult Into this parameter is stored content of resource as plain string
 * @param sOffset First byte of the resource data to be loaded (0 means
 *    first byte of resource data)
 * @param sSize Number of bytes for read. If this parameter is set to zero,
 *    method will read all bytes from @a sOffset until end of resource data.
 * @return @c true if operation went OK, @c false otherwise
 */
bool Resource::getString(std::string &sResult, std::size_t sOffset, std::size_t sSize) const
{
	if(sOffset >= bytes.size())
	{
		return false;
	}

	bytesToString(bytes.data(), bytes.size(), sResult, sOffset, sSize);
	return loaded;
}

/**
 * Get content of resource as bytes
 * @param sResult Read bytes in hexadecimal string representation
 * @return @c true if operation went OK, @c false otherwise
 */
bool Resource::getHexBytes(std::string &sResult) const
{
	bytesToHexString(bytes.data(), bytes.size(), sResult);
	return loaded;
}

/**
 * Set resource name
 * @param rName Resource name
 */
void Resource::setName(std::string rName)
{
	name = rName;
}

/**
 * Set resource type
 * @param rType Resource type
 */
void Resource::setType(std::string rType)
{
	type = rType;
}

/**
 * Set resource language
 * @param rLan Resource language
 */
void Resource::setLanguage(std::string rLan)
{
	language = rLan;
}

/**
 * Set resource offset
 * @param rOffset Offset of resource in input file
 */
void Resource::setOffset(std::size_t rOffset)
{
	offset = rOffset;
}

/**
 * Set resource size in file
 * @param rSize Size of resource in input file
 */
void Resource::setSizeInFile(std::size_t rSize)
{
	size = rSize;
}

/**
 * Set resource name ID
 * @param rId Resource name ID
 */
void Resource::setNameId(std::size_t rId)
{
	nameId = rId;
	nameIdIsValid = true;
}

/**
 * Set resource type ID
 * @param rId Resource type ID
 */
void Resource::setTypeId(std::size_t rId)
{
	typeId = rId;
	typeIdIsValid = true;
}

/**
 * Set resource language ID
 * @param rId Resource language ID
 */
void Resource::setLanguageId(std::size_t rId)
{
	languageId = rId;
	languageIdIsValid = true;
}

/**
 * Set resource sublanguage ID
 * @param rId Resource sublanguage ID
 */
void Resource::setSublanguageId(std::size_t rId)
{
	sublanguageId = rId;
	sublanguageIdIsValid = true;
}

/**
 * Invalidate name ID of resource
 *
 * Instance method @a getNameId() returns @c false after invocation of this method.
 * ID is possible to revalidate by invocation of method @a setNameId().
 */
void Resource::invalidateNameId()
{
	nameIdIsValid = false;
}

/**
 * Invalidate type ID of resource
 *
 * Instance method @a getTypeId() returns @c false after invocation of this method.
 * ID is possible to revalidate by invocation of method @a setTypeId().
 */
void Resource::invalidateTypeId()
{
	typeIdIsValid = false;
}

/**
 * Invalidate language ID of resource
 *
 * Instance method @a getLanguageId() returns @c false after invocation of this method.
 * ID is possible to revalidate by invocation of method @a setLanguageId().
 */
void Resource::invalidateLanguageId()
{
	languageIdIsValid = false;
}

/**
 * Invalidate sublanguage ID of resource
 *
 * Instance method @a getSublanguageId() returns @c false after invocation of this method.
 * ID is possible to revalidate by invocation of method @a setSublanguageId().
 */
void Resource::invalidateSublanguageId()
{
	sublanguageIdIsValid = false;
}

/**
 * Load content of resource from input file
 * @param rOwner Pointer to input file
 *
 * This method must be called before getters of resource content
 */
void Resource::load(const FileFormat *rOwner)
{
	if(!size || !rOwner || offset >= rOwner->getLoadedFileLength())
	{
		bytes = "";
		loaded = rOwner && offset < rOwner->getLoadedFileLength();
		return;
	}

	const auto *origBytes = rOwner->getLoadedBytesData() + offset;
	bytes = StringRef(reinterpret_cast<const char*>(origBytes), std::min(size, rOwner->getLoadedFileLength() - offset));
	loaded = true;

	if (!(rOwner->getLoadFlags() & LoadFlags::NO_VERBOSE_HASHES))
	{
		crc32 = retdec::crypto::getCrc32(origBytes, bytes.size());
		md5 = retdec::crypto::getMd5(origBytes, bytes.size());
		sha256 = retdec::crypto::getSha256(origBytes, bytes.size());
	}
}

/**
 * Check if CRC32 was computed
 * @return @c true if CRC32 was computed, @c false otherwise
 */
bool Resource::hasCrc32() const
{
	return !crc32.empty();
}

/**
 * Check if MD5 was computed
 * @return @c true if MD5 was computed, @c false otherwise
 */
bool Resource::hasMd5() const
{
	return !md5.empty();
}

/**
 * Check if SHA256 was computed
 * @return @c true if SHA256 was computed, @c false otherwise
 */
bool Resource::hasSha256() const
{
	return !sha256.empty();
}

/**
 * @return @c true if resource has empty name string, @c false otherwise
 */
bool Resource::hasEmptyName() const
{
	return name.empty();
}

/**
 * @return @c true if resource has empty type string, @c false otherwise
 */
bool Resource::hasEmptyType() const
{
	return type.empty();
}

/**
 * @return @c true if resource has empty language string, @c false otherwise
 */
bool Resource::hasEmptyLanguage() const
{
	return language.empty();
}

} // namespace fileformat
} // namespace retdec
