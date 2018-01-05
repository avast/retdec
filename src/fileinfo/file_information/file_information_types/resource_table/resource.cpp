/**
 * @file src/fileinfo/file_information/file_information_types/resource_table/resource.cpp
 * @brief Class for one resource.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/resource_table/resource.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
Resource::Resource() : nameId(std::numeric_limits<std::size_t>::max()),
						typeId(std::numeric_limits<std::size_t>::max()),
						languageId(std::numeric_limits<std::size_t>::max()),
						sublanguageId(std::numeric_limits<std::size_t>::max()),
						offset(std::numeric_limits<std::size_t>::max()),
						size(std::numeric_limits<std::size_t>::max())
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
 * Get resource name ID
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Resource name ID
 */
std::string Resource::getNameIdStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(nameId, format);
}

/**
 * Get resource type ID
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Resource type ID
 */
std::string Resource::getTypeIdStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(typeId, format);
}

/**
 * Get resource language ID
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Resource language ID
 */
std::string Resource::getLanguageIdStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(languageId, format);
}

/**
 * Get resource sublanguage ID
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Resource sublanguage ID
 */
std::string Resource::getSublanguageIdStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(sublanguageId, format);
}

/**
 * Get resource offset
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Offset of resource in input file
 */
std::string Resource::getOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(offset, format);
}

/**
 * Get resource size
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Size of resource in input file
 */
std::string Resource::getSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(size, format);
}

/**
 * Set resource CRC32
 * @param rCrc32 CRC32 of resource content
 */
void Resource::setCrc32(std::string rCrc32)
{
	crc32 = rCrc32;
}

/**
 * Set resource MD5
 * @param rMd5 MD5 of resource content
 */
void Resource::setMd5(std::string rMd5)
{
	md5 = rMd5;
}

/**
 * Set resource SHA256
 * @param rSha256 SHA256 of resource content
 */
void Resource::setSha256(std::string rSha256)
{
	sha256 = rSha256;
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
 * Set resource name ID
 * @param rId Resource name ID
 */
void Resource::setNameId(std::size_t rId)
{
	nameId = rId;
}

/**
 * Set resource type ID
 * @param rId Resource type ID
 */
void Resource::setTypeId(std::size_t rId)
{
	typeId = rId;
}

/**
 * Set resource language ID
 * @param rId Resource language ID
 */
void Resource::setLanguageId(std::size_t rId)
{
	languageId = rId;
}

/**
 * Set resource sublanguage ID
 * @param rId Resource sublanguage ID
 */
void Resource::setSublanguageId(std::size_t rId)
{
	sublanguageId = rId;
}

/**
 * Set resource offset in input file
 * @param rOffset Resource offset in input file
 */
void Resource::setOffset(std::size_t rOffset)
{
	offset = rOffset;
}

/**
 * Set resource size in input file
 * @param rSize Resource size in input file
 */
void Resource::setSize(std::size_t rSize)
{
	size = rSize;
}

} // namespace fileinfo
