/**
 * @file src/fileinfo/file_information/file_information_types/resource_table/resource_table.cpp
 * @brief Class for resource table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/resource_table/resource_table.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace retdec {
namespace fileinfo {

/**
 * Get number of resources in table
 * @return Number of resources in table
 */
std::size_t ResourceTable::getNumberOfResources() const
{
	return table ? table->getNumberOfResources() : 0;
}

/**
 * Get number of supported languages
 * @return Number of supported languages
 */
std::size_t ResourceTable::getNumberOfLanguages() const
{
	return table ? table->getNumberOfLanguages() : 0;
}

/**
 * Get number of strings
 * @return Number of strings
 */
std::size_t ResourceTable::getNumberOfStrings() const
{
	return table ? table->getNumberOfStrings() : 0;
}

/**
 * Get CRC32 of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return CRC32 of selected resource
 */
std::string ResourceTable::getResourceCrc32(std::size_t index) const
{
	const auto *record = table ? table->getResource(index) : nullptr;
	return record ? record->getCrc32() : "";
}

/**
 * Get MD5 of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return MD5 of selected resource
 */
std::string ResourceTable::getResourceMd5(std::size_t index) const
{
	const auto *record = table ? table->getResource(index) : nullptr;
	return record ? record->getMd5() : "";
}

/**
 * Get SHA256 of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return SHA256 of selected resource
 */
std::string ResourceTable::getResourceSha256(std::size_t index) const
{
	const auto *record = table ? table->getResource(index) : nullptr;
	return record ? record->getSha256() : "";
}

/**
 * Get iconhash as CRC32
 * @return Iconhash as CRC32
 */
std::string ResourceTable::getResourceIconhashCrc32() const
{
	return table ? table->getResourceIconhashCrc32() : "";
}

/**
 * Get iconhash as MD5
 * @return Iconhash as MD5
 */
std::string ResourceTable::getResourceIconhashMd5() const
{
	return table ? table->getResourceIconhashMd5() : "";
}

/**
 * Get iconhash as SHA256
 * @return Iconhash as SHA256
 */
std::string ResourceTable::getResourceIconhashSha256() const
{
	return table ? table->getResourceIconhashSha256() : "";
}

/**
 * Get icon perceptual hash as AvgHash
 * @return Icon perceptual hash as AvgHash
 */
std::string ResourceTable::getResourceIconPerceptualAvgHash() const
{
	return table ? table->getResourceIconPerceptualAvgHash() : "";
}

/**
 * Get resource
 * @param position Index of selected resource from table (indexed from 0)
 * @return Resource
 */
const retdec::fileformat::Resource* ResourceTable::getResource(std::size_t position) const
{
	return table ? table->getResource(position) : nullptr;
}

/**
 * Get name of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return Name of selected resource
 */
std::string ResourceTable::getResourceName(std::size_t index) const
{
	const auto *record = table ? table->getResource(index) : nullptr;
	return record ? record->getName() : "";
}

/**
 * Get type of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return Type of selected resource
 */
std::string ResourceTable::getResourceType(std::size_t index) const
{
	const auto *record = table ? table->getResource(index) : nullptr;
	return record ? record->getType() : "";
}

/**
 * Get language of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return Language of selected resource
 */
std::string ResourceTable::getResourceLanguage(std::size_t index) const
{
	const auto *record = table ? table->getResource(index) : nullptr;
	return record ? record->getLanguage() : "";
}

/**
 * Get LCID of supported language
 * @param index Index of selected supported language (indexed from 0)
 * @return LCID of supported language
 */
std::string ResourceTable::getLanguageLcid(std::size_t index) const
{
	const auto *record = table ? table->getLanguage(index) : nullptr;
	return record ? record->first : "";
}

/**
 * Get code page of supported language
 * @param index Index of selected code page (indexed from 0)
 * @return Code page of supported language
 */
std::string ResourceTable::getLanguageCodePage(std::size_t index) const
{
	const auto *record = table ? table->getLanguage(index) : nullptr;
	return record ? record->second : "";
}

/**
 * Get name of selected string
 * @param index Index of selected string (indexed from 0)
 * @return Name of string
 */
std::string ResourceTable::getStringName(std::size_t index) const
{
	const auto *record = table ? table->getString(index) : nullptr;
	return record ? record->first : "";
}

/**
 * Get value of selected string
 * @param index Index of selected string (indexed from 0)
 * @return Value of string
 */
std::string ResourceTable::getStringValue(std::size_t index) const
{
	const auto *record = table ? table->getString(index) : nullptr;
	return record ? record->second : "";
}

/**
 * Get name ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Name ID of selected resource
 */
std::string ResourceTable::getResourceNameIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	std::size_t id;
	const auto *record = table ? table->getResource(index) : nullptr;

	if (!record || !record->getNameId(id))
	{
		return "";
	}

	return getNumberAsString(id, format);
}

/**
 * Get type ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Type ID of selected resource
 */
std::string ResourceTable::getResourceTypeIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	std::size_t type;
	const auto *record = table ? table->getResource(index) : nullptr;

	if (!record || !record->getTypeId(type))
	{
		return "";
	}

	return getNumberAsString(type, format);
}

/**
 * Get language ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Language ID of selected resource
 */
std::string ResourceTable::getResourceLanguageIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	std::size_t language;
	const auto *record = table ? table->getResource(index) : nullptr;

	if (!record || !record->getLanguageId(language))
	{
		return "";
	}

	return getNumberAsString(language, format);
}

/**
 * Get sublanguage ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Sublanguage ID of selected resource
 */
std::string ResourceTable::getResourceSublanguageIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	std::size_t sublanguage;
	const auto *record = table ? table->getResource(index) : nullptr;

	if (!record || !record->getSublanguageId(sublanguage))
	{
		return "";
	}

	return getNumberAsString(sublanguage, format);
}

/**
 * Get offset of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Offset of selected resource
 */
std::string ResourceTable::getResourceOffsetStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	const auto *record = table ? table->getResource(index) : nullptr;
	return record && record->isValidOffset() ? getNumberAsString(record->getOffset(), format) : "";
}

/**
 * Get size of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Size of selected resource
 */
std::string ResourceTable::getResourceSizeStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	const auto *record = table ? table->getResource(index) : nullptr;
	return record ? getNumberAsString(record->getSizeInFile(), format) : "";
}

/**
 * Set resource table data
 * @param resourceTable Instance of class with original information about resource table
 */
void ResourceTable::setTable(const retdec::fileformat::ResourceTable *resourceTable)
{
	table = resourceTable;
}

/**
 * Find out if there are any resources
 * @return @c true if there are some resources, @c false otherwise
 */
bool ResourceTable::hasRecords() const
{
	return table ? table->hasResources() : false;
}

} // namespace fileinfo
} // namespace retdec
