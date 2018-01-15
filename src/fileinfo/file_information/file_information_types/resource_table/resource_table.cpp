/**
 * @file src/fileinfo/file_information/file_information_types/resource_table/resource_table.cpp
 * @brief Class for resource table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/resource_table/resource_table.h"

namespace fileinfo {

/**
 * Constructor
 */
ResourceTable::ResourceTable()
{

}

/**
 * Destructor
 */
ResourceTable::~ResourceTable()
{

}

/**
 * Get number of resources in table
 * @return Number of resources in table
 */
std::size_t ResourceTable::getNumberOfResources() const
{
	return table.size();
}

/**
 * Get CRC32 of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return CRC32 of selected resource
 */
std::string ResourceTable::getResourceCrc32(std::size_t index) const
{
	return table[index].getCrc32();
}

/**
 * Get MD5 of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return MD5 of selected resource
 */
std::string ResourceTable::getResourceMd5(std::size_t index) const
{
	return table[index].getMd5();
}

/**
 * Get SHA256 of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return SHA256 of selected resource
 */
std::string ResourceTable::getResourceSha256(std::size_t index) const
{
	return table[index].getSha256();
}

/**
 * Get name of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return Name of selected resource
 */
std::string ResourceTable::getResourceName(std::size_t index) const
{
	return table[index].getName();
}

/**
 * Get type of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return Type of selected resource
 */
std::string ResourceTable::getResourceType(std::size_t index) const
{
	return table[index].getType();
}

/**
 * Get language of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @return Language of selected resource
 */
std::string ResourceTable::getResourceLanguage(std::size_t index) const
{
	return table[index].getLanguage();
}

/**
 * Get name ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Name ID of selected resource
 */
std::string ResourceTable::getResourceNameIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return table[index].getNameIdStr(format);
}

/**
 * Get type ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Type ID of selected resource
 */
std::string ResourceTable::getResourceTypeIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return table[index].getTypeIdStr(format);
}

/**
 * Get language ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Language ID of selected resource
 */
std::string ResourceTable::getResourceLanguageIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return table[index].getLanguageIdStr(format);
}

/**
 * Get sublanguage ID of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Sublanguage ID of selected resource
 */
std::string ResourceTable::getResourceSublanguageIdStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return table[index].getSublanguageIdStr(format);
}

/**
 * Get offset of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Offset of selected resource
 */
std::string ResourceTable::getResourceOffsetStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return table[index].getOffsetStr(format);
}

/**
 * Get size of selected resource
 * @param index Index of selected resource (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Size of selected resource
 */
std::string ResourceTable::getResourceSizeStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	return table[index].getSizeStr(format);
}

/**
 * Add resource to the table
 * @param resource Resource to add
 */
void ResourceTable::addResource(Resource &resource)
{
	table.push_back(resource);
}

/**
 * Delete all resources from table
 */
void ResourceTable::clearResources()
{
	table.clear();
}

} // namespace fileinfo
