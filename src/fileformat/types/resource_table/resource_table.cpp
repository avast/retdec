/**
 * @file src/fileformat/types/resource_table/resource_table.cpp
 * @brief Class for resource table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "retdec/crypto/crypto.h"
#include "retdec/utils/conversion.h"
#include "retdec/fileformat/types/resource_table/resource_table.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

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
 * Get number of stored resources
 * @return Number of stored resources
 */
std::size_t ResourceTable::getNumberOfResources() const
{
	return table.size();
}

/**
 * Get total declared size of resources
 * @return Total declared size of resources
 */
std::size_t ResourceTable::getSizeInFile() const
{
	std::size_t sum = 0;

	for(const auto &r : table)
	{
		sum += r.getSizeInFile();
	}

	return sum;
}

/**
 * Get total loaded size of resources
 * @return Total loaded size of resources
 */
std::size_t ResourceTable::getLoadedSize() const
{
	std::size_t sum = 0;

	for(const auto &r : table)
	{
		sum += r.getLoadedSize();
	}

	return sum;
}

/**
 * Get selected resource
 * @param rIndex Index of selected resource (indexed from 0)
 * @return Pointer to selected resource or @c nullptr if resource index is invalid
 */
const Resource* ResourceTable::getResource(std::size_t rIndex) const
{
	return (rIndex < getNumberOfResources()) ? &table[rIndex] : nullptr;
}

/**
 * Get resource by name
 * @param rName Name of the resource to get
 * @return Pointer to resource with the specified name or @c nullptr if such resource not found
 */
const Resource* ResourceTable::getResourceWithName(const std::string &rName) const
{
	for(const auto &r : table)
	{
		if(r.getName() == rName)
		{
			return &r;
		}
	}

	return nullptr;
}

/**
 * Get resource by name ID
 * @param rId Name ID of the resource to get
 * @return Pointer to resource with specified name ID or @c nullptr if such resource not found
 */
const Resource* ResourceTable::getResourceWithName(std::size_t rId) const
{
	std::size_t tmpId;

	for(const auto &r : table)
	{
		if(r.getNameId(tmpId) && tmpId == rId)
		{
			return &r;
		}
	}

	return nullptr;
}

/**
 * Get resource by type
 * @param rType Type of the resource to get
 * @return Pointer to resource with the specified type or @c nullptr if such resource not found
 */
const Resource* ResourceTable::getResourceWithType(const std::string &rType) const
{
	for(const auto &r : table)
	{
		if(r.getType() == rType)
		{
			return &r;
		}
	}

	return nullptr;
}

/**
 * Get resource by type ID
 * @param rId Type ID of the resource to get
 * @return Pointer to resource with specified type ID or @c nullptr if such resource not found
 */
const Resource* ResourceTable::getResourceWithType(std::size_t rId) const
{
	std::size_t tmpId;

	for(const auto &r : table)
	{
		if(r.getTypeId(tmpId) && tmpId == rId)
		{
			return &r;
		}
	}

	return nullptr;
}

/**
 * Get resource by language
 * @param rLan Language of the resource to get
 * @return Pointer to resource with the specified language or @c nullptr if such resource not found
 */
const Resource* ResourceTable::getResourceWithLanguage(const std::string &rLan) const
{
	for(const auto &r : table)
	{
		if(r.getLanguage() == rLan)
		{
			return &r;
		}
	}

	return nullptr;
}

/**
 * Get resource by language ID
 * @param rId Language ID of the resource to get
 * @return Pointer to resource with specified language ID or @c nullptr if such resource not found
 */
const Resource* ResourceTable::getResourceWithLanguage(std::size_t rId) const
{
	std::size_t tmpId;

	for(const auto &r : table)
	{
		if(r.getLanguageId(tmpId) && tmpId == rId)
		{
			return &r;
		}
	}

	return nullptr;
}

/**
 * Get iconhash as CRC32
 * @return Iconhash as CRC32
 */
const std::string& ResourceTable::getResourceIconhashCrc32() const
{
	return iconHashCrc32;
}

/**
 * Get iconhash as MD5
 * @return Iconhash as MD5
 */
const std::string& ResourceTable::getResourceIconhashMd5() const
{
	return iconHashMd5;
}

/**
 * Get iconhash as SHA256
 * @return Iconhash as SHA256
 */
const std::string& ResourceTable::getResourceIconhashSha256() const
{
	return iconHashSha256;
}

/**
 * Get begin iterator
 * @return Begin iterator
 */
ResourceTable::resourcesIterator ResourceTable::begin() const
{
	return table.begin();
}

/**
 * Get end iterator
 * @return End iterator
 */
ResourceTable::resourcesIterator ResourceTable::end() const
{
	return table.end();
}

/**
 * Compute icon hashes - CRC32, MD5, SHA256.
 * @param rOwner Pointer to input file
 */
void ResourceTable::computeIconHashes(const FileFormat *rOwner)
{
	std::vector<Resource *> iconsWithName;
	std::vector<Resource *> iconsWithId;
	std::vector<std::uint8_t> iconHashBytes;

	for(auto& resource : table)
	{
		if(!resource.isUsedForIconhash() || resource.getType() != "Icon")
		{
			continue;
		}

		if(resource.hasValidName())
		{
			iconsWithName.push_back(&resource);
		}
		else if (resource.hasValidId())
		{
			iconsWithId.push_back(&resource);
		}
	}

	std::sort(iconsWithName.begin(), iconsWithName.end(),
		[](const Resource *r1, const Resource *r2) -> bool
		{
			return r1->getName() < r2->getName();
		}
	);

	std::sort(iconsWithId.begin(), iconsWithId.end(),
		[](const Resource *r1, const Resource *r2) -> bool
		{
			std::size_t id1, id2;
			r1->getNameId(id1);
			r2->getNameId(id2);

			return id1 < id2;
		}
	);

	for(auto icon : iconsWithName)
	{
		if(!icon->isLoaded())
		{
			icon->load(rOwner);
		}

		icon->getBytesPushBack(iconHashBytes);
	}

	for(auto icon : iconsWithId)
	{
		if(!icon->isLoaded())
		{
			icon->load(rOwner);
		}

		icon->getBytesPushBack(iconHashBytes);
	}

	iconHashCrc32 = retdec::crypto::getCrc32(iconHashBytes.data(), iconHashBytes.size());
	iconHashMd5 = retdec::crypto::getMd5(iconHashBytes.data(), iconHashBytes.size());
	iconHashSha256 = retdec::crypto::getSha256(iconHashBytes.data(), iconHashBytes.size());
}

/**
 * Delete all records from table
 */
void ResourceTable::clear()
{
	table.clear();
}

/**
 * Add resource
 * @param newResource Resource which will be added
 */
void ResourceTable::addResource(Resource &newResource)
{
	table.push_back(newResource);
}

/**
 * Find out if there are any resources
 * @return @c true if there are some resources, @c false otherwise
 */
bool ResourceTable::hasResources() const
{
	return !table.empty();
}

/**
 * Check if resource with name @a rName exists
 * @param rName Name of resource
 * @return @c true if has resource with name @a rName, @c false otherwise
 */
bool ResourceTable::hasResourceWithName(const std::string &rName) const
{
	return getResourceWithName(rName);
}

/**
 * Check if resource with name ID @a rId exists
 * @param rId Name ID of resource
 * @return @c true if has resource with name ID @a rId, @c false otherwise
 */
bool ResourceTable::hasResourceWithName(std::size_t rId) const
{
	return getResourceWithName(rId);
}

/**
 * Check if resource with type @a rType exists
 * @param rType Type of resource
 * @return @c true if has resource with type @a rType, @c false otherwise
 */
bool ResourceTable::hasResourceWithType(const std::string &rType) const
{
	return getResourceWithType(rType);
}

/**
 * Check if resource with type ID @a rId exists
 * @param rId Type ID of resource
 * @return @c true if has resource with type ID @a rId, @c false otherwise
 */
bool ResourceTable::hasResourceWithType(std::size_t rId) const
{
	return getResourceWithType(rId);
}

/**
 * Check if resource with language @a rLan exists
 * @param rLan Language of resource
 * @return @c true if has resource with language @a rLan, @c false otherwise
 */
bool ResourceTable::hasResourceWithLanguage(const std::string &rLan) const
{
	return getResourceWithLanguage(rLan);
}

/**
 * Check if resource with language ID @a rId exists
 * @param rId Language ID of resource
 * @return @c true if has resource with language ID @a rId, @c false otherwise
 */
bool ResourceTable::hasResourceWithLanguage(std::size_t rId) const
{
	return getResourceWithLanguage(rId);
}

/**
 * Dump information about all resources in table
 * @param dumpTable Into this parameter is stored dump of table in an LLVM style
 */
void ResourceTable::dump(std::string &dumpTable) const
{
	std::stringstream ret;

	ret << "; ------------ Resources ------------\n";
	ret << "; Number of resources: " << getNumberOfResources() << "\n";
	ret << "; Declared size of resources: " << std::hex << getSizeInFile() << "\n";
	ret << "; Loaded size of resources: " << getLoadedSize() << std::dec << "\n";

	if(hasResources())
	{
		std::size_t aux;
		ret << ";\n";

		for(const auto &res : table)
		{
			auto sName = (res.hasEmptyName() && res.getNameId(aux)) ? numToStr(aux, std::dec) : res.getName();
			auto sType = (res.hasEmptyType() && res.getTypeId(aux)) ? numToStr(aux, std::dec) : res.getType();
			auto sLang = res.getLanguage();
			if(sType.empty())
			{
				sType = "-";
			}
			if(sLang.empty())
			{
				if(res.getLanguageId(aux))
				{
					sLang = numToStr(aux, std::dec);
					if(res.getSublanguageId(aux))
					{
						sLang += ":" + numToStr(aux, std::dec);
					}
				}
				else
				{
					sLang = "-";
				}
			}
			const auto md5 = res.hasMd5() ? res.getMd5() : "-";
			ret << "; " << sName << " (type: " << sType << ", language: " << sLang << ", offset: " <<
				numToStr(res.getOffset(), std::hex) << ", declSize: " << numToStr(res.getSizeInFile(), std::hex) <<
				", loadedSize: " << numToStr(res.getLoadedSize(), std::hex) << ", md5: " << md5 << ")\n";
		}
	}

	dumpTable = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
