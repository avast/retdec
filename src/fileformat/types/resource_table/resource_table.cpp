/**
 * @file src/fileformat/types/resource_table/resource_table.cpp
 * @brief Class for resource table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>
#include <iostream>

#include "retdec/crypto/crypto.h"
#include "retdec/utils/conversion.h"
#include "retdec/fileformat/types/resource_table/resource_table.h"
#include "retdec/fileformat/types/resource_table/bitmap_image.h"

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
 * Compute icon perceptual hashes
 * @param icon Icon to compute the hash of
 * @return Perceptual hash as AvgHash
 */
std::string ResourceTable::computePerceptualAvgHash(const ResourceIcon &icon) const
{
	std::size_t trashHold = 128;
	auto img = BitmapImage();

	if (!img.parseDibFormat(icon))
	{
		return "";
	}

	if (!img.reduce8x8())
	{
		return "";
	}

	img.greyScale();

	std::uint64_t bytes = 0;
	std::size_t position = 63;

	for (std::size_t i = 0; i < 8; i++)
	{
		auto &row = img.getImage()[i];

		for (std::uint8_t j = 0; j < 8; j++)
		{
			auto &pixel = row[j];
			uint64_t value = (pixel.r >= trashHold) ? 0x00 : 0x01;

			bytes |= (value << position);
			position--;
		}
	}

	return retdec::utils::toHex(bytes, false, 16);
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
		sum += r->getSizeInFile();
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
		sum += r->getLoadedSize();
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
	return (rIndex < getNumberOfResources()) ? table[rIndex].get() : nullptr;
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
		if(r->getName() == rName)
		{
			return r.get();
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
		if(r->getNameId(tmpId) && tmpId == rId)
		{
			return r.get();
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
		if(r->getType() == rType)
		{
			return r.get();
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
		if(r->getTypeId(tmpId) && tmpId == rId)
		{
			return r.get();
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
		if(r->getLanguage() == rLan)
		{
			return r.get();
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
		if(r->getLanguageId(tmpId) && tmpId == rId)
		{
			return r.get();
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
 * Get icon perceptual hash as AvgHash
 * @return Icon perceptual hash as AvgHash
 */
const std::string& ResourceTable::getResourceIconPerceptualAvgHash() const
{
	return iconPerceptualAvgHash;
}

/**
 * Get prior icon group
 * @return Prior icon group
 */
const ResourceIconGroup* ResourceTable::getPriorResourceIconGroup() const
{
	for(const auto group : iconGroups)
	{
		if(group->getIconGroupID() == 0)
		{
			return group;
		}
	}

	return nullptr;
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
 */
void ResourceTable::computeIconHashes()
{
	std::vector<std::uint8_t> iconHashBytes;

	auto priorGroup = getPriorResourceIconGroup();
	if(!priorGroup)
	{
		return;
	}

	auto priorIcon = priorGroup->getPriorIcon();
	if(!priorIcon)
	{
		return;
	}

	if (!priorIcon->getBytes(iconHashBytes))
	{
		return;
	}

	iconHashCrc32 = retdec::crypto::getCrc32(iconHashBytes.data(), iconHashBytes.size());
	iconHashMd5 = retdec::crypto::getMd5(iconHashBytes.data(), iconHashBytes.size());
	iconHashSha256 = retdec::crypto::getSha256(iconHashBytes.data(), iconHashBytes.size());
	iconPerceptualAvgHash = computePerceptualAvgHash(*priorIcon);
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
void ResourceTable::addResource(std::unique_ptr<Resource>&& newResource)
{
	table.push_back(std::move(newResource));
}

/**
 * Add icon
 * @param icon Icon which will be added
 */
void ResourceTable::addResourceIcon(ResourceIcon *icon)
{
	icons.push_back(icon);
}

/**
 * Add icon group
 * @param iGroup Icon group which will be added
 */
void ResourceTable::addResourceIconGroup(ResourceIconGroup *iGroup)
{
	iconGroups.push_back(iGroup);
}

/**
 * Link resource icon group with referenced icons and set icon properties
 */
void ResourceTable::linkResourceIconGroups()
{
	for(auto iconGroup : iconGroups)
	{
		std::size_t numberOfEntries;
		if (!iconGroup->getNumberOfEntries(numberOfEntries))
		{
			continue;
		}

		for(size_t eIndex = 0; eIndex < numberOfEntries; eIndex++)
		{
			std::size_t entryNameID;
			if(!iconGroup->getEntryNameID(eIndex, entryNameID))
			{
				continue;
			}

			for(auto icon : icons)
			{
				size_t iconNameID, iconSize;
				unsigned short width, height;
				uint16_t planes, bitCount;
				uint8_t colorCount;
				if(!icon->getNameId(iconNameID) || iconNameID != entryNameID
					|| !iconGroup->getEntryWidth(eIndex, width) || !iconGroup->getEntryHeight(eIndex, height)
					|| !iconGroup->getEntryIconSize(eIndex, iconSize) || !iconGroup->getEntryColorCount(eIndex, colorCount)
					|| !iconGroup->getEntryPlanes(eIndex, planes) || !iconGroup->getEntryBitCount(eIndex, bitCount))
				{
					continue;
				}

				icon->setWidth(width);
				icon->setHeight(height);
				icon->setIconSize(iconSize);
				icon->setColorCount(colorCount);
				icon->setPlanes(planes);
				icon->setBitCount(bitCount);
				icon->setIconGroup(iconGroup->getIconGroupID());
				icon->setLoadedProperties();
				
				if(colorCount == 1 << (bitCount * planes))
				{
					icon->setValidColorCount();
				}

				iconGroup->addIcon(icon);
			}
		}
	}
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
			auto sName = (res->hasEmptyName() && res->getNameId(aux)) ? numToStr(aux, std::dec) : res->getName();
			auto sType = (res->hasEmptyType() && res->getTypeId(aux)) ? numToStr(aux, std::dec) : res->getType();
			auto sLang = res->getLanguage();
			if(sType.empty())
			{
				sType = "-";
			}
			if(sLang.empty())
			{
				if(res->getLanguageId(aux))
				{
					sLang = numToStr(aux, std::dec);
					if(res->getSublanguageId(aux))
					{
						sLang += ":" + numToStr(aux, std::dec);
					}
				}
				else
				{
					sLang = "-";
				}
			}
			const auto md5 = res->hasMd5() ? res->getMd5() : "-";
			ret << "; " << sName << " (type: " << sType << ", language: " << sLang << ", offset: " <<
				numToStr(res->getOffset(), std::hex) << ", declSize: " << numToStr(res->getSizeInFile(), std::hex) <<
				", loadedSize: " << numToStr(res->getLoadedSize(), std::hex) << ", md5: " << md5 << ")\n";
		}
	}

	dumpTable = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
