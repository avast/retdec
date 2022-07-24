/**
 * @file src/fileformat/types/resource_table/resource_table.cpp
 * @brief Class for resource table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "retdec/utils/conversion.h"
#include "retdec/utils/dynamic_buffer.h"
#include "retdec/utils/string.h"
#include "retdec/utils/alignment.h"
#include "retdec/fileformat/utils/crypto.h"
#include "retdec/fileformat/utils/other.h"
#include "retdec/fileformat/types/resource_table/resource_table.h"
#include "retdec/fileformat/types/resource_table/bitmap_image.h"

using namespace retdec::utils;

namespace {

constexpr std::size_t VI_KEY_SIZE = 32;               ///< unicode "VS_VERSION_INFO"
constexpr std::size_t VFI_KEY_SIZE = 24;              ///< unicode "VarFileInfo"
constexpr std::size_t SFI_KEY_SIZE = 30;              ///< unicode "StringFileInfo"
constexpr std::size_t VAR_KEY_SIZE = 24;              ///< unicode "Translation"
constexpr std::size_t STRTAB_KEY_SIZE = 18;           ///< 8 unicode hex digits

constexpr std::uint32_t FFI_SIGNATURE = 0xFEEF04BD;   ///< fixed file info signature

enum class VersionInfoType {BINARY = 0, STRING = 1};

struct FixedFileInfo
{
	std::uint32_t signature;                   ///< signature FFI_SIGNATURE
	std::uint16_t strucVersionMaj;             ///< binary major version number
	std::uint16_t strucVersionMin;             ///< binary minor version number
	std::uint32_t fileVersionMaj;              ///< file major version number
	std::uint32_t fileVersionMin;              ///< file minor version number
	std::uint64_t productVersion;              ///< product version number
	std::uint32_t fileFlagsMask;               ///< validity mask of fileFalgs member
	std::uint32_t fileFlags;                   ///< file flags
	std::uint32_t fileOS;                      ///< target operating system
	std::uint32_t fileType;                    ///< type of file
	std::uint32_t fileSubtype;                 ///< subtype of file
	std::uint64_t timestamp;                   ///< timestamp

	static std::size_t structSize()
	{
		return
			sizeof(signature) + sizeof(strucVersionMaj) + sizeof(strucVersionMin) + sizeof(fileVersionMaj) +
			sizeof(fileVersionMin) + sizeof(productVersion) + sizeof(fileFlagsMask) + sizeof(fileFlags) +
			sizeof(fileOS) + sizeof(fileType) + sizeof(fileSubtype) + sizeof(timestamp);
	}
};

struct VersionInfoHeader
{
	std::uint16_t length;                       ///< length of whole structure
	std::uint16_t valueLength;                  ///< length of following structure
	std::uint16_t type;                         ///< type of data

	static std::size_t structSize()
	{
		return sizeof(length) + sizeof(valueLength) + sizeof(type);
	}
};

} // anonymous namespace

namespace retdec {
namespace fileformat {

// Icon priority from YARA
static const std::vector<IconPriorityEntry> iconPriority_YARA =
{
	{32, 32},
	{24, 32},
	{48, 32},
	{32, 8},
	{16, 32},
	{64, 32},
	{24, 8},
	{48, 8},
	{16, 8},
	{64, 8},
	{96, 32},
	{96, 8},
	{128, 32},
	{128, 8},
	{256, 32},
	{256, 8}
};

/**
 * Compute icon perceptual hashes
 * @param icon Icon to compute the hash of
 * @return Perceptual hash as AvgHash
 */
std::string ResourceTable::computePerceptualAvgHash(const ResourceIcon &icon) const
{
	std::size_t trashHold = 128;
	auto img = BitmapImage();

	if (!img.parseDibFormat(icon) && !img.parsePngFormat(icon))
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

	return retdec::utils::intToHexString(bytes, false, 16);
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
 * Get number of supported languages
 * @return Number of supported languages
 */
std::size_t ResourceTable::getNumberOfLanguages() const
{
	return languages.size();
}

/**
 * Get number of strings
 * @return Number of strings
 */
std::size_t ResourceTable::getNumberOfStrings() const
{
	return strings.size();
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
 * Get selected language
 * @param rIndex Index of selected language (indexed from 0)
 * @return Pointer to selected language or @c nullptr if language index is invalid
 */
const std::pair<std::string, std::string>* ResourceTable::getLanguage(std::size_t rIndex) const
{
	return (rIndex < getNumberOfLanguages()) ? &languages[rIndex] : nullptr;
}

/**
 * Get selected string
 * @param rIndex Index of selected string (indexed from 0)
 * @return Pointer to selected string or @c nullptr if string index is invalid
 */
const std::pair<std::string, std::string>* ResourceTable::getString(std::size_t rIndex) const
{
	return (rIndex < getNumberOfStrings()) ? &strings[rIndex] : nullptr;
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
 * Get the icon that will be used for calculation of the icon hash.
 * This algorithm is supposed to be YARA-compatible
 * @return Prior icon
 */
const ResourceIcon* ResourceTable::getIconForIconHash() const
{
	ResourceIconGroup * iconGroup = nullptr;
	ResourceIcon * theBestIcon = nullptr;
	std::size_t number_icon_ordinals = 0;
	std::size_t best_icon_priority = 0xFF;

	//
	// Step 1: Get the suitable icon group. YARA takes the first icon group
	// YARA: Done in module "pe.c", function "pe_collect_icon_ordinals()"
	//

	if(iconGroups.size())
	{
		iconGroup = iconGroups[0];
		iconGroup->getNumberOfEntries(number_icon_ordinals);
	}

	//
	// Step 2: Parse all icons in the PE and retrieve the
	// YARA: Done in module "pe.c", function "pe_collect_icon_data()"
	//

	if(iconGroup && number_icon_ordinals)
	{
		for(ResourceIcon * icon : icons)
		{
			std::uint32_t icon_data_offset = icon->getOffset();
			std::uint32_t icon_data_size = icon->getSizeInFile();

			// Skip icons with zero offset or zero size
			if(icon_data_offset == 0 || icon_data_size == 0 /* || icon_data_offset > pe->data_size */)
				continue;

			// Parse all icons in the group
			for(std::size_t i = 0; i < number_icon_ordinals; i++)
			{
				std::size_t nameIdInGroup = 0;
				std::size_t nameIdOfIcon = 0;
				std::uint16_t iconWidth = 0;
				std::uint16_t iconHeight = 0;
				std::uint16_t iconBitCount = 0;

				// Skip icons that are of different ID
				iconGroup->getEntryNameID(i, nameIdInGroup);
				icon->getNameId(nameIdOfIcon);
				if(nameIdOfIcon != nameIdInGroup /* || fits_in_pe() */)
					continue;

				// Retrieve size and bit count
				iconGroup->getEntryWidth(i, iconWidth);
				iconGroup->getEntryHeight(i, iconHeight);
				iconGroup->getEntryBitCount(i, iconBitCount);

				// YARA ignores any icons that have width != height
				if(iconWidth == iconHeight)
				{
					for(size_t j = 0; j < iconPriority_YARA.size() && j < best_icon_priority; j++)
					{
						if(iconWidth == iconPriority_YARA[j].iconWidth && iconBitCount == iconPriority_YARA[j].iconBitCount)
						{
							best_icon_priority = j;
							theBestIcon = icon;
							break;
						}
					}
				}

				// Set the current icon as the best one
				if(!theBestIcon && icons.size())
				{
					best_icon_priority = iconPriority_YARA.size();
					theBestIcon = icon;
				}
			}
		}
	}

	// Return whatever best icon we found
	return theBestIcon;
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

	auto priorIcon = getIconForIconHash();
	if(!priorIcon)
	{
		return;
	}

	if (!priorIcon->getBytes(iconHashBytes))
	{
		return;
	}

	iconHashCrc32 = getCrc32(iconHashBytes.data(), iconHashBytes.size());
	iconHashMd5 = getMd5(iconHashBytes.data(), iconHashBytes.size());
	iconHashSha256 = getSha256(iconHashBytes.data(), iconHashBytes.size());
	iconPerceptualAvgHash = computePerceptualAvgHash(*priorIcon);
}

/**
 * Parse all version information resources
 */
void ResourceTable::parseVersionInfoResources()
{
	std::vector<std::uint8_t> bytes;

	for (auto ver : resourceVersions)
	{
		if (!ver->getBytes(bytes))
		{
			continue;
		}
		parseVersionInfo(bytes);
	}
}

/**
 * Parse version information
 * @param bytes Resource bytes
 * @return @c true if parsing was successful, @c false otherwise
 */
bool ResourceTable::parseVersionInfo(const std::vector<std::uint8_t> &bytes)
{
	VersionInfoHeader vih;
	if (bytes.size() < vih.structSize())
	{
		return false;
	}

	std::size_t offset = 0;

	DynamicBuffer structContent(bytes, retdec::utils::Endianness::LITTLE);
	vih.length = structContent.read<std::uint16_t>(offset); offset += sizeof(vih.length);
	vih.valueLength = structContent.read<std::uint16_t>(offset); offset += sizeof(vih.valueLength);
	vih.type = structContent.read<std::uint16_t>(offset); offset += sizeof(vih.type);

	std::string key = retdec::utils::unicodeToAscii(&bytes.data()[offset], bytes.size() - offset);
	if (key != "VS_VERSION_INFO")
	{
		return false;
	}

	offset += VI_KEY_SIZE;
	offset = retdec::utils::alignUp(offset, sizeof(std::uint32_t));

	FixedFileInfo ffi;
	if (vih.valueLength == ffi.structSize())
	{
		if (bytes.size() < offset + ffi.structSize())
		{
			return false;
		}

		ffi.signature = structContent.read<std::uint32_t>(offset); offset += sizeof(ffi.signature);
		ffi.strucVersionMin = structContent.read<std::uint16_t>(offset); offset += sizeof(ffi.strucVersionMin);
		ffi.strucVersionMaj = structContent.read<std::uint16_t>(offset); offset += sizeof(ffi.strucVersionMaj);
		std::uint32_t t1 = structContent.read<std::uint32_t>(offset);
		ffi.fileVersionMaj = t1 >> 16; offset += sizeof(ffi.fileVersionMaj);
		ffi.fileVersionMin = t1 & 0xFFFF; offset += sizeof(ffi.fileVersionMin);
		std::uint64_t t2 = structContent.read<std::uint64_t>(offset);
		ffi.productVersion = t2 >> 16; offset += sizeof(ffi.productVersion);
		ffi.fileFlagsMask = structContent.read<std::uint32_t>(offset); offset += sizeof(ffi.fileFlagsMask);
		ffi.fileFlags = structContent.read<std::uint32_t>(offset); offset += sizeof(ffi.fileFlags);
		ffi.fileOS = structContent.read<std::uint32_t>(offset); offset += sizeof(ffi.fileOS);
		ffi.fileType = structContent.read<std::uint32_t>(offset); offset += sizeof(ffi.fileType);
		ffi.fileSubtype = structContent.read<std::uint32_t>(offset); offset += sizeof(ffi.fileSubtype);
		ffi.timestamp = structContent.read<std::uint64_t>(offset); offset += sizeof(ffi.timestamp);

		if (ffi.signature != FFI_SIGNATURE)
		{
			return false;
		}
	}

	else if (vih.valueLength != 0)
	{
		return false;
	}

	offset = retdec::utils::alignUp(offset, sizeof(std::uint32_t));
	while (offset < vih.length)
	{
		if (!parseVersionInfoChild(bytes, offset))
		{
			return false;
		}
	}

	return true;
}

/**
 * Parse Version Info child
 * @param bytes Resource bytes
 * @param offset Offset to Version Info Child structure
 * @return @c true if parsing was successful, @c false otherwise
 */
bool ResourceTable::parseVersionInfoChild(const std::vector<std::uint8_t> &bytes, std::size_t &offset)
{
	std::size_t origOffset = offset;
	VersionInfoHeader chh;
	if (bytes.size() < offset + chh.structSize())
	{
		return false;
	}

	DynamicBuffer structContent(bytes, retdec::utils::Endianness::LITTLE);
	chh.length = structContent.read<std::uint16_t>(offset); offset += sizeof(chh.length);
	chh.valueLength = structContent.read<std::uint16_t>(offset); offset += sizeof(chh.valueLength);
	chh.type = structContent.read<std::uint16_t>(offset); offset += sizeof(chh.type);

	std::string key = retdec::utils::unicodeToAscii(&bytes.data()[offset], bytes.size() - offset);

	if (key == "VarFileInfo")
	{
		offset += VFI_KEY_SIZE;
		offset = retdec::utils::alignUp(offset, sizeof(std::uint32_t));

		for (std::size_t targetOffset = origOffset + chh.length; offset < targetOffset; )
		{
			if (!parseVarFileInfoChild(bytes, offset))
			{
				return false;
			}
		}
	}
	else if (key == "StringFileInfo")
	{
		offset += SFI_KEY_SIZE;
		offset = retdec::utils::alignUp(offset, sizeof(std::uint32_t));

		for (std::size_t targetOffset = origOffset + chh.length; offset < targetOffset; )
		{
			if (!parseStringFileInfoChild(bytes, offset))
			{
				return false;
			}
		}
	}
	else
	{
		return false;
	}

	offset = retdec::utils::alignUp(offset, sizeof(std::uint32_t));
	return true;
}

/**
 * Parse VarFileInfo structure
 * @param bytes Resource bytes
 * @param offset Offset to structure
 * @return @c true if parsing was successful, @c false otherwise
 */
bool ResourceTable::parseVarFileInfoChild(const std::vector<std::uint8_t> &bytes, std::size_t &offset)
{
	VersionInfoHeader var;
	if (bytes.size() < offset + var.structSize())
	{
		return false;
	}

	DynamicBuffer structContent(bytes, retdec::utils::Endianness::LITTLE);
	var.length = structContent.read<std::uint16_t>(offset); offset += sizeof(var.length);
	var.valueLength = structContent.read<std::uint16_t>(offset); offset += sizeof(var.valueLength);
	var.type = structContent.read<std::uint16_t>(offset); offset += sizeof(var.type);

	std::string key = retdec::utils::unicodeToAscii(&bytes.data()[offset], bytes.size() - offset);
	if (key != "Translation")
	{
		return false;
	}

	offset += VAR_KEY_SIZE;
	offset = retdec::utils::alignUp(offset, sizeof(std::uint32_t));
	if (bytes.size() < offset + var.valueLength || var.valueLength % sizeof(std::uint32_t))
	{
		return false;
	}

	for (std::size_t targetOffset = offset + var.valueLength; offset < targetOffset; )
	{
		std::uint32_t lang = structContent.read<uint32_t>(offset); offset += sizeof(lang);
		std::uint16_t lcid = lang & 0xFFFF;
		std::uint16_t codePage = lang >> 16;
		languages.emplace_back(std::make_pair(lcidToStr(lcid), codePageToStr(codePage)));
	}

	offset = retdec::utils::alignUp(offset, sizeof(std::uint32_t));
	return true;
}

/**
 * Parse StringFileInfo child
 * @param bytes Resource bytes
 * @param offset Offset to structure
 * @return @c true if parsing was successful, @c false otherwise
 */
bool ResourceTable::parseStringFileInfoChild(const std::vector<std::uint8_t> &bytes, std::size_t &offset)
{
	std::size_t origOffset = offset;
	VersionInfoHeader sfih;
	if (bytes.size() < offset + sfih.structSize())
	{
		return false;
	}

	DynamicBuffer structContent(bytes, retdec::utils::Endianness::LITTLE);
	sfih.length = structContent.read<std::uint16_t>(offset); offset += sizeof(sfih.length);
	sfih.valueLength = structContent.read<std::uint16_t>(offset); offset += sizeof(sfih.valueLength);
	sfih.type = structContent.read<std::uint16_t>(offset); offset += sizeof(sfih.type);

	std::size_t nRead;
	std::string key = retdec::utils::unicodeToAscii(&bytes.data()[offset], bytes.size() - offset, nRead);
	if (nRead != STRTAB_KEY_SIZE)
	{
		return false;
	}

	offset += STRTAB_KEY_SIZE;
	offset = retdec::utils::alignUp(offset, sizeof(std::uint32_t));

	for (std::size_t targetOffset = origOffset + sfih.length; offset < targetOffset; )
	{
		if (!parseVarString(bytes, offset))
		{
			return false;
		}
	}

	offset = retdec::utils::alignUp(offset, sizeof(std::uint32_t));
	return true;
}

/**
 * Parse var string
 * @param bytes Resource bytes
 * @param offset Offset to structure
 * @return @c true if parsing was successful, @c false otherwise
 */
bool ResourceTable::parseVarString(const std::vector<std::uint8_t> &bytes, std::size_t &offset)
{
	std::size_t origOffset = offset;
	VersionInfoHeader str;
	if (bytes.size() < offset + str.structSize())
	{
		return false;
	}

	DynamicBuffer structContent(bytes, retdec::utils::Endianness::LITTLE);
	str.length = structContent.read<std::uint16_t>(offset); offset += sizeof(str.length);
	str.valueLength = structContent.read<std::uint16_t>(offset); offset += sizeof(str.valueLength);
	str.type = structContent.read<std::uint16_t>(offset); offset += sizeof(str.type);

	if (bytes.size() < origOffset + str.length || str.length < str.structSize())
	{
		return false;
	}

	std::size_t targetOffset = retdec::utils::alignUp(origOffset + str.length, sizeof(std::uint32_t));
	if (offset > targetOffset)
	{
		return false;
	}

	std::size_t nToRead = targetOffset - offset;
	std::size_t nRead;
	std::string name = retdec::utils::unicodeToAscii(&bytes.data()[offset], nToRead, nRead);
	offset += nRead;
	offset = retdec::utils::alignUp(offset, sizeof(std::uint32_t));
	if (offset > targetOffset)
	{
		return false;
	}

	nToRead = targetOffset - offset;
	std::string value;
	if (nToRead > 0)
		value = retdec::utils::unicodeToAscii(&bytes.data()[offset], nToRead, nRead);

	offset = targetOffset;
	strings.emplace_back(std::make_pair(name, value));
	return true;
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
 * Add version resource
 * @param ver Version resource which will be added
 */
void ResourceTable::addResourceVersion(Resource *ver)
{
	resourceVersions.push_back(ver);
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

		for(std::size_t eIndex = 0; eIndex < numberOfEntries; eIndex++)
		{
			std::size_t entryNameID;
			if(!iconGroup->getEntryNameID(eIndex, entryNameID))
			{
				continue;
			}

			for(auto icon : icons)
			{
				std::size_t iconNameID, iconSize;
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

				// Multiple icon group may reference an icon. If that happens, do not rewrite
				// icon dimensions. Doing so messes up with the icon hash, and we only care for the first icon anyway
				if(icon->hasValidDimensions())
					continue;

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
			auto sName = (res->hasEmptyName() && res->getNameId(aux)) ? std::to_string(aux) : res->getName();
			auto sType = (res->hasEmptyType() && res->getTypeId(aux)) ? std::to_string(aux) : res->getType();
			auto sLang = res->getLanguage();
			if(sType.empty())
			{
				sType = "-";
			}
			if(sLang.empty())
			{
				if(res->getLanguageId(aux))
				{
					sLang = std::to_string(aux);
					if(res->getSublanguageId(aux))
					{
						sLang += ":" + std::to_string(aux);
					}
				}
				else
				{
					sLang = "-";
				}
			}
			const auto md5 = res->hasMd5() ? res->getMd5() : "-";
			ret << "; " << sName << " (type: " << sType << ", language: " << sLang << ", offset: " <<
				intToHexString(res->getOffset()) << ", declSize: " << intToHexString(res->getSizeInFile()) <<
				", loadedSize: " << intToHexString(res->getLoadedSize()) << ", md5: " << md5 << ")\n";
		}
	}

	dumpTable = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
