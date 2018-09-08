/**
 * @file src/fileformat/types/resource_table/resource_icon_group.cpp
 * @brief Class for one resource icon group.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/resource_table/resource_icon.h"
#include "retdec/fileformat/types/resource_table/resource_icon_group.h"


namespace {

// Icon priority list
constexpr std::pair<unsigned short, uint16_t> iconPriorities[] =
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
 * Icon comparator
 * @param i1 First icon to be compared
 * @param i2 Second icon to be compared
 * @return Comparison result
 */
bool iconCompare(const retdec::fileformat::ResourceIcon *i1, const retdec::fileformat::ResourceIcon *i2)
{
	auto i1Width = i1->getWidth();
	auto i1BitCount = i1->getBitCount();
	auto i2Width = i2->getWidth();
	auto i2Height = i2->getHeight();
	auto i2BitCount = i2->getBitCount();

	if(i2Width != i2Height)
	{
		return false;
	}

	for(const auto &p : iconPriorities)
	{
		if(p.first == i1Width && p.second == i1BitCount)
		{
			return false;
		}

		if(p.first == i2Width && p.second == i2BitCount)
		{
			return true;
		}
	}

	return false;
}

} // anonymous namespace

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
ResourceIconGroup::ResourceIconGroup() : iconGroupID(0)
{

}

/**
 * Destructor
 */
ResourceIconGroup::~ResourceIconGroup()
{

}

/**
 * Get entry offset
 * @param eIndex Index of selected entry (indexed from 0)
 * @return Entry offset
 */
std::size_t ResourceIconGroup::getEntryOffset(std::size_t eIndex) const
{
	return 6 + eIndex * 14;
}

/**
 * Get number of icons
 * @return Number of icons
 */
std::size_t ResourceIconGroup::getNumberOfIcons() const
{
	return icons.size();
}

/**
 * Get icon
 * @param iIndex Index of selected icon (indexed from 0)
 * @return Icon
 */
const ResourceIcon *ResourceIconGroup::getIcon(std::size_t iIndex) const
{
	if(iIndex >= icons.size())
	{
		return nullptr;
	}

	return icons[iIndex];
}

/**
 * Get prior icon by Windows OS precedence
 * @return Prior icon
 */
const ResourceIcon *ResourceIconGroup::getPriorIcon() const
{
	auto result = std::max_element(icons.begin(), icons.end(), iconCompare);

	if(result == icons.end())
	{
		return nullptr;
	}

	return *result;
}

/**
 * Get icon group ID
 * @return Icon group ID
 */
std::size_t ResourceIconGroup::getIconGroupID() const
{
	return iconGroupID;
}

/**
 * Get number of entries
 * @param nEntries Destination for result to be stored
 * @return @c true if get was successfull, otherwise false
*/
bool ResourceIconGroup::getNumberOfEntries(std::size_t &nEntries) const
{
	std::vector<unsigned char> bytes;

	if(!getBytes(bytes, 4, 2))
	{
		return false;
	}

	nEntries = bytes[1] << 8 | bytes[0];

	return true;
}

/**
 * Get entry name ID
 * @param eIndex Index of selected entry (indexed from 0)
 * @param nameID Destination for result to be stored
 * @return @c true if get was successfull, otherwise false
*/
bool ResourceIconGroup::getEntryNameID(std::size_t eIndex, std::size_t &nameID) const
{
	std::vector<unsigned char> bytes;

	if(!getBytes(bytes, getEntryOffset(eIndex) + 12, 2))
	{
		return false;
	}

	nameID = bytes[1] << 8 | bytes[0];

	return true;
}

/**
 * Get entry width
 * @param eIndex Index of selected entry (indexed from 0)
 * @param width Destination for result to be stored
 * @return @c true if get was successfull, otherwise false
*/
bool ResourceIconGroup::getEntryWidth(std::size_t eIndex, std::uint16_t &width) const
{
	std::vector<unsigned char> bytes;

	if(!getBytes(bytes, getEntryOffset(eIndex) + 0, 1))
	{
		return false;
	}

	width = bytes[0];

	return true;
}

/**
 * Get entry height
 * @param eIndex Index of selected entry (indexed from 0)
 * @param height Destination for result to be stored
 * @return @c true if get was successfull, otherwise false
*/
bool ResourceIconGroup::getEntryHeight(std::size_t eIndex, std::uint16_t &height) const
{
	std::vector<unsigned char> bytes;

	if(!getBytes(bytes, getEntryOffset(eIndex) + 1, 1))
	{
		return false;
	}

	height = bytes[0];

	return true;
}

/**
 * Get entry icon size
 * @param eIndex Index of selected entry (indexed from 0)
 * @param iconSize Destination for result to be stored
 * @return @c true if get was successfull, otherwise false
*/
bool ResourceIconGroup::getEntryIconSize(std::size_t eIndex, std::size_t &iconSize) const
{
	std::vector<unsigned char> bytes;

	if(!getBytes(bytes, getEntryOffset(eIndex) + 8, 4))
	{
		return false;
	}

	iconSize = bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0];

	return true;
}

/**
 * Get entry color count
 * @param eIndex Index of selected entry (indexed from 0)
 * @param colorCount Destination for result to be stored
 * @return @c true if get was successfull, otherwise false
*/
bool ResourceIconGroup::getEntryColorCount(std::size_t eIndex, std::uint8_t &colorCount) const
{
	std::vector<unsigned char> bytes;

	if(!getBytes(bytes, getEntryOffset(eIndex) + 2, 1))
	{
		return false;
	}

	colorCount = bytes[0];

	return true;
}

/**
 * Get entry planes
 * @param eIndex Index of selected entry (indexed from 0)
 * @param planes Destination for result to be stored
 * @return @c true if get was successfull, otherwise false
*/
bool ResourceIconGroup::getEntryPlanes(std::size_t eIndex, std::uint16_t &planes) const
{
	std::vector<unsigned char> bytes;

	if(!getBytes(bytes, getEntryOffset(eIndex) + 4, 2))
	{
		return false;
	}

	planes = bytes[1] << 8 | bytes[0];

	return true;
}

/**
 * Get entry bit count
 * @param eIndex Index of selected entry (indexed from 0)
 * @param bitCount Destination for result to be stored
 * @return @c true if get was successfull, otherwise false
*/
bool ResourceIconGroup::getEntryBitCount(std::size_t eIndex, std::uint16_t &bitCount) const
{
	std::vector<unsigned char> bytes;

	if(!getBytes(bytes, getEntryOffset(eIndex) + 6, 2))
	{
		return false;
	}

	bitCount = bytes[1] << 8 | bytes[0];

	return true;
}

/**
 * Set icon group ID
 * @param id Icon group ID
*/
void ResourceIconGroup::setIconGroupID(std::size_t id)
{
	iconGroupID = id;
}

/**
 * A method which indicates whether there are icons present in icon group.
 * @return @c `true` if there are, otherwise `false`
 */
bool ResourceIconGroup::hasIcons() const
{
	return !icons.empty();
}

/**
 * Add an icon to the icon group 
 */
void ResourceIconGroup::addIcon(ResourceIcon *icon)
{
	icons.push_back(icon);
}

} // namespace fileformat
} // namespace retdec
