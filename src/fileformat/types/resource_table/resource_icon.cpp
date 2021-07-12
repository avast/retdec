/**
 * @file src/fileformat/types/resource_table/resource_icon.cpp
 * @brief Class for one resource icon.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/resource_table/resource_icon.h"

namespace retdec {
namespace fileformat {

/**
 * Get icon width
 * @return Icon with
 */
std::uint16_t ResourceIcon::getWidth() const
{
	return width;
}

/**
 * Get icon height
 * @return Icon height
 */
std::uint16_t ResourceIcon::getHeight() const
{
	return height;
}

/**
 * Get icon size
 * @return Icon size
 */
std::size_t ResourceIcon::getIconSize() const
{
	return iconSize;
}

/**
 * Get icon color count
 * @return Color count
 */
std::uint8_t ResourceIcon::getColorCount() const
{
	return colorCount;
}

/**
 * Get icon planes
 * @return Planes
 */
std::uint16_t ResourceIcon::getPlanes() const
{
	return planes;
}

/**
 * Get icon bit count
 * @return Bit count
 */
std::uint16_t ResourceIcon::getBitCount() const
{
	return bitCount;
}

/**
 * Get icon group
 * @return Icon group
 */
std::size_t ResourceIcon::getIconGroup() const
{
	return iconGroup;
}

/**
 * Set icon width
 * @param iWidth Icon width
 */
void ResourceIcon::setWidth(std::uint16_t iWidth)
{
	if(width == 0)
	{
		width = 256;
	}

	width = iWidth;
}

/**
 * Set icon height
 * @param iHeight Icon height
 */
void ResourceIcon::setHeight(std::uint16_t iHeight)
{
	if(height == 0)
	{
		height = 256;
	}

	height = iHeight;
}

/**
 * Set icon size
 * @param iSize Icon size
 */
void ResourceIcon::setIconSize(std::size_t iSize)
{
	iconSize = iSize;
}

/**
 * Set icon color count
 * @param iColorCount Icon color count
 */
void ResourceIcon::setColorCount(std::uint8_t iColorCount)
{
	colorCount = iColorCount;
}

/**
 * Set icon planes
 * @param iPlanes Icon planes
 */
void ResourceIcon::setPlanes(std::uint16_t iPlanes)
{
	planes = iPlanes;
}

/**
 * Set icon bit count
 * @param iBitCount Icon bit count
 */
void ResourceIcon::setBitCount(std::uint16_t iBitCount)
{
	bitCount = iBitCount;
}

/**
 * Set icon group
 * @param iGroup Icon Group
 */
void ResourceIcon::setIconGroup(std::size_t iGroup)
{
	iconGroup = iGroup;
}

/**
 * Set loaded properties flag
 */
void ResourceIcon::setLoadedProperties()
{
	loadedProperties = true;
}

/**
 * Set color count to a valid state
 */
void ResourceIcon::setValidColorCount()
{
	validColorCount = true;
}

/**
 * A method which indicates whether icon properties are loaded.
 * @return @c `true` if it is, otherwise `false`
 */
bool ResourceIcon::hasLoadedProperties() const
{
	return loadedProperties;
}

/**
 * A method which indicates whether color count of an icon is valid.
 * @return @c `true` if it is, otherwise `false`
 */
bool ResourceIcon::hasValidColorCount() const
{
	return validColorCount;
}

/**
* Returns tru if the icon dimensions were already set before
* @return @c `true` if they were, otherwise `false`
*/
bool ResourceIcon::hasValidDimensions() const
{
	return (width && height);
}


} // namespace fileformat
} // namespace retdec
