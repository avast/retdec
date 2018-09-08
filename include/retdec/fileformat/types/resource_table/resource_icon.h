/**
 * @file include/retdec/fileformat/types/resource_table/resource_icon.h
 * @brief Class for one resource icon.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_ICON_H
#define RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_ICON_H

#include "retdec/fileformat/types/resource_table/resource.h"
namespace retdec {
namespace fileformat {

/**
 * One resource icon
 */
class ResourceIcon : public Resource
{
    private:
        std::uint16_t width;              ///< icon width
        std::uint16_t height;             ///< icon height
        std::size_t iconSize;             ///< icon size in file
        std::uint8_t colorCount;          ///< icon color count
        std::uint16_t planes;             ///< icon planes
        std::uint16_t bitCount;           ///< icon bit count
        std::size_t iconGroup;            ///< icon group the icon belongs to
        bool loadedProperties;            ///< @c true if properties were successfully loaded from icon group resource
        bool validColorCount;             ///< @c true if color count has a valid value

    public:
        ResourceIcon();
        ~ResourceIcon();

        /// @name Getters
        /// @{
        std::uint16_t getWidth() const;
        std::uint16_t getHeight() const;
        std::size_t getIconSize() const;
        std::uint8_t getColorCount() const;
        std::uint16_t getPlanes() const;
        std::uint16_t getBitCount() const;
        std::size_t getIconGroup() const;
        /// @}

        /// @name Setters
        /// @{
        void setWidth(std::uint16_t iWidth);
        void setHeight(std::uint16_t iHeight);
        void setIconSize(std::size_t iSize);
        void setColorCount(std::uint8_t iColorCount);
        void setPlanes(std::uint16_t iPlanes);
        void setBitCount(std::uint16_t iBitCount);
        void setIconGroup(std::size_t iGroup);
        void setLoadedProperties();
        void setValidColorCount();
        /// @}

        /// @name Other methods
        /// @{
        bool hasLoadedProperties() const;
        bool hasValidColorCount() const;
        /// @}
};

} // namespace fileformat
} // namespace retdec

#endif
