/**
 * @file include/retdec/fileformat/types/resource_table/resource_icon_group.h
 * @brief Class for one resource icon group.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_ICON_GROUP_H
#define RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_ICON_GROUP_H

#include "retdec/fileformat/types/resource_table/resource.h"
#include "retdec/fileformat/types/resource_table/resource_icon.h"

namespace retdec {
namespace fileformat {

/**
 * One resource icon
 */
class ResourceIconGroup : public Resource
{
    private:
        std::vector<ResourceIcon *> icons;  ///< stored icons
        size_t iconGroupID;                 ///< icon group id

        /// @name Auxiliary methods
        /// @{
        std::size_t getEntryOffset(std::size_t eIndex) const;
        /// @}

    public:
        ResourceIconGroup();
        ~ResourceIconGroup();

        /// @name Getters
        /// @{
        std::size_t getNumberOfIcons() const;
        const ResourceIcon *getIcon(std::size_t iIndex) const;
        const ResourceIcon *getPriorIcon() const;
        std::size_t getIconGroupID() const;
        /// @}

        /// @name Getters of icon group content
        /// @{
        bool getNumberOfEntries(std::size_t &nEntries) const;
        bool getEntryNameID(std::size_t eIndex, std::size_t &nameID) const;
        bool getEntryWidth(std::size_t eIndex, std::uint16_t &width) const;
        bool getEntryHeight(std::size_t eIndex, std::uint16_t &height) const;
        bool getEntryIconSize(std::size_t eIndex, std::size_t &iconSize) const;
        bool getEntryColorCount(std::size_t eIndex, std::uint8_t &colorCount) const;
        bool getEntryPlanes(std::size_t eIndex, std::uint16_t &planes) const;
        bool getEntryBitCount(std::size_t eIndex, std::uint16_t &bitCount) const;
        /// @}

        /// @name Setters
        /// @{
        void setIconGroupID(std::size_t id);
        /// @}

        /// @name Other methods
        /// @{
        bool hasIcons() const;
        void addIcon(ResourceIcon *icon);
        /// @}
};

} // namespace fileformat
} // namespace retdec

#endif
