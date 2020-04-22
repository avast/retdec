/**
 * @file src/fileformat/types/rich_header/linker_info.cpp
 * @brief Class for information about linker.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/rich_header/linker_info.h"

namespace retdec {
namespace fileformat {

/**
 * Get major version
 * @return Major version of linker
 */
uint32_t LinkerInfo::getProductId() const
{
	return productId;
}

/**
 * Get build version
 * @return Build version of linker
 */
uint32_t LinkerInfo::getProductBuild() const
{
	return productBuild;
}

/**
 * Get number of uses
 * @return Number of uses
 */
uint32_t LinkerInfo::getNumberOfUses() const
{
	return count;
}

/**
 * Get product name as string
 * @return Product Name as std::string
 */
std::string LinkerInfo::getProductName() const
{
	return productName;
}

/**
 * Get aproximate name of Visual Studio
 * @return Visual Studio version as std::string
 */
std::string LinkerInfo::getVisualStudioName() const
{
	return visualStudioName;
}

/**
 * Set major version of linker
 * @param richProductId Major version of linker
 */
void LinkerInfo::setProductId(uint32_t richProductId)
{
	productId = richProductId;
}

/**
 * Set build version
 * @param richProductBuild Build version
 */
void LinkerInfo::setProductBuild(uint32_t richProductBuild)
{
	productBuild = richProductBuild;
}

/**
 * Set number of uses
 * @param richProductCount Number of uses
 */
void LinkerInfo::setNumberOfUses(uint32_t richProductCount)
{
	count = richProductCount;
}

void LinkerInfo::setProductName(const std::string & richProductName)
{
	productName = richProductName;
}

void LinkerInfo::setVisualStudioName(const std::string & richVisualStudioName)
{
	visualStudioName = richVisualStudioName;
}

} // namespace fileformat
} // namespace retdec
