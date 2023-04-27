/**
 * @file include/retdec/fileformat/types/rich_header/linker_info.h
 * @brief Class for information about linker.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RICH_HEADER_LINKER_INFO_H
#define RETDEC_FILEFORMAT_TYPES_RICH_HEADER_LINKER_INFO_H

#include <cstdint>
#include <string>

namespace retdec {
namespace fileformat {

/**
 * Information about linker
 */
class LinkerInfo
{
	private:
		std::uint32_t productId = 0;    ///< Product ID from the RichHeader
		std::uint32_t productBuild = 0; ///< Product Build from the RichHeader
		std::uint32_t count = 0;        ///< number of uses
		std::string productName;        ///< Product codename
		std::string visualStudioName;   ///< Product codename
	public:
		/// @name Getters
		/// @{
		std::uint32_t getProductId() const;
		std::uint32_t getProductBuild() const;
		std::uint32_t getNumberOfUses() const;
		std::string getProductName() const;
		std::string getVisualStudioName() const;
		/// @}

		/// @name Setters
		/// @{
		void setProductId(std::uint32_t richProductId);
		void setProductBuild(std::uint32_t richProductBuild);
		void setNumberOfUses(std::uint32_t richProductCount);
		void setProductName(const std::string & richProductName);
		void setVisualStudioName(const std::string & richVisualStudioName);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
