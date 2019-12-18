/**
 * @file include/retdec/fileformat/types/rich_header/linker_info.h
 * @brief Class for information about linker.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RICH_HEADER_LINKER_INFO_H
#define RETDEC_FILEFORMAT_TYPES_RICH_HEADER_LINKER_INFO_H

namespace retdec {
namespace fileformat {

/**
 * Information about linker
 */
class LinkerInfo
{
	private:
		unsigned long long majorVersion = 0; ///< major version of linker
		unsigned long long minorVersion = 0; ///< minor version of linker
		unsigned long long buildVersion = 0; ///< build version
		unsigned long long count = 0;        ///< number of uses
	public:
		/// @name Getters
		/// @{
		unsigned long long getMajorVersion() const;
		unsigned long long getMinorVersion() const;
		unsigned long long getBuildVersion() const;
		unsigned long long getNumberOfUses() const;
		/// @}

		/// @name Setters
		/// @{
		void setMajorVersion(unsigned long long linkerMajorVersion);
		void setMinorVersion(unsigned long long linkerMinorVersion);
		void setBuildVersion(unsigned long long linkerBuildVersion);
		void setNumberOfUses(unsigned long long linkerCount);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
