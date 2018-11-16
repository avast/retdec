/**
 * @file include/retdec/fileformat/types/visual_basic_header/visual_basic_project_info.h
 * @brief Class for visual basic project info.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_HEADER_VISUAL_BASIC_PROJECT_INFO_H
#define RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_HEADER_VISUAL_BASIC_PROJECT_INFO_H

#include <string>

namespace retdec {
namespace fileformat {

struct VBProjInfo
{
	std::uint32_t	dwVersion;                      ///< 5.00 in Hex (0x1F4), version
	std::uint32_t	lpObjectTable;                  ///< pointer to object table
	std::uint32_t	dwNull;                         ///< unused value after compilation
	std::uint32_t	lpCodeStart;                    ///< pointer to start of code
	std::uint32_t	lpCodeEnd;                      ///< pointer to end of code
	std::uint32_t	dwDataSize;                     ///< size of VB object structures
	std::uint32_t	lpThreadSpace;                  ///< pointer to pointer to thread object
	std::uint32_t	lpVbaSeh;                       ///< pointer to VBA exception handler
	std::uint32_t	lpNativeCode;                   ///< pointer to .DATA section
	uint8_t			szPathInformation[528];         ///< path and id string, <SP6
	std::uint32_t	lpExternalTable;                ///< pointer to external table
	std::uint32_t	dwExternalCount;                ///< objects in the external table

	VBProjInfo()
	{

	}

	std::size_t headerSize()
	{
		return
			sizeof(dwVersion) + sizeof(lpObjectTable) + sizeof(dwNull)
			+ sizeof(lpCodeStart) + sizeof(lpCodeEnd) + sizeof(dwDataSize)
			+ sizeof(lpThreadSpace) + sizeof(lpVbaSeh) + sizeof(lpNativeCode)
			+ sizeof(szPathInformation) + sizeof(lpExternalTable) + sizeof(dwExternalCount);
	}

	void dump(std::ostream &out)
	{
		out << "dwVersion:\t\t" << dwVersion << "\n";
		out << "lpObjectTable:\t\t" << lpObjectTable << "\n";
		out << "dwNull:\t\t\t" << dwNull << "\n";
		out << "lpCodeStart:\t\t" << lpCodeStart << "\n";
		out << "lpCodeEnd:\t\t" << lpCodeEnd << "\n";
		out << "dwDataSize:\t\t" << dwDataSize << "\n";
		out << "lpThreadSpace:\t\t" << lpThreadSpace << "\n";
		out << "lpVbaSeh:\t\t" << lpVbaSeh << "\n";
		out << "lpNativeCode:\t" << lpNativeCode << "\n";
		out << "szPathInformation:\t" << "TODO szPathInformation" << "\n";
		out << "lpExternalTable:\t" << lpExternalTable << "\n";
		out << "dwExternalCount:\t" << dwExternalCount << "\n";
		out << "\n";
	}
};

/**
 * Visual basic header
 */
class VisualBasicProjectInfo
{
	private:

	public:
		VisualBasicProjectInfo();
		~VisualBasicProjectInfo();

		/// @name Getters
		/// @{

		/// @}

		/// @name Setters
		/// @{

		/// @}

		/// @name Iterators
		/// @{

		/// @}

		/// @name Other methods
		/// @{

		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
