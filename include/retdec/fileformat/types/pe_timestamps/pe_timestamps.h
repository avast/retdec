/**
 * @file include/retdec/fileformat/types/pe_timestamps/pe_timestamps.h
 * @brief PE timestamps.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILEFORMAT_TYPES_PE_TIMESTAMPS_H
#define FILEINFO_FILE_INFORMATION_FILEFORMAT_TYPES_PE_TIMESTAMPS_H

#include <cstdint>
#include <vector>

namespace retdec {
namespace fileformat {

/**
 * Class for PE timestamps
 */
class PeTimestamps
{
public:
	std::uint32_t coffTime;
	std::uint32_t exportTime;
	std::uint32_t configTime;
	std::vector<std::uint32_t> resourceTime; // each Resource Directory
	std::vector<std::uint32_t> debugTime;    // each Debug Directory entry
	std::vector<std::uint32_t> pdbTime;      // each NB10 debug data
};

} // namespace fileformat
} // namespace retdec

#endif
