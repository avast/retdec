/**
 * @file include/fileformat/types/dotnet_headers/guid_stream.h
 * @brief Class for \#GUID Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_TYPES_DOTNET_HEADERS_GUID_STREAM_H
#define FILEFORMAT_TYPES_DOTNET_HEADERS_GUID_STREAM_H

#include <array>
#include <vector>

#include "fileformat/types/dotnet_headers/stream.h"

namespace fileformat {

class GuidStream : public Stream
{
	private:
		using GuidData = std::array<std::uint8_t, 16>;

		std::vector<GuidData> guids;
	public:
		GuidStream(std::uint64_t streamOffset, std::uint64_t streamSize);

		/// @name Getters
		/// @{
		std::vector<std::uint8_t> getGuid(std::size_t index) const;
		std::string getGuidString(std::size_t index) const;
		/// @}

		/// @name GUID methods
		/// @{
		void addGuids(const std::vector<std::uint8_t>& data);
		/// @}
};

} // namespace fileformat

#endif
