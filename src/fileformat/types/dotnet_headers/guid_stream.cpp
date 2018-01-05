/**
 * @file src/fileformat/types/dotnet_headers/guid_stream.cpp
 * @brief Class for \#GUID Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "retdec/fileformat/types/dotnet_headers/guid_stream.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor.
 * @param streamOffset Stream offset.
 * @param streamSize Stream size.
 */
GuidStream::GuidStream(std::uint64_t streamOffset, std::uint64_t streamSize) : Stream(StreamType::Guid, streamOffset, streamSize)
{
}

/**
 * Returns the GUID at the specified index.
 * @param index Index of the GUID.
 * @return Binary GUID if it exists, otherwise empty sequence.
 */
std::vector<std::uint8_t> GuidStream::getGuid(std::size_t index) const
{
	if (index >= guids.size())
		return {};

	return std::vector<std::uint8_t>(guids[index].begin(), guids[index].end());
}

/**
 * Returns the GUID at the specified index in the string representation.
 * @param index Index of the GUID.
 * @return String representation of GUID if it exists, otherwise empty string.
 */
std::string GuidStream::getGuidString(std::size_t index) const
{
	// GUIDs are indexed starting from 1
	if (index - 1 >= guids.size())
		return {};

	const auto& guid = guids[index - 1];

	// GUID is in format AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
	// AAAAAAAA = little-endian dword
	// BBBB/CCCC = little-endian word
	// DDDD/EEEEEEEEEEE = individual bytes
	std::stringstream ss;
	for (std::int32_t i = 4; i > 0; --i)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<std::uint32_t>(guid[i - 1]);
	}

	ss << '-';

	for (std::int32_t j = 0; j < 2; ++j)
	{
		for (std::int32_t i = 2; i > 0; --i)
		{
			ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<std::uint32_t>(guid[4 + j * 2 + i - 1]);
		}

		ss << '-';
	}

	ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<std::uint32_t>(guid[8]);
	ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<std::uint32_t>(guid[9]);
	ss << '-';

	for (std::int32_t i = 10; i < 16; ++i)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<std::uint32_t>(guid[i]);
	}

	return ss.str();
}

/**
 * Adds multiple GUIDs stored in single sequence. Each GUID is 16 bytes long.
 * Sequence is read until there are less than 16 bytes available.
 * @param data Sequence of GUIDs.
 */
void GuidStream::addGuids(const std::vector<std::uint8_t>& data)
{
	auto guidSrc = data;

	while (guidSrc.size() >= 16)
	{
		GuidData newGuid;
		std::copy_n(guidSrc.begin(), 16, newGuid.begin());
		guidSrc.erase(guidSrc.begin(), guidSrc.begin() + 16);

		guids.push_back(std::move(newGuid));
	}
}

} // namespace fileformat
} // namespace retdec
