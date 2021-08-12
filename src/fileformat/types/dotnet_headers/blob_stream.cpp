/**
 * @file src/fileformat/types/dotnet_headers/blob_stream.cpp
 * @brief Class for \#Blob Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/dotnet_headers/blob_stream.h"
#include <cstdint>

namespace retdec {
namespace fileformat {

/**
 * Constructor.
 * @param streamOffset Stream offset.
 * @param streamSize Stream size.
 */
BlobStream::BlobStream(std::vector<std::uint8_t> data, std::uint64_t streamOffset, std::uint64_t streamSize)
	: Stream(StreamType::Blob, streamOffset, streamSize), data(data)
{
}

/**
 * Returns the element at the specified offset in the blob.
 * @param offset Offset of the element.
 * @return Element data if it exists, otherwise empty sequence.
 */
std::vector<std::uint8_t> BlobStream::getElement(std::size_t offset) const
{
	// Ugly, C like just for fast prototype, rework TODO
	std::uint32_t len = 0;
	std::vector<std::uint8_t> res;
	const unsigned char* ptr = data.data() + offset;
	if (offset >= data.size())
	{
		return res;
	}
	else if ((*ptr & 0x80) == 0x00)
	{
		len = *ptr;
		offset += 1;
		if (offset + len <= data.size())
		{
			res.assign(data.begin() + offset, data.begin() + offset + len);
		}
	}
	else if ((*ptr & 0xC0) == 0x80)
	{
		// Make sure we have one more byte.
		if (offset + 1 < data.size())
		{
			// Shift remaining 6 bits left by 8 and OR in the remaining byte.
			len = ((*ptr & 0x3F) << 8) | *(ptr + 1);
			offset += 2;
		}
		if (offset + len <= data.size())
		{
			res.assign(data.begin() + offset, data.begin() + offset + len);
		}
	}
	else if ((*ptr & 0xE0) == 0xC0)
	{
		// Make sure we have 3 more bytes.
		if (offset + 3 < data.size())
		{
			// Shift remaining 6 bits left by 8 and OR in the remaining byte.
			len = ((*ptr & 0x1F) << 24) |
					(*(ptr + 1) << 16) |
					(*(ptr + 2) << 8) |
					*(ptr + 3);
			offset += 4;
		}
		if (offset + len <= data.size())
		{
			res.assign(data.begin() + offset, data.begin() + offset + len);
		}
	}

	return res;
}
} // namespace fileformat
} // namespace retdec
