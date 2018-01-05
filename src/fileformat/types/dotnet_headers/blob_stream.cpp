/**
 * @file src/fileformat/types/dotnet_headers/blob_stream.cpp
 * @brief Class for \#Blob Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/dotnet_headers/blob_stream.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor.
 * @param streamOffset Stream offset.
 * @param streamSize Stream size.
 */
BlobStream::BlobStream(std::uint64_t streamOffset, std::uint64_t streamSize) : Stream(StreamType::Blob, streamOffset, streamSize)
{
}

/**
 * Returns the element at the specified offset in the blob.
 * @param offset Offset of the element.
 * @return Element data if it exists, otherwise empty sequence.
 */
std::vector<std::uint8_t> BlobStream::getElement(std::size_t offset) const
{
	auto itr = elements.find(offset);
	if (itr == elements.end())
		return {};

	return itr->second;
}

/**
 * Adds new element at the specified offset.
 * @param offset Offset of the element.
 * @param data Data of the element.
 */
void BlobStream::addElement(std::size_t offset, const std::vector<std::uint8_t>& data)
{
	elements.emplace(offset, data);
}

} // namespace fileformat
} // namespace retdec
