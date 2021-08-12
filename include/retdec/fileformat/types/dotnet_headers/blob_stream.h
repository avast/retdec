/**
 * @file include/retdec/fileformat/types/dotnet_headers/blob_stream.h
 * @brief Class for \#Blob Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_BLOB_STREAM_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_BLOB_STREAM_H

#include <cstdint>
#include <unordered_map>

#include "retdec/fileformat/types/dotnet_headers/stream.h"

namespace retdec {
namespace fileformat {

class BlobStream : public Stream
{
	private:
		std::vector<std::uint8_t> data;
	public:
		BlobStream(std::vector<std::uint8_t> data, std::uint64_t streamOffset, std::uint64_t streamSize);

		std::vector<std::uint8_t> getElement(std::size_t offset) const;
};

} // namespace fileformat
} // namespace retdec

#endif
