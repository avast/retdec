/**
 * @file include/retdec/fileformat/types/dotnet_headers/stream.h
 * @brief Abstract class for Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_STREAM_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_STREAM_H

#include <cstdint>
#include <string>
#include <vector>

namespace retdec {
namespace fileformat {

/**
 * Stream type
 */
enum class StreamType
{
	Metadata,
	String,
	UserString,
	Blob,
	Guid
};

/**
 * Abstract stream
 */
class Stream
{
	private:
		StreamType type;
		std::uint64_t offset;
		std::uint64_t size;
		std::string name;
	protected:
		Stream(StreamType streamType, std::uint64_t streamOffset, std::uint64_t streamSize) : type(streamType), offset(streamOffset), size(streamSize)
		{
			switch (type)
			{
				case StreamType::Metadata:
					name = "#~";
					break;
				case StreamType::String:
					name = "#Strings";
					break;
				case StreamType::UserString:
					name = "#US";
					break;
				case StreamType::Blob:
					name = "#Blob";
					break;
				case StreamType::Guid:
					name = "#GUID";
					break;
				default:
					name.clear();
					break;
			}
		}
	public:
		virtual ~Stream() = default;

		/// @name Getters
		/// @{
		StreamType getType() const { return type; }
		std::uint64_t getOffset() const { return offset; }
		std::uint64_t getSize() const { return size; }
		const std::string& getName() const { return name; }
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
