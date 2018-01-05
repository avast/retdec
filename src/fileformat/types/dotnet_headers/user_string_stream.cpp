/**
 * @file src/fileformat/types/dotnet_headers/user_string_stream.cpp
 * @brief Class for \#US Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileformat/types/dotnet_headers/user_string_stream.h"

namespace fileformat {

/**
 * Constructor.
 * @param streamOffset Stream offset.
 * @param streamSize Stream size.
 */
UserStringStream::UserStringStream(std::uint64_t streamOffset, std::uint64_t streamSize) : Stream(StreamType::UserString, streamOffset, streamSize)
{
}

} // namespace fileformat
