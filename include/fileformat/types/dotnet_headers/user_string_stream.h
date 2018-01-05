/**
 * @file include/fileformat/types/dotnet_headers/user_string_stream.h
 * @brief Class for \#US Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_TYPES_DOTNET_HEADERS_USER_STRING_STREAM_H
#define FILEFORMAT_TYPES_DOTNET_HEADERS_USER_STRING_STREAM_H

#include "fileformat/types/dotnet_headers/stream.h"

namespace fileformat {

class UserStringStream : public Stream
{
	public:
		UserStringStream(std::uint64_t streamOffset, std::uint64_t streamSize);
};

} // namespace fileformat

#endif
