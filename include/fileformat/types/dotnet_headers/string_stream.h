/**
 * @file include/fileformat/types/dotnet_headers/string_stream.h
 * @brief Class for \#Strings Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_TYPES_DOTNET_HEADERS_STRING_STREAM_H
#define FILEFORMAT_TYPES_DOTNET_HEADERS_STRING_STREAM_H

#include <map>

#include "fileformat/types/dotnet_headers/stream.h"

namespace fileformat {

class StringStream : public Stream
{
	private:
		std::map<std::size_t, std::string> strings;
	public:
		StringStream(std::uint64_t streamOffset, std::uint64_t streamSize);

		/// @name Getters
		/// @{
		bool getString(std::size_t offset, std::string& result) const;
		/// @}

		/// @name String methods
		/// @{
		void addString(std::size_t offset, const std::string& string);
		/// @}
};

} // namespace fileformat

#endif
