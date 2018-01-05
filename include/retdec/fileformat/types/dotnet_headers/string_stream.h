/**
 * @file include/retdec/fileformat/types/dotnet_headers/string_stream.h
 * @brief Class for \#Strings Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_STRING_STREAM_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_STRING_STREAM_H

#include <map>

#include "retdec/fileformat/types/dotnet_headers/stream.h"

namespace retdec {
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
} // namespace retdec

#endif
