/**
 * @file include/retdec/fileformat/types/dotnet_headers/metadata_header.h
 * @brief Class for Metadata header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_METADATA_HEADER_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_METADATA_HEADER_H

#include <string>

namespace retdec {
namespace fileformat {

const std::uint64_t MetadataHeaderSignature = 0x424A5342;

/**
 * Metadata header
 */
class MetadataHeader
{
	private:
		std::uint64_t address;
		std::uint64_t majorVersion;
		std::uint64_t minorVersion;
		std::string version;
		std::uint64_t flags;
	public:
		/// @name Getters
		/// @{
		std::uint64_t getAddress() const;
		std::uint64_t getMajorVersion() const;
		std::uint64_t getMinorVersion() const;
		const std::string& getVersion() const;
		std::uint64_t getFlags() const;
		/// @}

		/// @name Setters
		/// @{
		void setAddress(std::uint64_t metadataHeaderAddress);
		void setMajorVersion(std::uint64_t metadataMajorVersion);
		void setMinorVersion(std::uint64_t metadataMinorVersion);
		void setVersion(const std::string& metadataVersion);
		void setFlags(std::uint64_t metadataFlags);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
