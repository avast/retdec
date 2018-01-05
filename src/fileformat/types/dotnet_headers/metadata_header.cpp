/**
 * @file src/fileformat/types/dotnet_headers/metadata_header.cpp
 * @brief Class for Metadata header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/dotnet_headers/metadata_header.h"

namespace retdec {
namespace fileformat {

/**
 * Returns the address of metadata header.
 * @return Metadata header address.
 */
std::uint64_t MetadataHeader::getAddress() const
{
	return address;
}

/**
 * Returns the major version of the header.
 * @return Major version.
 */
std::uint64_t MetadataHeader::getMajorVersion() const
{
	return majorVersion;
}

/**
 * Returns the minor version of the header.
 * @return Minor version.
 */
std::uint64_t MetadataHeader::getMinorVersion() const
{
	return minorVersion;
}

/**
 * Returns the version string.
 * @return Version string.
 */
const std::string& MetadataHeader::getVersion() const
{
	return version;
}

/**
 * Returns the flags.
 * @return The flags.
 */
std::uint64_t MetadataHeader::getFlags() const
{
	return flags;
}

/**
 * Sets the metadata header address.
 * @param metadataHeaderAddress Metadata header address.
 */
void MetadataHeader::setAddress(std::uint64_t metadataHeaderAddress)
{
	address = metadataHeaderAddress;
}

/**
 * Sets the major version of the header.
 * @param metadataMajorVersion Major version of the header.
 */
void MetadataHeader::setMajorVersion(std::uint64_t metadataMajorVersion)
{
	majorVersion = metadataMajorVersion;
}

/**
 * Sets the minor version of the header.
 * @param metadataMinorVersion Minor version of the header.
 */
void MetadataHeader::setMinorVersion(std::uint64_t metadataMinorVersion)
{
	minorVersion = metadataMinorVersion;
}

/**
 * Sets the version string.
 * @param metadataVersion Version string.
 */
void MetadataHeader::setVersion(const std::string& metadataVersion)
{
	version = metadataVersion;
}

/**
 * Sets the flags.
 * @param metadataFlags Flags.
 */
void MetadataHeader::setFlags(std::uint64_t metadataFlags)
{
	flags = metadataFlags;
}

} // namespace fileformat
} // namespace retdec
