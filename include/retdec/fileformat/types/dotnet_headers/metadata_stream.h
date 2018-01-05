/**
 * @file include/retdec/fileformat/types/dotnet_headers/metadata_stream.h
 * @brief Class for \#~ Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_METADATA_STREAM_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_METADATA_STREAM_H

#include <map>
#include <memory>

#include "retdec/utils/container.h"
#include "retdec/fileformat/types/dotnet_headers/metadata_table.h"
#include "retdec/fileformat/types/dotnet_headers/stream.h"

namespace retdec {
namespace fileformat {

class MetadataStream : public Stream
{
	private:
		using TypeToTableMap = std::map<MetadataTableType, std::unique_ptr<BaseMetadataTable>>;

		std::uint32_t majorVersion;
		std::uint32_t minorVersion;
		std::uint32_t stringStreamIndexSize;
		std::uint32_t guidStreamIndexSize;
		std::uint32_t blobStreamIndexSize;
		TypeToTableMap metadataTables;
	public:
		MetadataStream(std::uint64_t streamOffset, std::uint64_t streamSize);

		/// @name Getters
		/// @{
		std::uint32_t getMajorVersion() const;
		std::uint32_t getMinorVersion() const;
		std::uint32_t getStringStreamIndexSize() const;
		std::uint32_t getGuidStreamIndexSize() const;
		std::uint32_t getBlobStreamIndexSize() const;
		BaseMetadataTable* getMetadataTable(MetadataTableType tableType);
		const BaseMetadataTable* getMetadataTable(MetadataTableType tableType) const;
		/// @}

		/// @name Setters
		/// @{
		void setMajorVersion(std::uint32_t streamMajorVersion);
		void setMinorVersion(std::uint32_t streamMinorVersion);
		void setStringStreamIndexSize(std::uint32_t indexSize);
		void setGuidStreamIndexSize(std::uint32_t indexSize);
		void setBlobStreamIndexSize(std::uint32_t indexSize);
		/// @}

		/// @name Metadata tables methods
		/// @{
		BaseMetadataTable* addMetadataTable(MetadataTableType tableType, std::uint32_t tableSize);
		/// @}

		/// @name Detection
		/// @{
		bool hasTable(MetadataTableType metadataTableType) const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
