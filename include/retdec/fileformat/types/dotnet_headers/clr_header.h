/**
 * @file include/retdec/fileformat/types/dotnet_headers/clr_header.h
 * @brief Class for CLR header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_CLR_HEADER_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_CLR_HEADER_H

#include <cstdint>

namespace retdec {
namespace fileformat {

/**
 * CLR header
 */
class CLRHeader
{
	private:
		std::uint64_t headerSize;
		std::uint64_t majorRuntimeVersion;
		std::uint64_t minorRuntimeVersion;
		std::uint64_t metadataDirectoryAddress;
		std::uint64_t metadataDirectorySize;
		std::uint64_t flags;
		std::uint64_t entryPointToken;
		std::uint64_t resourcesAddress;
		std::uint64_t resourcesSize;
		std::uint64_t strongNameSignatureAddress;
		std::uint64_t strongNameSignatureSize;
		std::uint64_t codeManagerTableAddress;
		std::uint64_t codeManagerTableSize;
		std::uint64_t vTableFixupsDirectoryAddress;
		std::uint64_t vTableFixupsDirectorySize;
		std::uint64_t exportAddressTableAddress;
		std::uint64_t exportAddressTableSize;
		std::uint64_t precompileHeaderAddress;
		std::uint64_t precompileHeaderSize;
	public:
		/// @name Getters
		/// @{
		std::uint64_t getHeaderSize() const;
		std::uint64_t getMajorRuntimeVersion() const;
		std::uint64_t getMinorRuntimeVersion() const;
		std::uint64_t getMetadataDirectoryAddress() const;
		std::uint64_t getMetadataDirectorySize() const;
		std::uint64_t getFlags() const;
		std::uint64_t getEntryPointToken() const;
		std::uint64_t getResourcesAddress() const;
		std::uint64_t getResourcesSize() const;
		std::uint64_t getStrongNameSignatureAddress() const;
		std::uint64_t getStrongNameSignatureSize() const;
		std::uint64_t getCodeManagerTableAddress() const;
		std::uint64_t getCodeManagerTableSize() const;
		std::uint64_t getVTableFixupsDirectoryAddress() const;
		std::uint64_t getVTableFixupsDirectorySize() const;
		std::uint64_t getExportAddressTableAddress() const;
		std::uint64_t getExportAddressTableSize() const;
		std::uint64_t getPrecompileHeaderAddress() const;
		std::uint64_t getPrecompileHeaderSize() const;
		/// @}

		/// @name Setters
		/// @{
		void setHeaderSize(std::uint64_t clrHeaderSize);
		void setMajorRuntimeVersion(std::uint64_t clrMajorRuntimeVersion);
		void setMinorRuntimeVersion(std::uint64_t clrMinorRuntimeVersion);
		void setMetadataDirectoryAddress(std::uint64_t clrMetadataDirectoryAddress);
		void setMetadataDirectorySize(std::uint64_t clrMetadataDirectorySize);
		void setFlags(std::uint64_t clrFlags);
		void setEntryPointToken(std::uint64_t clrEntryPointToken);
		void setResourcesAddress(std::uint64_t clrResourcesAddress);
		void setResourcesSize(std::uint64_t clrResourcesSize);
		void setStrongNameSignatureAddress(std::uint64_t clrStrongNameSignatureAddress);
		void setStrongNameSignatureSize(std::uint64_t clrStrongNameSignatureSize);
		void setCodeManagerTableAddress(std::uint64_t clrCodeManagerTableAddress);
		void setCodeManagerTableSize(std::uint64_t clrCodeManagerTableSize);
		void setVTableFixupsDirectoryAddress(std::uint64_t clrVTableFixupsDirectoryAddress);
		void setVTableFixupsDirectorySize(std::uint64_t clrVTableFixupsDirectorySize);
		void setExportAddressTableAddress(std::uint64_t clrExportAddressTableAddress);
		void setExportAddressTableSize(std::uint64_t clrExportAddressTableSize);
		void setPrecompileHeaderAddress(std::uint64_t clrPrecompileHeaderAddress);
		void setPrecompileHeaderSize(std::uint64_t clrPrecompileHeaderSize);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
