/**
 * @file src/fileformat/types/dotnet_headers/clr_header.cpp
 * @brief Class for CLR header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/dotnet_headers/clr_header.h"

namespace retdec {
namespace fileformat {

/**
 * Returns the size of the header.
 * @return Size of the header.
 */
std::uint64_t CLRHeader::getHeaderSize() const
{
	return headerSize;
}

/**
 * Returns the major runtime version.
 * @return Major runtime version.
 */
std::uint64_t CLRHeader::getMajorRuntimeVersion() const
{
	return majorRuntimeVersion;
}

/**
 * Returns the minor runtime version.
 * @return Minor runtime version.
 */
std::uint64_t CLRHeader::getMinorRuntimeVersion() const
{
	return minorRuntimeVersion;
}

/**
 * Returns the metadata directory address.
 * @return Metadata directory address.
 */
std::uint64_t CLRHeader::getMetadataDirectoryAddress() const
{
	return metadataDirectoryAddress;
}

/**
 * Returns the metadata directory size.
 * @return Metadata directory size.
 */
std::uint64_t CLRHeader::getMetadataDirectorySize() const
{
	return metadataDirectorySize;
}

/**
 * Returns the flags.
 * @return The flags.
 */
std::uint64_t CLRHeader::getFlags() const
{
	return flags;
}

/**
 * Returns the entry point token.
 * @return Entry point token.
 */
std::uint64_t CLRHeader::getEntryPointToken() const
{
	return entryPointToken;
}

/**
 * Returns the resources address.
 * @return Resources address.
 */
std::uint64_t CLRHeader::getResourcesAddress() const
{
	return resourcesAddress;
}

/**
 * Returns the resources size.
 * @return Resources size.
 */
std::uint64_t CLRHeader::getResourcesSize() const
{
	return resourcesSize;
}

/**
 * Returns the strong name signature address.
 * @return String name signature access.
 */
std::uint64_t CLRHeader::getStrongNameSignatureAddress() const
{
	return strongNameSignatureAddress;
}

/**
 * Returns the strong name signature size.
 * @return String name signature size.
 */
std::uint64_t CLRHeader::getStrongNameSignatureSize() const
{
	return strongNameSignatureSize;
}

/**
 * Returns the code manager table address.
 * @return Code manager table address.
 */
std::uint64_t CLRHeader::getCodeManagerTableAddress() const
{
	return codeManagerTableAddress;
}

/**
 * Returns the code manager table size.
 * @return Code manager table size.
 */
std::uint64_t CLRHeader::getCodeManagerTableSize() const
{
	return codeManagerTableSize;
}

/**
 * Returns the v-table fixups directory address.
 * @return V-table fixups directory address.
 */
std::uint64_t CLRHeader::getVTableFixupsDirectoryAddress() const
{
	return vTableFixupsDirectoryAddress;
}

/**
 * Returns the v-table fixups directory size.
 * @return V-table fixups directory size.
 */
std::uint64_t CLRHeader::getVTableFixupsDirectorySize() const
{
	return vTableFixupsDirectorySize;
}

/**
 * Returns the export address table address.
 * @return Export address table address.
 */
std::uint64_t CLRHeader::getExportAddressTableAddress() const
{
	return exportAddressTableAddress;
}

/**
 * Returns the export address table size.
 * @return Export address table size.
 */
std::uint64_t CLRHeader::getExportAddressTableSize() const
{
	return exportAddressTableSize;
}

/**
 * Returns the precompile header address.
 * @return Precompile header address.
 */
std::uint64_t CLRHeader::getPrecompileHeaderAddress() const
{
	return precompileHeaderAddress;
}

/**
 * Returns the precompile header size.
 * @return Precompile header size.
 */
std::uint64_t CLRHeader::getPrecompileHeaderSize() const
{
	return precompileHeaderSize;
}

/**
 * Sets the header size.
 * @param clrHeaderSize Header size.
 */
void CLRHeader::setHeaderSize(std::uint64_t clrHeaderSize)
{
	headerSize = clrHeaderSize;
}

/**
 * Sets the major runtime version.
 * @param clrMajorRuntimeVersion Major runtime version.
 */
void CLRHeader::setMajorRuntimeVersion(std::uint64_t clrMajorRuntimeVersion)
{
	majorRuntimeVersion = clrMajorRuntimeVersion;
}

/**
 * Sets the minor runtime version.
 * @param clrMinorRuntimeVersion Minor runtime version.
 */
void CLRHeader::setMinorRuntimeVersion(std::uint64_t clrMinorRuntimeVersion)
{
	minorRuntimeVersion = clrMinorRuntimeVersion;
}

/**
 * Sets the metadata directory address.
 * @param clrMetadataDirectoryAddress Metadata directory address.
 */
void CLRHeader::setMetadataDirectoryAddress(std::uint64_t clrMetadataDirectoryAddress)
{
	metadataDirectoryAddress = clrMetadataDirectoryAddress;
}

/**
 * Sets the metadata directory size.
 * @param clrMetadataDirectorySize Metadata directory size.
 */
void CLRHeader::setMetadataDirectorySize(std::uint64_t clrMetadataDirectorySize)
{
	metadataDirectorySize = clrMetadataDirectorySize;
}

/**
 * Sets the flags.
 * @param clrFlags The flags.
 */
void CLRHeader::setFlags(std::uint64_t clrFlags)
{
	flags = clrFlags;
}

/**
 * Sets the entry point token.
 * @param clrEntryPointToken The entry point token.
 */
void CLRHeader::setEntryPointToken(std::uint64_t clrEntryPointToken)
{
	entryPointToken = clrEntryPointToken;
}

/**
 * Sets the resources address.
 * @param clrResourcesAddress The resources address.
 */
void CLRHeader::setResourcesAddress(std::uint64_t clrResourcesAddress)
{
	resourcesAddress = clrResourcesAddress;
}

/**
 * Sets the resources size.
 * @param clrResourcesSize The resources size.
 */
void CLRHeader::setResourcesSize(std::uint64_t clrResourcesSize)
{
	resourcesSize = clrResourcesSize;
}

/**
 * Sets the strong name signature address.
 * @param clrStrongNameSignatureAddress The strong name signature address.
 */
void CLRHeader::setStrongNameSignatureAddress(std::uint64_t clrStrongNameSignatureAddress)
{
	strongNameSignatureAddress = clrStrongNameSignatureAddress;
}

/**
 * Sets the strong name signature size.
 * @param clrStrongNameSignatureSize The strong name signature size.
 */
void CLRHeader::setStrongNameSignatureSize(std::uint64_t clrStrongNameSignatureSize)
{
	strongNameSignatureSize = clrStrongNameSignatureSize;
}

/**
 * Sets the code manager table address.
 * @param clrCodeManagerTableAddress The code manager table address.
 */
void CLRHeader::setCodeManagerTableAddress(std::uint64_t clrCodeManagerTableAddress)
{
	codeManagerTableAddress = clrCodeManagerTableAddress;
}

/**
 * Sets the code manager table size.
 * @param clrCodeManagerTableSize The code manager table size.
 */
void CLRHeader::setCodeManagerTableSize(std::uint64_t clrCodeManagerTableSize)
{
	codeManagerTableSize = clrCodeManagerTableSize;
}

/**
 * Sets the v-table fixups directory address.
 * @param clrVTableFixupsDirectoryAddress The v-table fixups directory address.
 */
void CLRHeader::setVTableFixupsDirectoryAddress(std::uint64_t clrVTableFixupsDirectoryAddress)
{
	vTableFixupsDirectoryAddress = clrVTableFixupsDirectoryAddress;
}

/**
 * Sets the v-table fixups directory size.
 * @param clrVTableFixupsDirectorySize The v-table fixups directory size.
 */
void CLRHeader::setVTableFixupsDirectorySize(std::uint64_t clrVTableFixupsDirectorySize)
{
	vTableFixupsDirectorySize = clrVTableFixupsDirectorySize;
}

/**
 * Sets the export address table address.
 * @param clrExportAddressTableAddress The export address table address.
 */
void CLRHeader::setExportAddressTableAddress(std::uint64_t clrExportAddressTableAddress)
{
	exportAddressTableAddress = clrExportAddressTableAddress;
}

/**
 * Sets the export address table size.
 * @param clrExportAddressTableSize The export address table size.
 */
void CLRHeader::setExportAddressTableSize(std::uint64_t clrExportAddressTableSize)
{
	exportAddressTableSize = clrExportAddressTableSize;
}

/**
 * Sets the precompile header address.
 * @param clrPrecompileHeaderAddress The precompile header address.
 */
void CLRHeader::setPrecompileHeaderAddress(std::uint64_t clrPrecompileHeaderAddress)
{
	precompileHeaderAddress = clrPrecompileHeaderAddress;
}

/**
 * Sets the precompile header size.
 * @param clrPrecompileHeaderSize The precompile header size.
 */
void CLRHeader::setPrecompileHeaderSize(std::uint64_t clrPrecompileHeaderSize)
{
	precompileHeaderSize = clrPrecompileHeaderSize;
}

} // namespace fileformat
} // namespace retdec
