/**
 * @file src/fileinfo/file_information/file_information_types/dotnet_info.cpp
 * @brief Information about .NET.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/dotnet_info.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor.
 */
DotnetInfo::DotnetInfo() : used(false), runtimeVersion(), metadataHeaderAddress(0), metadataStream({0, 0}), stringStream({0, 0}),
	blobStream({0, 0}), guidStream({0, 0}), userStringStream({0, 0}), moduleVersionId(), typeLibId(), definedClassList(), importedClassList()
{
}

/**
 * Returns the runtime version.
 * @return Runtime version.
 */
const std::string& DotnetInfo::getRuntimeVersion() const
{
	return runtimeVersion;
}

/**
 * Returns the metadata header address in string representation with specified format.
 * @param format Format.
 * @return Metadata header address string.
 */
std::string DotnetInfo::getMetadataHeaderAddressStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(metadataHeaderAddress, format);
}

/**
 * Returns the metadata stream offset in string representation with specified format.
 * @param format Format.
 * @return Metadata stream offset string.
 */
std::string DotnetInfo::getMetadataStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(metadataStream.offset, format);
}

/**
 * Returns the metadata stream size in string representation with specified format.
 * @param format Format.
 * @return Metadata stream size string.
 */
std::string DotnetInfo::getMetadataStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(metadataStream.size, format);
}

/**
 * Returns the string stream offset in string representation with specified format.
 * @param format Format.
 * @return String stream offset string.
 */
std::string DotnetInfo::getStringStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(stringStream.offset, format);
}

/**
 * Returns the string stream size in string representation with specified format.
 * @param format Format.
 * @return String stream size string.
 */
std::string DotnetInfo::getStringStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(stringStream.size, format);
}

/**
 * Returns the blob stream offset in string representation with specified format.
 * @param format Format.
 * @return Blob stream offset string.
 */
std::string DotnetInfo::getBlobStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(blobStream.offset, format);
}

/**
 * Returns the blob stream size in string representation with specified format.
 * @param format Format.
 * @return Blob stream size string.
 */
std::string DotnetInfo::getBlobStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(blobStream.size, format);
}

/**
 * Returns the GUID stream offset in string representation with specified format.
 * @param format Format.
 * @return GUID stream offset string.
 */
std::string DotnetInfo::getGuidStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(guidStream.offset, format);
}

/**
 * Returns the GUID stream size in string representation with specified format.
 * @param format Format.
 * @return GUID stream size string.
 */
std::string DotnetInfo::getGuidStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(guidStream.size, format);
}

/**
 * Returns the user string stream offset in string representation with specified format.
 * @param format Format.
 * @return User string stream offset string.
 */
std::string DotnetInfo::getUserStringStreamOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(userStringStream.offset, format);
}

/**
 * Returns the user string stream size in string representation with specified format.
 * @param format Format.
 * @return User string stream size string.
 */
std::string DotnetInfo::getUserStringStreamSizeStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(userStringStream.size, format);
}

/**
 * Returns the module version ID.
 * @return Module version ID.
 */
const std::string& DotnetInfo::getModuleVersionId() const
{
	return moduleVersionId;
}

/**
 * Returns type lib ID.
 * @return Type lib ID.
 */
const std::string& DotnetInfo::getTypeLibId() const
{
	return typeLibId;
}

/**
 * Returns defined class list.
 * @return Defined classes.
 */
const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& DotnetInfo::getDefinedClassList() const
{
	return definedClassList;
}

/**
 * Returns imported class list.
 * @return Imported classes.
 */
const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& DotnetInfo::getImportedClassList() const
{
	return importedClassList;
}

/**
 * Sets whether .NET info is used.
 * @param set @c true if used, @c false otherwise.
 */
void DotnetInfo::setUsed(bool set)
{
	used = set;
}

/**
 * Sets the runtime version.
 * @param majorVersion Major runtime version.
 * @param minorVersion Minor runtime version.
 */
void DotnetInfo::setRuntimeVersion(std::uint64_t majorVersion, std::uint64_t minorVersion)
{
	std::stringstream ss;
	ss << majorVersion << '.' << minorVersion;
	runtimeVersion = ss.str();
}

/**
 * Sets the metadata header address.
 * @param address Metadata header address.
 */
void DotnetInfo::setMetadataHeaderAddress(std::uint64_t address)
{
	metadataHeaderAddress = address;
}

/**
 * Sets the metadata stream information.
 * @param offset Metadata stream offset.
 * @param size Metadata stream size.
 */
void DotnetInfo::setMetadataStreamInfo(std::uint64_t offset, std::uint64_t size)
{
	metadataStream.offset = offset;
	metadataStream.size = size;
}

/**
 * Sets the string stream information.
 * @param offset String stream offset.
 * @param size String stream size.
 */
void DotnetInfo::setStringStreamInfo(std::uint64_t offset, std::uint64_t size)
{
	stringStream.offset = offset;
	stringStream.size = size;
}

/**
 * Sets the blob stream information.
 * @param offset Blob stream offset.
 * @param size Blob stream size.
 */
void DotnetInfo::setBlobStreamInfo(std::uint64_t offset, std::uint64_t size)
{
	blobStream.offset = offset;
	blobStream.size = size;
}

/**
 * Sets the GUID stream information.
 * @param offset GUID stream offset.
 * @param size GUID stream size.
 */
void DotnetInfo::setGuidStreamInfo(std::uint64_t offset, std::uint64_t size)
{
	guidStream.offset = offset;
	guidStream.size = size;
}

/**
 * Sets the user string stream information.
 * @param offset User string stream offset.
 * @param size User string stream size.
 */
void DotnetInfo::setUserStringStreamInfo(std::uint64_t offset, std::uint64_t size)
{
	userStringStream.offset = offset;
	userStringStream.size = size;
}

/**
 * Sets the module version ID.
 * @param id Module version ID.
 */
void DotnetInfo::setModuleVersionId(const std::string& id)
{
	moduleVersionId = id;
}

/**
 * Sets the type lib ID.
 * @param id Type lib ID.
 */
void DotnetInfo::setTypeLibId(const std::string& id)
{
	typeLibId = id;
}

/**
 * Sets defined class list.
 * @param dotnetClassList Defined classes.
 */
void DotnetInfo::setDefinedClassList(const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& dotnetClassList)
{
	definedClassList = dotnetClassList;
}

/**
 * Sets imported class list.
 * @param dotnetClassList Imported classes.
 */
void DotnetInfo::setImportedClassList(const std::vector<std::shared_ptr<retdec::fileformat::DotnetClass>>& dotnetClassList)
{
	importedClassList = dotnetClassList;
}

/**
 * Checks whether .NET information are used.
 * @return @c true if used, otherwise @c false.
 */
bool DotnetInfo::isUsed() const
{
	return used;
}

/**
 * Checks whether .NET information contains metadata stream.
 * @return @c true if contains, otherwise @c false.
 */
bool DotnetInfo::hasMetadataStream() const
{
	return metadataStream.offset != 0 && metadataStream.size != 0;
}

/**
 * Checks whether .NET information contains string stream.
 * @return @c true if contains, otherwise @c false.
 */
bool DotnetInfo::hasStringStream() const
{
	return stringStream.offset != 0 && stringStream.size != 0;
}

/**
 * Checks whether .NET information contains blob stream.
 * @return @c true if contains, otherwise @c false.
 */
bool DotnetInfo::hasBlobStream() const
{
	return blobStream.offset != 0 && blobStream.size != 0;
}

/**
 * Checks whether .NET information contains GUID stream.
 * @return @c true if contains, otherwise @c false.
 */
bool DotnetInfo::hasGuidStream() const
{
	return guidStream.offset != 0 && guidStream.size != 0;
}

/**
 * Checks whether .NET information contains user string stream.
 * @return @c true if contains, otherwise @c false.
 */
bool DotnetInfo::hasUserStringStream() const
{
	return userStringStream.offset != 0 && userStringStream.size != 0;
}

/**
 * Checks whether .NET information contains type lib ID.
 * @return @c true if contains, otherwise @c false.
 */
bool DotnetInfo::hasTypeLibId() const
{
	return !typeLibId.empty();
}

} // namespace fileinfo
