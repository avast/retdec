/**
 * @file src/fileformat/types/dotnet_headers/metadata_stream.cpp
 * @brief Class for #~ Stream.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/dotnet_headers/metadata_stream.h"
#include "retdec/fileformat/types/dotnet_headers/metadata_tables.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor.
 * @param streamOffset Stream offset.
 * @param streamSize Stream size.
 */
MetadataStream::MetadataStream(std::uint64_t streamOffset, std::uint64_t streamSize) : Stream(StreamType::Metadata, streamOffset, streamSize)
{
}

/**
 * Returns the major version.
 * @return Major version.
 */
std::uint32_t MetadataStream::getMajorVersion() const
{
	return majorVersion;
}

/**
 * Returns the minor version.
 * @return Minor version.
 */
std::uint32_t MetadataStream::getMinorVersion() const
{
	return minorVersion;
}

/**
 * Returns the size (in bytes) of index into string stream. Can be only 2 or 4.
 * @return String stream index size.
 */
std::uint32_t MetadataStream::getStringStreamIndexSize() const
{
	return stringStreamIndexSize;
}

/**
 * Returns the size (in bytes) of index into guid stream. Can be only 2 or 4.
 * @return Guid stream index size.
 */
std::uint32_t MetadataStream::getGuidStreamIndexSize() const
{
	return guidStreamIndexSize;
}

/**
 * Returns the size (in bytes) of index into blob stream. Can be only 2 or 4.
 * @return Blob stream index size.
 */
std::uint32_t MetadataStream::getBlobStreamIndexSize() const
{
	return blobStreamIndexSize;
}

/**
 * Returns the metadata table for the specified type if it exists.
 * @param tableType Type of the metadata table.
 * @return Metadata table if exists, otherwise @c nullptr.
 */
BaseMetadataTable* MetadataStream::getMetadataTable(MetadataTableType tableType)
{
	auto itr = metadataTables.find(tableType);
	if (itr == metadataTables.end())
		return nullptr;

	return itr->second.get();
}

/**
 * Returns the metadata table for the specified type if it exists.
 * @param tableType Type of the metadata table.
 * @return Metadata table if exists, otherwise @c nullptr.
 */
const BaseMetadataTable* MetadataStream::getMetadataTable(MetadataTableType tableType) const
{
	auto itr = metadataTables.find(tableType);
	if (itr == metadataTables.end())
		return nullptr;

	return itr->second.get();
}

/**
 * Sets the major version.
 * @param streamMajorVersion Major version.
 */
void MetadataStream::setMajorVersion(std::uint32_t streamMajorVersion)
{
	majorVersion = streamMajorVersion;
}

/**
 * Sets the minor version.
 * @param streamMinorVersion Minor version.
 */
void MetadataStream::setMinorVersion(std::uint32_t streamMinorVersion)
{
	minorVersion = streamMinorVersion;
}

/**
 * Sets the size (in bytes) of index into string stream. Size is set to 4 if number greater than 2
 * is provided. Otherwise, it is set to 2.
 * @param indexSize Size of the index.
 */
void MetadataStream::setStringStreamIndexSize(std::uint32_t indexSize)
{
	stringStreamIndexSize = (indexSize > 2) ? 4 : 2;
}

/**
 * Sets the size (in bytes) of index into guid stream. Size is set to 4 if number greater than 2
 * is provided. Otherwise, it is set to 2.
 * @param indexSize Size of the index.
 */
void MetadataStream::setGuidStreamIndexSize(std::uint32_t indexSize)
{
	guidStreamIndexSize = (indexSize > 2) ? 4 : 2;
}

/**
 * Sets the size (in bytes) of index into blob stream. Size is set to 4 if number greater than 2
 * is provided. Otherwise, it is set to 2.
 * @param indexSize Size of the index.
 */
void MetadataStream::setBlobStreamIndexSize(std::uint32_t indexSize)
{
	blobStreamIndexSize = (indexSize > 2) ? 4 : 2;
}

/**
 * Adds new metadata table with the specified type and returns it. Each table can only be present once in the stream.
 * Every subsequent try to insert the table with type that already exists ends with failure and pointer
 * to the original table is returned instead.
 * @param tableType Type of the metadata table.
 * @param tableSize Size of the metadata table.
 * @return Inserted table.
 */
BaseMetadataTable* MetadataStream::addMetadataTable(MetadataTableType tableType, std::uint32_t tableSize)
{
	bool success = false;
	TypeToTableMap::iterator itr;
	switch (tableType)
	{
		case MetadataTableType::Module:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<DotnetModule>>(tableType, tableSize));
			break;
		case MetadataTableType::TypeRef:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<TypeRef>>(tableType, tableSize));
			break;
		case MetadataTableType::TypeDef:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<TypeDef>>(tableType, tableSize));
			break;
		case MetadataTableType::FieldPtr:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<FieldPtr>>(tableType, tableSize));
			break;
		case MetadataTableType::Field:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<Field>>(tableType, tableSize));
			break;
		case MetadataTableType::MethodPtr:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<MethodPtr>>(tableType, tableSize));
			break;
		case MetadataTableType::MethodDef:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<MethodDef>>(tableType, tableSize));
			break;
		case MetadataTableType::ParamPtr:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<ParamPtr>>(tableType, tableSize));
			break;
		case MetadataTableType::Param:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<Param>>(tableType, tableSize));
			break;
		case MetadataTableType::InterfaceImpl:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<InterfaceImpl>>(tableType, tableSize));
			break;
		case MetadataTableType::MemberRef:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<MemberRef>>(tableType, tableSize));
			break;
		case MetadataTableType::Constant:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<Constant>>(tableType, tableSize));
			break;
		case MetadataTableType::CustomAttribute:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<CustomAttribute>>(tableType, tableSize));
			break;
		case MetadataTableType::FieldMarshal:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<FieldMarshal>>(tableType, tableSize));
			break;
		case MetadataTableType::DeclSecurity:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<DeclSecurity>>(tableType, tableSize));
			break;
		case MetadataTableType::ClassLayout:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<ClassLayout>>(tableType, tableSize));
			break;
		case MetadataTableType::FieldLayout:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<FieldLayout>>(tableType, tableSize));
			break;
		case MetadataTableType::StandAloneSig:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<StandAloneSig>>(tableType, tableSize));
			break;
		case MetadataTableType::EventMap:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<EventMap>>(tableType, tableSize));
			break;
		case MetadataTableType::Event:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<Event>>(tableType, tableSize));
			break;
		case MetadataTableType::PropertyMap:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<PropertyMap>>(tableType, tableSize));
			break;
		case MetadataTableType::PropertyPtr:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<PropertyPtr>>(tableType, tableSize));
			break;
		case MetadataTableType::Property:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<Property>>(tableType, tableSize));
			break;
		case MetadataTableType::MethodSemantics:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<MethodSemantics>>(tableType, tableSize));
			break;
		case MetadataTableType::MethodImpl:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<MethodImpl>>(tableType, tableSize));
			break;
		case MetadataTableType::ModuleRef:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<ModuleRef>>(tableType, tableSize));
			break;
		case MetadataTableType::TypeSpec:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<TypeSpec>>(tableType, tableSize));
			break;
		case MetadataTableType::ImplMap:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<ImplMap>>(tableType, tableSize));
			break;
		case MetadataTableType::FieldRVA:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<FieldRVA>>(tableType, tableSize));
			break;
		case MetadataTableType::ENCLog:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<ENCLog>>(tableType, tableSize));
			break;
		case MetadataTableType::ENCMap:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<ENCMap>>(tableType, tableSize));
			break;
		case MetadataTableType::Assembly:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<Assembly>>(tableType, tableSize));
			break;
		case MetadataTableType::AssemblyProcessor:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<AssemblyProcessor>>(tableType, tableSize));
			break;
		case MetadataTableType::AssemblyOS:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<AssemblyOS>>(tableType, tableSize));
			break;
		case MetadataTableType::AssemblyRef:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<AssemblyRef>>(tableType, tableSize));
			break;
		case MetadataTableType::AssemblyRefProcessor:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<AssemblyRefProcessor>>(tableType, tableSize));
			break;
		case MetadataTableType::AssemblyRefOS:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<AssemblyRefOS>>(tableType, tableSize));
			break;
		case MetadataTableType::File:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<File>>(tableType, tableSize));
			break;
		case MetadataTableType::ExportedType:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<ExportedType>>(tableType, tableSize));
			break;
		case MetadataTableType::ManifestResource:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<ManifestResource>>(tableType, tableSize));
			break;
		case MetadataTableType::NestedClass:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<NestedClass>>(tableType, tableSize));
			break;
		case MetadataTableType::GenericParam:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<GenericParam>>(tableType, tableSize));
			break;
		case MetadataTableType::MethodSpec:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<MethodSpec>>(tableType, tableSize));
			break;
		case MetadataTableType::GenericParamContstraint:
			std::tie(itr, success) = metadataTables.emplace(tableType, std::make_unique<MetadataTable<GenericParamContstraint>>(tableType, tableSize));
			break;
		default:
			return nullptr;
	}

	return success ? itr->second.get() : nullptr;
}

/**
 * Checks whether the stream contains table of a given type.
 * @param tableType Type of the metadata table.
 * @return @c true if present, otherwise @c false.
 */
bool MetadataStream::hasTable(MetadataTableType tableType) const
{
	return retdec::utils::mapHasKey(metadataTables, tableType);
}

} // namespace fileformat
} // namespace retdec
