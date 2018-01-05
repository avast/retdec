/**
 * @file src/fileformat/types/dotnet_headers/metadata_tables.cpp
 * @brief Classes for metadata tables.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/dotnet_headers/metadata_tables.h"

namespace retdec {
namespace fileformat {

template <>
std::uint8_t BaseRecord::loadUInt<std::uint8_t>(const FileFormat* file, std::uint64_t& address)
{
	std::uint64_t val;
	if (!file->get1Byte(address, val))
		throw InvalidDotnetRecordError();

	address += 1;
	return val;
}

template <>
std::uint16_t BaseRecord::loadUInt<std::uint16_t>(const FileFormat* file, std::uint64_t& address)
{
	std::uint64_t val;
	if (!file->get2Byte(address, val))
		throw InvalidDotnetRecordError();

	address += 2;
	return val;
}

template <>
std::uint32_t BaseRecord::loadUInt<std::uint32_t>(const FileFormat* file, std::uint64_t& address)
{
	std::uint64_t val;
	if (!file->get4Byte(address, val))
		throw InvalidDotnetRecordError();

	address += 4;
	return val;
}

template <>
std::uint32_t BaseRecord::getIndexSize<StringStreamIndex>(const MetadataStream* stream)
{
	return stream->getStringStreamIndexSize();
}

template <>
std::uint32_t BaseRecord::getIndexSize<BlobStreamIndex>(const MetadataStream* stream)
{
	return stream->getBlobStreamIndexSize();
}

template <>
std::uint32_t BaseRecord::getIndexSize<GuidStreamIndex>(const MetadataStream* stream)
{
	return stream->getGuidStreamIndexSize();
}

template <>
std::uint32_t BaseRecord::getIndexSize<FieldTableIndex>(const MetadataStream* stream)
{
	auto table = stream->getMetadataTable(MetadataTableType::Field);
	return table && table->getSize() > 0xFFFF ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<MethodDefTableIndex>(const MetadataStream* stream)
{
	auto table = stream->getMetadataTable(MetadataTableType::MethodDef);
	return table && table->getSize() > 0xFFFF ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<ParamTableIndex>(const MetadataStream* stream)
{
	auto table = stream->getMetadataTable(MetadataTableType::Param);
	return table && table->getSize() > 0xFFFF ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<TypeDefTableIndex>(const MetadataStream* stream)
{
	auto table = stream->getMetadataTable(MetadataTableType::TypeDef);
	return table && table->getSize() > 0xFFFF ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<EventTableIndex>(const MetadataStream* stream)
{
	auto table = stream->getMetadataTable(MetadataTableType::Event);
	return table && table->getSize() > 0xFFFF ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<PropertyTableIndex>(const MetadataStream* stream)
{
	auto table = stream->getMetadataTable(MetadataTableType::Property);
	return table && table->getSize() > 0xFFFF ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<ModuleRefTableIndex>(const MetadataStream* stream)
{
	auto table = stream->getMetadataTable(MetadataTableType::ModuleRef);
	return table && table->getSize() > 0xFFFF ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<AssemblyRefTableIndex>(const MetadataStream* stream)
{
	auto table = stream->getMetadataTable(MetadataTableType::AssemblyRef);
	return table && table->getSize() > 0xFFFF ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<GenericParamTableIndex>(const MetadataStream* stream)
{
	auto table = stream->getMetadataTable(MetadataTableType::GenericParam);
	return table && table->getSize() > 0xFFFF ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<TypeDefOrRef>(const MetadataStream* stream)
{
	std::vector<const BaseMetadataTable*> tables;
	tables.reserve(3);

	tables.push_back(stream->getMetadataTable(MetadataTableType::TypeDef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::TypeRef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::TypeSpec));

	// 2 bits to encode which table is used, so we need to take out 2 bits from 0xFFFF
	return std::any_of(tables.begin(), tables.end(), [](auto t) { return t && t->getSize() > 0x3FFF; }) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<HasConstant>(const MetadataStream* stream)
{
	std::vector<const BaseMetadataTable*> tables;
	tables.reserve(3);

	tables.push_back(stream->getMetadataTable(MetadataTableType::Field));
	tables.push_back(stream->getMetadataTable(MetadataTableType::Param));
	tables.push_back(stream->getMetadataTable(MetadataTableType::Property));

	// 2 bits to encode which table is used, so we need to take out 2 bits from 0xFFFF
	return std::any_of(tables.begin(), tables.end(), [](auto t) { return t && t->getSize() > 0x3FFF; }) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<HasCustomAttribute>(const MetadataStream* stream)
{
	std::vector<const BaseMetadataTable*> tables;
	tables.reserve(21);

	tables.push_back(stream->getMetadataTable(MetadataTableType::MethodDef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::Field));
	tables.push_back(stream->getMetadataTable(MetadataTableType::TypeRef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::TypeDef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::Param));
	tables.push_back(stream->getMetadataTable(MetadataTableType::InterfaceImpl));
	tables.push_back(stream->getMetadataTable(MetadataTableType::MemberRef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::Module));
	tables.push_back(stream->getMetadataTable(MetadataTableType::DeclSecurity));
	tables.push_back(stream->getMetadataTable(MetadataTableType::Property));
	tables.push_back(stream->getMetadataTable(MetadataTableType::Event));
	tables.push_back(stream->getMetadataTable(MetadataTableType::StandAloneSig));
	tables.push_back(stream->getMetadataTable(MetadataTableType::ModuleRef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::TypeSpec));
	tables.push_back(stream->getMetadataTable(MetadataTableType::Assembly));
	tables.push_back(stream->getMetadataTable(MetadataTableType::AssemblyRef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::File));
	tables.push_back(stream->getMetadataTable(MetadataTableType::ExportedType));
	tables.push_back(stream->getMetadataTable(MetadataTableType::ManifestResource));
	tables.push_back(stream->getMetadataTable(MetadataTableType::GenericParam));
	tables.push_back(stream->getMetadataTable(MetadataTableType::GenericParamContstraint));
	tables.push_back(stream->getMetadataTable(MetadataTableType::MethodSpec));

	// 5 bits to encode which table is used, so we need to take out 5 bits from 0xFFFF
	return std::any_of(tables.begin(), tables.end(), [](auto t) { return t && t->getSize() > 0x07FF; }) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<HasFieldMarshal>(const MetadataStream* stream)
{
	auto fieldTable = stream->getMetadataTable(MetadataTableType::Field);
	auto paramTable = stream->getMetadataTable(MetadataTableType::Param);

	// 1 bit to encode which table is used, so we need to take out 1 bit from 0xFFFF
	return ((fieldTable && fieldTable->getSize() > 0x7FFF) ||
			(paramTable && paramTable->getSize() > 0x7FFF)) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<HasDeclSecurity>(const MetadataStream* stream)
{
	std::vector<const BaseMetadataTable*> tables;
	tables.reserve(3);

	tables.push_back(stream->getMetadataTable(MetadataTableType::TypeDef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::MethodDef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::Assembly));

	// 2 bits to encode which table is used, so we need to take out 2 bits from 0xFFFF
	return std::any_of(tables.begin(), tables.end(), [](auto t) { return t && t->getSize() > 0x3FFF; }) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<MemberRefParent>(const MetadataStream* stream)
{
	std::vector<const BaseMetadataTable*> tables;
	tables.reserve(5);

	tables.push_back(stream->getMetadataTable(MetadataTableType::TypeDef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::TypeRef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::ModuleRef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::MethodDef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::TypeSpec));

	// 3 bits to encode which table is used, so we need to take out 3 bits from 0xFFFF
	return std::any_of(tables.begin(), tables.end(), [](auto t) { return t && t->getSize() > 0x1FFF; }) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<HasSemantics>(const MetadataStream* stream)
{
	auto eventTable = stream->getMetadataTable(MetadataTableType::Event);
	auto propertyTable = stream->getMetadataTable(MetadataTableType::Property);

	// 1 bit to encode which table is used, so we need to take out 1 bit from 0xFFFF
	return ((eventTable && eventTable->getSize() > 0x7FFF) ||
			(propertyTable && propertyTable->getSize() > 0x7FFF)) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<MethodDefOrRef>(const MetadataStream* stream)
{
	auto methodDefTable = stream->getMetadataTable(MetadataTableType::MethodDef);
	auto memberRefTable = stream->getMetadataTable(MetadataTableType::MemberRef);

	// 1 bit to encode which table is used, so we need to take out 1 bit from 0xFFFF
	return ((methodDefTable && methodDefTable->getSize() > 0x7FFF) ||
			(memberRefTable && memberRefTable->getSize() > 0x7FFF)) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<MemberForwarded>(const MetadataStream* stream)
{
	auto fieldTable = stream->getMetadataTable(MetadataTableType::Field);
	auto methodDefTable = stream->getMetadataTable(MetadataTableType::MethodDef);

	// 1 bit to encode which table is used, so we need to take out 1 bit from 0xFFFF
	return ((fieldTable && fieldTable->getSize() > 0x7FFF) ||
			(methodDefTable && methodDefTable->getSize() > 0x7FFF)) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<Implementation>(const MetadataStream* stream)
{
	std::vector<const BaseMetadataTable*> tables;
	tables.reserve(3);

	tables.push_back(stream->getMetadataTable(MetadataTableType::File));
	tables.push_back(stream->getMetadataTable(MetadataTableType::AssemblyRef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::ExportedType));

	// 2 bits to encode which table is used, so we need to take out 2 bits from 0xFFFF
	return std::any_of(tables.begin(), tables.end(), [](auto t) { return t && t->getSize() > 0x3FFF; }) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<CustomAttributeType>(const MetadataStream* stream)
{
	std::vector<const BaseMetadataTable*> tables;
	tables.reserve(2);

	// 3 unused
	tables.push_back(stream->getMetadataTable(MetadataTableType::MethodDef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::MemberRef));

	// 3 bits to encode which table is used, so we need to take out 3 bits from 0xFFFF
	return std::any_of(tables.begin(), tables.end(), [](auto t) { return t && t->getSize() > 0x1FFF; }) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<ResolutionScope>(const MetadataStream* stream)
{
	std::vector<const BaseMetadataTable*> tables;
	tables.reserve(3);

	tables.push_back(stream->getMetadataTable(MetadataTableType::Module));
	tables.push_back(stream->getMetadataTable(MetadataTableType::ModuleRef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::AssemblyRef));
	tables.push_back(stream->getMetadataTable(MetadataTableType::TypeRef));

	// 2 bits to encode which table is used, so we need to take out 2 bits from 0xFFFF
	return std::any_of(tables.begin(), tables.end(), [](auto t) { return t && t->getSize() > 0x3FFF; }) ? 4 : 2;
}

template <>
std::uint32_t BaseRecord::getIndexSize<TypeDefOrMethodDef>(const MetadataStream* stream)
{
	auto fieldTable = stream->getMetadataTable(MetadataTableType::TypeDef);
	auto methodDefTable = stream->getMetadataTable(MetadataTableType::MethodDef);

	// 1 bit to encode which table is used, so we need to take out 1 bit from 0xFFFF
	return ((fieldTable && fieldTable->getSize() > 0x7FFF) ||
			(methodDefTable && methodDefTable->getSize() > 0x7FFF)) ? 4 : 2;
}

} // namespace fileformat
} // namespace retdec
