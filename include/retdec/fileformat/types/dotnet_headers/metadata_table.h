/**
 * @file include/retdec/fileformat/types/dotnet_headers/metadata_table.h
 * @brief Class for metadata table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_METADATA_TABLE_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_METADATA_TABLE_H

#include <string>
#include <vector>

namespace retdec {
namespace fileformat {

enum class MetadataTableType
{
	Module = 0,
	TypeRef = 1,
	TypeDef = 2,
	FieldPtr = 3,
	Field = 4,
	MethodPtr = 5,
	MethodDef = 6,
	ParamPtr = 7,
	Param = 8,
	InterfaceImpl = 9,
	MemberRef = 10,
	Constant = 11,
	CustomAttribute = 12,
	FieldMarshal = 13,
	DeclSecurity = 14,
	ClassLayout = 15,
	FieldLayout = 16,
	StandAloneSig = 17,
	EventMap = 18,
	Event = 20,
	PropertyMap = 21,
	PropertyPtr = 22,
	Property = 23,
	MethodSemantics = 24,
	MethodImpl = 25,
	ModuleRef = 26,
	TypeSpec = 27,
	ImplMap = 28,
	FieldRVA = 29,
	ENCLog = 30,
	ENCMap = 31,
	Assembly = 32,
	AssemblyProcessor = 33,
	AssemblyOS = 34,
	AssemblyRef = 35,
	AssemblyRefProcessor = 36,
	AssemblyRefOS = 37,
	File = 38,
	ExportedType = 39,
	ManifestResource = 40,
	NestedClass = 41,
	GenericParam = 42,
	MethodSpec = 43,
	GenericParamContstraint = 44
};

/**
 * Base metadata table representation.
 */
class BaseMetadataTable
{
	private:
		MetadataTableType type;
		std::uint32_t size;
	protected:
		BaseMetadataTable(MetadataTableType tableType, std::uint32_t tableSize) : type(tableType), size(tableSize) {}
	public:
		virtual ~BaseMetadataTable() = default;

		/// @name Getters
		/// @{
		MetadataTableType getType() const { return type; }
		std::uint32_t getSize() const { return size; }
		/// @}
};

/**
 * Metadata table representation with rows of generic type.
 */
template <typename T>
class MetadataTable : public BaseMetadataTable
{
	private:
		std::vector<T> rows;
	public:
		MetadataTable(MetadataTableType tableType, std::uint32_t tableSize) : BaseMetadataTable(tableType, tableSize) {}

		/// @name Getters
		/// @{
		std::size_t getNumberOfRows() const { return rows.size(); }
		const T* getRow(std::size_t index) const { return index - 1 >= rows.size() ? nullptr : &rows[index - 1]; }
		auto begin() const { return rows.begin(); }
		auto end() const { return rows.end(); }
		/// @}

		/// @name Row methods
		/// @{
		template <typename U>
		void addRow(U&& row)
		{
			rows.push_back(std::forward<U>(row));
		}
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
