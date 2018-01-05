/**
 * @file include/retdec/fileformat/types/dotnet_headers/metadata_tables.h
 * @brief Classes for metadata tables.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_METADATA_TABLES_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_HEADERS_METADATA_TABLES_H

#include <cstdint>
#include <type_traits>

#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/types/dotnet_headers/metadata_stream.h"

namespace retdec {
namespace fileformat {

//
// Flags enumerations
//

enum TypeDefFlags
{
	// Visibility flags
	TypeVisibilityMask     = 0x00000007,
	TypeNotPublic          = 0x00000000,
	TypePublic             = 0x00000001,
	TypeNestedPublic       = 0x00000002,
	TypeNestedPrivate      = 0x00000003,
	TypeNestedFamily       = 0x00000004,
	TypeNestedAssembly     = 0x00000005,
	TypeNestedFamANDAssem  = 0x00000006,
	TypeNestedFamORAssem   = 0x00000007,
	// Layout flags - we do not care
	// ClassSemantics flags
	TypeClassSemanticsMask = 0x00000020,
	TypeClass              = 0x00000000,
	TypeInterface          = 0x00000020,
	// special semantics
	TypeClassAbstract      = 0x00000080,
	TypeClassSealed        = 0x00000100,
	TypeClassSpecialName   = 0x00000400,
	// StringFormat flags
	TypeStringFormatMask   = 0x00030000,
	TypeAnsiClass          = 0x00000000,
	TypeUnicodeClass       = 0x00010000,
	TypeAutoClass          = 0x00020000,
	TypeCustomFormatClass  = 0x00030000
};

enum FieldFlags
{
	// Field access flags
	FieldAccessMask         = 0x0007,
	FieldCompilerControlled = 0x0000,
	FieldPrivate            = 0x0001,
	FieldFamANDAssem        = 0x0002,
	FieldAssembly           = 0x0003,
	FieldFamily             = 0x0004,
	FieldFamORAssem         = 0x0005,
	FieldPublic             = 0x0006,
	// special
	FieldStatic             = 0x0010,
	FieldInitOnly           = 0x0020,
	FieldLiteral            = 0x0040,
	FieldNotSerialized      = 0x0080,
	FieldSpecialName        = 0x0200
	// Interop attributes - we do not care
	// Additional flags - we do not care
};

enum MethodFlags
{
	// Member access flags
	MethodMemberAccessMask   = 0x0007,
	MethodCompilerControlled = 0x0000,
	MethodPrivate            = 0x0001,
	MethodFamANDAssem        = 0x0002,
	MethodAssem              = 0x0003,
	MethodFamily             = 0x0004,
	MethodFamORAssem         = 0x0005,
	MethodPublic             = 0x0006,
	// special flags
	MethodStatic             = 0x0010,
	MethodFinal              = 0x0020,
	MethodVirtual            = 0x0040,
	MethodHideBySig          = 0x0080,
	// Vtable layout mask - we do not care
	// additional special flags
	MethodStrict             = 0x0200,
	MethodAbstract           = 0x0400,
	MethodSpecialName        = 0x0800
	// Interop attributes - we do not care
	// Additional flags - we do not care
};

enum ParamFlags
{
	ParamIn                  = 0x0001,
	ParamOut                 = 0x0002,
	ParamOptional            = 0x0010,
	ParamHasDefault          = 0x1000,
	ParamHasFieldMarshal     = 0x2000
};

//
// Index types
//

struct Index
{
	protected:
		std::uint64_t index = 0;

		constexpr std::uint64_t maskForBits(std::uint64_t bits) const { return (1ULL << bits) - 1; }
	public:
		std::uint64_t getRawIndex() const { return index; }
		virtual std::uint64_t getIndex() const = 0;

		void setIndex(std::uint64_t newIndex) { index = newIndex; }
};

struct CompoundIndex : public Index
{
	public:
		virtual bool getTable(MetadataTableType& result) const = 0;
};

struct StringStreamIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct BlobStreamIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct GuidStreamIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct FieldTableIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct MethodDefTableIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct ParamTableIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct TypeDefTableIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct EventTableIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct PropertyTableIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct ModuleRefTableIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct AssemblyRefTableIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct GenericParamTableIndex : public Index
{
	virtual std::uint64_t getIndex() const override { return index; }
};

struct TypeDefOrRef : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 2; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(2))
		{
			case 0:
				result = MetadataTableType::TypeDef;
				break;
			case 1:
				result = MetadataTableType::TypeRef;
				break;
			case 2:
				result = MetadataTableType::TypeSpec;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct HasConstant : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 2; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(2))
		{
			case 0:
				result = MetadataTableType::Field;
				break;
			case 1:
				result = MetadataTableType::Param;
				break;
			case 2:
				result = MetadataTableType::Property;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct HasCustomAttribute : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 5; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(5))
		{
			case 0:
				result = MetadataTableType::MethodDef;
				break;
			case 1:
				result = MetadataTableType::Field;
				break;
			case 2:
				result = MetadataTableType::TypeRef;
				break;
			case 3:
				result = MetadataTableType::TypeDef;
				break;
			case 4:
				result = MetadataTableType::Param;
				break;
			case 5:
				result = MetadataTableType::InterfaceImpl;
				break;
			case 6:
				result = MetadataTableType::MemberRef;
				break;
			case 7:
				result = MetadataTableType::Module;
				break;
			case 8:
				result = MetadataTableType::DeclSecurity;
				break;
			case 9:
				result = MetadataTableType::Property;
				break;
			case 10:
				result = MetadataTableType::Event;
				break;
			case 11:
				result = MetadataTableType::StandAloneSig;
				break;
			case 12:
				result = MetadataTableType::ModuleRef;
				break;
			case 13:
				result = MetadataTableType::TypeSpec;
				break;
			case 14:
				result = MetadataTableType::Assembly;
				break;
			case 15:
				result = MetadataTableType::AssemblyRef;
				break;
			case 16:
				result = MetadataTableType::File;
				break;
			case 17:
				result = MetadataTableType::ExportedType;
				break;
			case 18:
				result = MetadataTableType::ManifestResource;
				break;
			case 19:
				result = MetadataTableType::GenericParam;
				break;
			case 20:
				result = MetadataTableType::GenericParamContstraint;
				break;
			case 21:
				result = MetadataTableType::MethodSpec;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct HasFieldMarshal : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 1; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(1))
		{
			case 0:
				result = MetadataTableType::Field;
				break;
			case 1:
				result = MetadataTableType::Param;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct HasDeclSecurity : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 2; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(2))
		{
			case 0:
				result = MetadataTableType::TypeDef;
				break;
			case 1:
				result = MetadataTableType::MethodDef;
				break;
			case 2:
				result = MetadataTableType::Assembly;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct MemberRefParent : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 3; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(3))
		{
			case 0:
				result = MetadataTableType::TypeDef;
				break;
			case 1:
				result = MetadataTableType::TypeRef;
				break;
			case 2:
				result = MetadataTableType::ModuleRef;
				break;
			case 3:
				result = MetadataTableType::MethodDef;
				break;
			case 4:
				result = MetadataTableType::TypeSpec;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct HasSemantics : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 1; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(1))
		{
			case 0:
				result = MetadataTableType::Event;
				break;
			case 1:
				result = MetadataTableType::Property;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct MethodDefOrRef : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 1; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(1))
		{
			case 0:
				result = MetadataTableType::MethodDef;
				break;
			case 1:
				result = MetadataTableType::MemberRef;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct MemberForwarded : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 1; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(1))
		{
			case 0:
				result = MetadataTableType::Field;
				break;
			case 1:
				result = MetadataTableType::MethodDef;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct Implementation : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 2; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(2))
		{
			case 0:
				result = MetadataTableType::File;
				break;
			case 1:
				result = MetadataTableType::AssemblyRef;
				break;
			case 2:
				result = MetadataTableType::ExportedType;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct CustomAttributeType : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 3; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(3))
		{
			case 2:
				result = MetadataTableType::MethodDef;
				break;
			case 3:
				result = MetadataTableType::MemberRef;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct ResolutionScope : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 2; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(2))
		{
			case 0:
				result = MetadataTableType::Module;
				break;
			case 1:
				result = MetadataTableType::ModuleRef;
				break;
			case 2:
				result = MetadataTableType::AssemblyRef;
				break;
			case 3:
				result = MetadataTableType::TypeRef;
				break;
			default:
				return false;
		}

		return true;
	}
};

struct TypeDefOrMethodDef : public CompoundIndex
{
	virtual std::uint64_t getIndex() const override { return index >> 1; }
	virtual bool getTable(MetadataTableType& result) const override
	{
		switch (index & maskForBits(1))
		{
			case 0:
				result = MetadataTableType::TypeDef;
				break;
			case 1:
				result = MetadataTableType::MethodDef;
				break;
			default:
				return false;
		}

		return true;
	}
};

//
// Table records
//

class InvalidDotnetRecordError : public std::exception
{
public:
	InvalidDotnetRecordError() noexcept {}
	InvalidDotnetRecordError(const InvalidDotnetRecordError&) noexcept = default;

	virtual const char* what() const noexcept { return "Invalid .NET record"; }
};

/**
 * Base record type
 */
struct BaseRecord
{
	virtual ~BaseRecord() = default;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) = 0;

protected:
	template <typename T>
	T loadUInt(const FileFormat* file, std::uint64_t& address);

	template <typename T>
	std::uint32_t getIndexSize(const MetadataStream* stream);

	template <typename T>
	T loadIndex(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address)
	{
		std::uint64_t val;
		if (getIndexSize<T>(stream) == 2)
		{
			if (!file->get2Byte(address, val))
				throw InvalidDotnetRecordError();

			address += 2;
		}
		else
		{
			if (!file->get4Byte(address, val))
				throw InvalidDotnetRecordError();

			address += 4;
		}

		T index;
		index.setIndex(val);
		return index;
	}
};

template <> std::uint8_t BaseRecord::loadUInt<std::uint8_t>(const FileFormat* file, std::uint64_t& address);
template <> std::uint16_t BaseRecord::loadUInt<std::uint16_t>(const FileFormat* file, std::uint64_t& address);
template <> std::uint32_t BaseRecord::loadUInt<std::uint32_t>(const FileFormat* file, std::uint64_t& address);

struct DotnetModule : public BaseRecord
{
	std::uint16_t generation;
	StringStreamIndex name;
	GuidStreamIndex mvId;
	GuidStreamIndex encId;
	GuidStreamIndex encBaseId;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		generation = loadUInt<std::uint16_t>(file, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
		mvId = loadIndex<GuidStreamIndex>(file, stream, address);
		encId = loadIndex<GuidStreamIndex>(file, stream, address);
		encBaseId = loadIndex<GuidStreamIndex>(file, stream, address);
	}
};

struct TypeRef : public BaseRecord
{
	ResolutionScope resolutionScope;
	StringStreamIndex typeName;
	StringStreamIndex typeNamespace;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		resolutionScope = loadIndex<ResolutionScope>(file, stream, address);
		typeName = loadIndex<StringStreamIndex>(file, stream, address);
		typeNamespace = loadIndex<StringStreamIndex>(file, stream, address);
	}
};

struct TypeDef : public BaseRecord
{
	std::uint32_t flags;
	StringStreamIndex typeName;
	StringStreamIndex typeNamespace;
	TypeDefOrRef extends;
	FieldTableIndex fieldList;
	MethodDefTableIndex methodList;

	bool isNonPublic() const { return (flags & TypeVisibilityMask) == TypeNotPublic; }
	bool isPublic() const { return (flags & TypeVisibilityMask) == TypePublic; }
	bool isNestedPublic() const { return (flags & TypeVisibilityMask) == TypeNestedPublic; }
	bool isNestedPrivate() const { return (flags & TypeVisibilityMask) == TypeNestedPrivate; }
	bool isNestedProtected() const { return (flags & TypeVisibilityMask) == TypeNestedFamily; }
	bool isClass() const { return (flags & TypeClassSemanticsMask) == TypeClass; }
	bool isInterface() const { return (flags & TypeClassSemanticsMask) == TypeInterface; }
	bool isAbstract() const { return flags & TypeClassAbstract; }
	bool isSealed() const { return flags & TypeClassSealed; }
	bool hasAnsiName() const { return (flags & TypeStringFormatMask) == TypeAnsiClass; }
	bool hasUnicodeName() const { return (flags & TypeStringFormatMask) == TypeUnicodeClass; }

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		flags = loadUInt<std::uint32_t>(file, address);
		typeName = loadIndex<StringStreamIndex>(file, stream, address);
		typeNamespace = loadIndex<StringStreamIndex>(file, stream, address);
		extends = loadIndex<TypeDefOrRef>(file, stream, address);
		fieldList = loadIndex<FieldTableIndex>(file, stream, address);
		methodList = loadIndex<MethodDefTableIndex>(file, stream, address);
	}
};

struct FieldPtr : public BaseRecord
{
	FieldTableIndex field;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		field = loadIndex<FieldTableIndex>(file, stream, address);
	}
};

struct Field : public BaseRecord
{
	std::uint16_t flags;
	StringStreamIndex name;
	BlobStreamIndex signature;

	bool isPublic() const { return (flags & FieldAccessMask) == FieldPublic; }
	bool isProtected() const { return (flags & FieldAccessMask) == FieldFamily; }
	bool isPrivate() const { return (flags & FieldAccessMask) == FieldPrivate; }
	bool isStatic() const { return flags & FieldStatic; }

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		flags = loadUInt<std::uint16_t>(file, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
		signature = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct MethodPtr : public BaseRecord
{
	MethodDefTableIndex method;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		method = loadIndex<MethodDefTableIndex>(file, stream, address);
	}
};

struct MethodDef : public BaseRecord
{
	std::uint32_t rva;
	std::uint16_t implFlags;
	std::uint16_t flags;
	StringStreamIndex name;
	BlobStreamIndex signature;
	ParamTableIndex paramList;

	bool isPublic() const { return (flags & MethodMemberAccessMask) == MethodPublic; }
	bool isPrivate() const { return (flags & MethodMemberAccessMask) == MethodPrivate; }
	bool isProtected() const { return (flags & MethodMemberAccessMask) == MethodFamily; }
	bool isStatic() const { return flags & MethodStatic; }
	bool isVirtual() const { return flags & MethodVirtual; }
	bool isFinal() const { return flags & MethodFinal; }
	bool isAbstract() const { return flags & MethodAbstract; }

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		rva = loadUInt<std::uint32_t>(file, address);
		implFlags = loadUInt<std::uint16_t>(file, address);
		flags = loadUInt<std::uint16_t>(file, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
		signature = loadIndex<BlobStreamIndex>(file, stream, address);
		paramList = loadIndex<ParamTableIndex>(file, stream, address);
	}
};

struct ParamPtr : public BaseRecord
{
	ParamTableIndex param;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		param = loadIndex<ParamTableIndex>(file, stream, address);
	}
};

struct Param : public BaseRecord
{
	std::uint16_t flags;
	std::uint16_t sequence;
	StringStreamIndex name;

	bool isOut() const { return flags & ParamOut; }

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		flags = loadUInt<std::uint16_t>(file, address);
		sequence = loadUInt<std::uint16_t>(file, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
	}
};

struct InterfaceImpl : public BaseRecord
{
	TypeDefTableIndex classType;
	TypeDefOrRef interfaceType;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		classType = loadIndex<TypeDefTableIndex>(file, stream, address);
		interfaceType = loadIndex<TypeDefOrRef>(file, stream, address);
	}
};

struct MemberRef : public BaseRecord
{
	MemberRefParent classType;
	StringStreamIndex name;
	BlobStreamIndex signature;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		classType = loadIndex<MemberRefParent>(file, stream, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
		signature = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct Constant : public BaseRecord
{
	std::uint8_t type;
	HasConstant parent;
	BlobStreamIndex value;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		type = loadUInt<std::uint8_t>(file, address);
		address += 1; // 1-byte always 0 padding
		parent = loadIndex<HasConstant>(file, stream, address);
		value = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct CustomAttribute : public BaseRecord
{
	HasCustomAttribute parent;
	CustomAttributeType type;
	BlobStreamIndex value;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		parent = loadIndex<HasCustomAttribute>(file, stream, address);
		type = loadIndex<CustomAttributeType>(file, stream, address);
		value = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct FieldMarshal : public BaseRecord
{
	HasFieldMarshal parent;
	BlobStreamIndex nativeType;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		parent = loadIndex<HasFieldMarshal>(file, stream, address);
		nativeType = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct DeclSecurity : public BaseRecord
{
	std::uint16_t action;
	HasDeclSecurity parent;
	BlobStreamIndex permissionSet;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		action = loadUInt<std::uint16_t>(file, address);
		parent = loadIndex<HasDeclSecurity>(file, stream, address);
		permissionSet = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct ClassLayout : public BaseRecord
{
	std::uint16_t packingSize;
	std::uint32_t classSize;
	TypeDefTableIndex parent;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		packingSize = loadUInt<std::uint16_t>(file, address);
		classSize = loadUInt<std::uint32_t>(file, address);
		parent = loadIndex<TypeDefTableIndex>(file, stream, address);
	}
};

struct FieldLayout : public BaseRecord
{
	std::uint32_t offset;
	FieldTableIndex field;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		offset = loadUInt<std::uint32_t>(file, address);
		field = loadIndex<FieldTableIndex>(file, stream, address);
	}
};

struct StandAloneSig : public BaseRecord
{
	BlobStreamIndex signature;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		signature = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct EventMap : public BaseRecord
{
	TypeDefTableIndex parent;
	EventTableIndex eventList;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		parent = loadIndex<TypeDefTableIndex>(file, stream, address);
		eventList = loadIndex<EventTableIndex>(file, stream, address);
	}
};

struct Event : public BaseRecord
{
	std::uint16_t eventFlags;
	StringStreamIndex name;
	TypeDefOrRef eventType;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		eventFlags = loadUInt<std::uint16_t>(file, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
		eventType = loadIndex<TypeDefOrRef>(file, stream, address);
	}
};

struct PropertyPtr : public BaseRecord
{
	PropertyTableIndex property;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		property = loadIndex<PropertyTableIndex>(file, stream, address);
	}
};

struct PropertyMap : public BaseRecord
{
	TypeDefTableIndex parent;
	PropertyTableIndex propertyList;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		parent = loadIndex<TypeDefTableIndex>(file, stream, address);
		propertyList = loadIndex<PropertyTableIndex>(file, stream, address);
	}
};

struct Property : public BaseRecord
{
	std::uint16_t flags;
	StringStreamIndex name;
	BlobStreamIndex type;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		flags = loadUInt<std::uint16_t>(file, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
		type = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct MethodSemantics : public BaseRecord
{
	std::uint16_t semantics;
	MethodDefTableIndex method;
	HasSemantics association;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		semantics = loadUInt<std::uint16_t>(file, address);
		method = loadIndex<MethodDefTableIndex>(file, stream, address);
		association = loadIndex<HasSemantics>(file, stream, address);
	}
};

struct MethodImpl : public BaseRecord
{
	TypeDefTableIndex classType;
	MethodDefOrRef methodBody;
	MethodDefOrRef methodDeclaration;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		classType = loadIndex<TypeDefTableIndex>(file, stream, address);
		methodBody = loadIndex<MethodDefOrRef>(file, stream, address);
		methodDeclaration = loadIndex<MethodDefOrRef>(file, stream, address);
	}
};

struct ModuleRef : public BaseRecord
{
	StringStreamIndex name;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		name = loadIndex<StringStreamIndex>(file, stream, address);
	}
};

struct TypeSpec : public BaseRecord
{
	BlobStreamIndex signature;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		signature = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct ImplMap : public BaseRecord
{
	std::uint16_t mappingFlags;
	MemberForwarded memberForwarded;
	StringStreamIndex importName;
	ModuleRefTableIndex importScope;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		mappingFlags = loadUInt<std::uint16_t>(file, address);
		memberForwarded = loadIndex<MemberForwarded>(file, stream, address);
		importName = loadIndex<StringStreamIndex>(file, stream, address);
		importScope = loadIndex<ModuleRefTableIndex>(file, stream, address);
	}
};

struct FieldRVA : public BaseRecord
{
	std::uint32_t rva;
	FieldTableIndex field;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		rva = loadUInt<std::uint32_t>(file, address);
		field = loadIndex<FieldTableIndex>(file, stream, address);
	}
};

struct ENCLog : public BaseRecord
{
	std::uint32_t token;
	std::uint32_t funcCode;

	virtual void load(const FileFormat* file, const MetadataStream*, std::uint64_t& address) override
	{
		token = loadUInt<std::uint32_t>(file, address);
		funcCode = loadUInt<std::uint32_t>(file, address);
	}
};

struct ENCMap : public BaseRecord
{
	std::uint32_t token;

	virtual void load(const FileFormat* file, const MetadataStream*, std::uint64_t& address) override
	{
		token = loadUInt<std::uint32_t>(file, address);
	}
};

struct Assembly : public BaseRecord
{
	std::uint32_t hashAlgId;
	std::uint16_t majorVersion;
	std::uint16_t minorVersion;
	std::uint16_t buildNumber;
	std::uint16_t revisionNumber;
	std::uint32_t flags;
	BlobStreamIndex publicKey;
	StringStreamIndex name;
	StringStreamIndex culture;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		hashAlgId = loadUInt<std::uint32_t>(file, address);
		majorVersion = loadUInt<std::uint16_t>(file, address);
		minorVersion = loadUInt<std::uint16_t>(file, address);
		buildNumber = loadUInt<std::uint16_t>(file, address);
		revisionNumber = loadUInt<std::uint16_t>(file, address);
		flags = loadUInt<std::uint32_t>(file, address);
		publicKey = loadIndex<BlobStreamIndex>(file, stream, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
		culture = loadIndex<StringStreamIndex>(file, stream, address);
	}
};

struct AssemblyProcessor : public BaseRecord
{
	std::uint32_t processor;

	virtual void load(const FileFormat* file, const MetadataStream*, std::uint64_t& address) override
	{
		processor = loadUInt<std::uint32_t>(file, address);
	}
};

struct AssemblyOS : public BaseRecord
{
	std::uint32_t osPlatformId;
	std::uint32_t osMajorVersion;
	std::uint32_t osMinorVersion;

	virtual void load(const FileFormat* file, const MetadataStream*, std::uint64_t& address) override
	{
		osPlatformId = loadUInt<std::uint32_t>(file, address);
		osMajorVersion = loadUInt<std::uint32_t>(file, address);
		osMinorVersion = loadUInt<std::uint32_t>(file, address);
	}
};

struct AssemblyRef : public BaseRecord
{
	std::uint16_t majorVersion;
	std::uint16_t minorVersion;
	std::uint16_t buildNumber;
	std::uint16_t revisionNumber;
	std::uint32_t flags;
	BlobStreamIndex publicKeyOrToken;
	StringStreamIndex name;
	StringStreamIndex culture;
	BlobStreamIndex hashValue;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		majorVersion = loadUInt<std::uint16_t>(file, address);
		minorVersion = loadUInt<std::uint16_t>(file, address);
		buildNumber = loadUInt<std::uint16_t>(file, address);
		revisionNumber = loadUInt<std::uint16_t>(file, address);
		flags = loadUInt<std::uint32_t>(file, address);
		publicKeyOrToken = loadIndex<BlobStreamIndex>(file, stream, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
		culture = loadIndex<StringStreamIndex>(file, stream, address);
		hashValue = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct AssemblyRefProcessor : public BaseRecord
{
	std::uint32_t processor;
	AssemblyRefTableIndex assemblyRef;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		processor = loadUInt<std::uint32_t>(file, address);
		assemblyRef = loadIndex<AssemblyRefTableIndex>(file, stream, address);
	}
};

struct AssemblyRefOS : public BaseRecord
{
	std::uint32_t osPlatformId;
	std::uint32_t osMajorVersion;
	std::uint32_t osMinorVersion;
	AssemblyRefTableIndex assemblyRef;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		osPlatformId = loadUInt<std::uint32_t>(file, address);
		osMajorVersion = loadUInt<std::uint32_t>(file, address);
		osMinorVersion = loadUInt<std::uint32_t>(file, address);
		assemblyRef = loadIndex<AssemblyRefTableIndex>(file, stream, address);
	}
};

struct File : public BaseRecord
{
	std::uint32_t flags;
	StringStreamIndex name;
	BlobStreamIndex hashValue;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		flags = loadUInt<std::uint32_t>(file, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
		hashValue = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct ExportedType : public BaseRecord
{
	std::uint32_t flags;
	std::uint32_t typeDefId;
	StringStreamIndex typeName;
	StringStreamIndex typeNamespace;
	Implementation implementation;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		flags = loadUInt<std::uint32_t>(file, address);
		typeDefId = loadUInt<std::uint32_t>(file, address);
		typeName = loadIndex<StringStreamIndex>(file, stream, address);
		typeNamespace = loadIndex<StringStreamIndex>(file, stream, address);
		implementation = loadIndex<Implementation>(file, stream, address);
	}
};

struct ManifestResource : public BaseRecord
{
	std::uint32_t offset;
	std::uint32_t flags;
	StringStreamIndex name;
	Implementation implementation;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		offset = loadUInt<std::uint32_t>(file, address);
		flags = loadUInt<std::uint32_t>(file, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
		implementation = loadIndex<Implementation>(file, stream, address);
	}
};

struct NestedClass : public BaseRecord
{
	TypeDefTableIndex nestedClass;
	TypeDefTableIndex enclosingClass;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		nestedClass = loadIndex<TypeDefTableIndex>(file, stream, address);
		enclosingClass = loadIndex<TypeDefTableIndex>(file, stream, address);
	}
};

struct GenericParam : public BaseRecord
{
	std::uint16_t number;
	std::uint16_t flags;
	TypeDefOrMethodDef owner;
	StringStreamIndex name;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		number = loadUInt<std::uint16_t>(file, address);
		flags = loadUInt<std::uint16_t>(file, address);
		owner = loadIndex<TypeDefOrMethodDef>(file, stream, address);
		name = loadIndex<StringStreamIndex>(file, stream, address);
	}
};

struct MethodSpec : public BaseRecord
{
	MethodDefOrRef method;
	BlobStreamIndex instantiation;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		method = loadIndex<MethodDefOrRef>(file, stream, address);
		instantiation = loadIndex<BlobStreamIndex>(file, stream, address);
	}
};

struct GenericParamContstraint : public BaseRecord
{
	GenericParamTableIndex owner;
	TypeDefOrRef constraint;

	virtual void load(const FileFormat* file, const MetadataStream* stream, std::uint64_t& address) override
	{
		owner = loadIndex<GenericParamTableIndex>(file, stream, address);
		constraint = loadIndex<TypeDefOrRef>(file, stream, address);
	}
};

} // namespace fileformat
} // namespace retdec

#endif
