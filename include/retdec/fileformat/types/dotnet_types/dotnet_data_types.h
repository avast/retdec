/**
 * @file include/retdec/fileformat/types/dotnet_types/dotnet_data_types.h
 * @brief Classes for .NET data types.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_DATA_TYPES_H
#define RETDEC_FILEFORMAT_TYPES_DOTNET_TYPES_DOTNET_DATA_TYPES_H

#include <memory>
#include <unordered_map>
#include <vector>

#include "retdec/fileformat/types/dotnet_headers/metadata_tables.h"

namespace retdec {
namespace fileformat {

class DotnetClass;

enum class ElementType
{
	End            = 0x00,
	Void           = 0x01,
	Boolean        = 0x02,
	Char           = 0x03,
	Int8           = 0x04,
	UInt8          = 0x05,
	Int16          = 0x06,
	UInt16         = 0x07,
	Int32          = 0x08,
	UInt32         = 0x09,
	Int64          = 0x0A,
	UInt64         = 0x0B,
	Float32        = 0x0C,
	Float64        = 0x0D,
	String         = 0x0E,
	Ptr            = 0x0F,
	ByRef          = 0x10,
	ValueType      = 0x11,
	Class          = 0x12,
	GenericVar     = 0x13,
	Array          = 0x14,
	GenericInst    = 0x15,
	TypedByRef     = 0x16,
	IntPtr         = 0x18,
	UIntPtr        = 0x19,
	FnPtr          = 0x1B,
	Object         = 0x1C,
	SzArray        = 0x1D,
	GenericMVar    = 0x1E,
	CModRequired   = 0x1F,
	CModOptional   = 0x20,
	Internal       = 0x21,
	Modifier       = 0x40,
	Sentinel       = 0x41,
	Pinned         = 0x45,
	MetaType       = 0x50,
	BoxedObject    = 0x51,
	CustomField    = 0x53,
	CustomProperty = 0x54,
	CustomEnum     = 0x55
};

class DotnetDataTypeBase
{
	protected:
		ElementType type;
	public:
		DotnetDataTypeBase(ElementType elementType) : type(elementType) {}
		virtual ~DotnetDataTypeBase() = default;

		/// @name Virtual methods
		/// @{
		virtual std::string getText() const = 0;
		/// @}

		/// @name Getters
		/// @{
		ElementType getElementType() const { return type; }
		/// @}
};

template <ElementType Type>
class DotnetDataType : public DotnetDataTypeBase
{
	public:
		DotnetDataType() : DotnetDataTypeBase(Type) {}

		virtual std::string getText() const override
		{
			static const std::unordered_map<ElementType, std::string, retdec::utils::EnumClassKeyHash> typeNames =
			{
				{ ElementType::Void,       "void"           },
				{ ElementType::Boolean,    "bool"           },
				{ ElementType::Char,       "char"           },
				{ ElementType::Int8,       "sbyte"          },
				{ ElementType::UInt8,      "byte"           },
				{ ElementType::Int16,      "short"          },
				{ ElementType::UInt16,     "ushort"         },
				{ ElementType::Int32,      "int"            },
				{ ElementType::UInt32,     "uint"           },
				{ ElementType::Int64,      "long"           },
				{ ElementType::UInt64,     "ulong"          },
				{ ElementType::Float32,    "float"          },
				{ ElementType::Float64,    "double"         },
				{ ElementType::String,     "string"         },
				{ ElementType::IntPtr,     "IntPtr"         },
				{ ElementType::UIntPtr,    "UIntPtr"        },
				{ ElementType::Object,     "object"         },
				{ ElementType::TypedByRef, "TypedReference" }
			};

			auto itr = typeNames.find(Type);
			if (itr == typeNames.end())
				return {};

			return itr->second;
		}
};

template <>
class DotnetDataType<ElementType::Ptr> : public DotnetDataTypeBase
{
	private:
		std::unique_ptr<DotnetDataTypeBase> pointed;
	public:
		DotnetDataType(std::unique_ptr<DotnetDataTypeBase>&& pointedType)
			: DotnetDataTypeBase(ElementType::Ptr), pointed(std::move(pointedType)) {}

		virtual std::string getText() const override;

		const DotnetDataTypeBase* getPointedType() const { return pointed.get(); }
};

template <>
class DotnetDataType<ElementType::ByRef> : public DotnetDataTypeBase
{
	private:
		std::unique_ptr<DotnetDataTypeBase> referred;
	public:
		DotnetDataType(std::unique_ptr<DotnetDataTypeBase>&& referredType)
			: DotnetDataTypeBase(ElementType::ByRef), referred(std::move(referredType)) {}

		virtual std::string getText() const override;

		const DotnetDataTypeBase* getReferredType() const { return referred.get(); }
};

template <>
class DotnetDataType<ElementType::ValueType> : public DotnetDataTypeBase
{
	private:
		const DotnetClass* type;
	public:
		DotnetDataType(const DotnetClass* classType)
			: DotnetDataTypeBase(ElementType::ValueType), type(classType) {}

		virtual std::string getText() const override;

		const DotnetClass* getType() const { return type; }
};

template <>
class DotnetDataType<ElementType::Class> : public DotnetDataTypeBase
{
	private:
		const DotnetClass* type;
	public:
		DotnetDataType(const DotnetClass* classType)
			: DotnetDataTypeBase(ElementType::Class), type(classType) {}

		virtual std::string getText() const override;

		const DotnetClass* getType() const { return type; }
};

template <>
class DotnetDataType<ElementType::GenericVar> : public DotnetDataTypeBase
{
	private:
		const std::string* genericVar;
	public:
		DotnetDataType(const std::string* varGenericVar)
			: DotnetDataTypeBase(ElementType::GenericVar), genericVar(varGenericVar) {}

		virtual std::string getText() const override;

		const std::string& getGenericVariable() const { return *genericVar; }
};

template <>
class DotnetDataType<ElementType::Array> : public DotnetDataTypeBase
{
	private:
		std::unique_ptr<DotnetDataTypeBase> underlyingType;
		std::vector<std::pair<std::int64_t, std::int64_t>> dimensions;
	public:
		DotnetDataType(std::unique_ptr<DotnetDataTypeBase>&& arrayUnderlyingType, std::vector<std::pair<std::int64_t, std::int64_t>>&& arrayDimensions)
			: DotnetDataTypeBase(ElementType::Array), underlyingType(std::move(arrayUnderlyingType)), dimensions(std::move(arrayDimensions)) {}

		virtual std::string getText() const override;

		const DotnetDataTypeBase* getUnderlyingType() const { return underlyingType.get(); }
		const std::vector<std::pair<std::int64_t, std::int64_t>>& getDimensions() const { return dimensions; }
};

template <>
class DotnetDataType<ElementType::GenericInst> : public DotnetDataTypeBase
{
	private:
		std::unique_ptr<DotnetDataTypeBase> type;
		std::vector<std::unique_ptr<DotnetDataTypeBase>> genericTypes;
	public:
		DotnetDataType(std::unique_ptr<DotnetDataTypeBase>&& instType, std::vector<std::unique_ptr<DotnetDataTypeBase>>&& instGenericTypes)
			: DotnetDataTypeBase(ElementType::GenericInst), type(std::move(instType)), genericTypes(std::move(instGenericTypes)) {}

		virtual std::string getText() const override;

		const DotnetDataTypeBase* getType() const { return type.get(); }
		std::size_t getGenericCount() const { return genericTypes.size(); }
		const std::vector<std::unique_ptr<DotnetDataTypeBase>>& getGenericTypes() const { return genericTypes; }
};

template <>
class DotnetDataType<ElementType::FnPtr> : public DotnetDataTypeBase
{
	private:
		std::unique_ptr<DotnetDataTypeBase> returnType;
		std::vector<std::unique_ptr<DotnetDataTypeBase>> paramTypes;
	public:
		DotnetDataType(std::unique_ptr<DotnetDataTypeBase>&& fnReturnType, std::vector<std::unique_ptr<DotnetDataTypeBase>>&& fnParamTypes)
			: DotnetDataTypeBase(ElementType::FnPtr), returnType(std::move(fnReturnType)), paramTypes(std::move(fnParamTypes)) {}

		virtual std::string getText() const override;

		const DotnetDataTypeBase* getReturnType() const { return returnType.get(); }
		const std::vector<std::unique_ptr<DotnetDataTypeBase>>& getParameterTypes() const { return paramTypes; }
};

template <>
class DotnetDataType<ElementType::SzArray> : public DotnetDataTypeBase
{
	private:
		std::unique_ptr<DotnetDataTypeBase> underlyingType;
	public:
		DotnetDataType(std::unique_ptr<DotnetDataTypeBase>&& arrayUnderlyingType)
			: DotnetDataTypeBase(ElementType::SzArray), underlyingType(std::move(arrayUnderlyingType)) {}

		virtual std::string getText() const override;

		const DotnetDataTypeBase* getUnderlyingType() const { return underlyingType.get(); }
};

template <>
class DotnetDataType<ElementType::GenericMVar> : public DotnetDataTypeBase
{
	private:
		const std::string* genericVar;
	public:
		DotnetDataType(const std::string* mvarGenericVar)
			: DotnetDataTypeBase(ElementType::GenericMVar), genericVar(mvarGenericVar) {}

		virtual std::string getText() const override;

		const std::string& getGenericVariable() const { return *genericVar; }
};

template <>
class DotnetDataType<ElementType::CModRequired> : public DotnetDataTypeBase
{
	private:
		const DotnetClass* modifier;
		std::unique_ptr<DotnetDataTypeBase> type;
	public:
		DotnetDataType(const DotnetClass* typeModifier, std::unique_ptr<DotnetDataTypeBase>&& modifierType)
			: DotnetDataTypeBase(ElementType::CModRequired), modifier(typeModifier), type(std::move(modifierType)) {}

		virtual std::string getText() const override;

		const DotnetClass* getModifier() const { return modifier; }
		const DotnetDataTypeBase* getType() const { return type.get(); }
};

template <>
class DotnetDataType<ElementType::CModOptional> : public DotnetDataTypeBase
{
	private:
		const DotnetClass* modifier;
		std::unique_ptr<DotnetDataTypeBase> type;
	public:
		DotnetDataType(const DotnetClass* typeModifier, std::unique_ptr<DotnetDataTypeBase>&& modifierType)
			: DotnetDataTypeBase(ElementType::CModRequired), modifier(typeModifier), type(std::move(modifierType)) {}

		virtual std::string getText() const override;

		const DotnetClass* getModifier() const { return modifier; }
		const DotnetDataTypeBase* getType() const { return type.get(); }
};

using DotnetDataTypeEnd = DotnetDataType<ElementType::End>;
using DotnetDataTypeVoid = DotnetDataType<ElementType::Void>;
using DotnetDataTypeBoolean = DotnetDataType<ElementType::Boolean>;
using DotnetDataTypeChar = DotnetDataType<ElementType::Char>;
using DotnetDataTypeInt8 = DotnetDataType<ElementType::Int8>;
using DotnetDataTypeUInt8 = DotnetDataType<ElementType::UInt8>;
using DotnetDataTypeInt16 = DotnetDataType<ElementType::Int16>;
using DotnetDataTypeUInt16 = DotnetDataType<ElementType::UInt16>;
using DotnetDataTypeInt32 = DotnetDataType<ElementType::Int32>;
using DotnetDataTypeUInt32 = DotnetDataType<ElementType::UInt32>;
using DotnetDataTypeInt64 = DotnetDataType<ElementType::Int64>;
using DotnetDataTypeUInt64 = DotnetDataType<ElementType::UInt64>;
using DotnetDataTypeFloat32 = DotnetDataType<ElementType::Float32>;
using DotnetDataTypeFloat64 = DotnetDataType<ElementType::Float64>;
using DotnetDataTypeString = DotnetDataType<ElementType::String>;
using DotnetDataTypePtr = DotnetDataType<ElementType::Ptr>;
using DotnetDataTypeByRef = DotnetDataType<ElementType::ByRef>;
using DotnetDataTypeValueType = DotnetDataType<ElementType::ValueType>;
using DotnetDataTypeClass = DotnetDataType<ElementType::Class>;
using DotnetDataTypeGenericVar = DotnetDataType<ElementType::GenericVar>;
using DotnetDataTypeArray = DotnetDataType<ElementType::Array>;
using DotnetDataTypeGenericInst = DotnetDataType<ElementType::GenericInst>;
using DotnetDataTypeTypedByRef = DotnetDataType<ElementType::TypedByRef>;
using DotnetDataTypeIntPtr = DotnetDataType<ElementType::IntPtr>;
using DotnetDataTypeUIntPtr = DotnetDataType<ElementType::UIntPtr>;
using DotnetDataTypeFnPtr = DotnetDataType<ElementType::FnPtr>;
using DotnetDataTypeObject = DotnetDataType<ElementType::Object>;
using DotnetDataTypeSzArray = DotnetDataType<ElementType::SzArray>;
using DotnetDataTypeGenericMVar = DotnetDataType<ElementType::GenericMVar>;
using DotnetDataTypeCModRequired = DotnetDataType<ElementType::CModRequired>;
using DotnetDataTypeCModOptional = DotnetDataType<ElementType::CModOptional>;
//using DotnetDataTypeInternal = DotnetDataType<ElementType::Internal>;
//using DotnetDataTypeModifier = DotnetDataType<ElementType::Modifier>;
//using DotnetDataTypeSentinel = DotnetDataType<ElementType::Sentinel>;
//using DotnetDataTypePinned = DotnetDataType<ElementType::Pinned>;
//using DotnetDataTypeMetaType = DotnetDataType<ElementType::MetaType>;
//using DotnetDataTypeBoxedObject = DotnetDataType<ElementType::BoxedObject>;
//using DotnetDataTypeCustomField = DotnetDataType<ElementType::CustomField>;
//using DotnetDataTypeCustomProperty = DotnetDataType<ElementType::CustomProperty>;
//using DotnetDataTypeCustomEnum = DotnetDataType<ElementType::CustomEnum>;

} // namespace fileformat
} // namespace retdec

#endif
