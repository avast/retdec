/**
 * @file include/retdec/dwarfparser/dwarf_types.h
 * @brief Declaration of classes representing data types.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DWARFPARSER_DWARF_TYPES_H
#define RETDEC_DWARFPARSER_DWARF_TYPES_H

#include <cstdlib>
#include <map>
#include <vector>

#include <libdwarf/libdwarf.h>

#include "retdec/dwarfparser/dwarf_base.h"
#include "retdec/dwarfparser/dwarf_locations.h"
#include "retdec/dwarfparser/dwarf_utils.h"

namespace retdec {
namespace dwarfparser {

// Extern forward declarations.
class DwarfFile;
class DwarfVarContainer;

// Locale forward declarations.
class DwarfType;
class DwarfArrayType;
class DwarfEnumType;
class DwarfStructType;
class DwarfUnionType;
class DwarfTypedefType;
class DwarfFunctionType;
class DwarfTypeContainer;

class DwarfModifierType;
class DwarfConstType;
class DwarfPackedType;
class DwarfPointerType;
class DwarfReferenceType;
class DwarfRestrictType;
class DwarfRValReferenceType;
class DwarfSharedType;
class DwarfVolatileType;

// Macros for type identification.
#define DEC_DWARF_TYPE_TID static const DwarfType::eDataType TID
#define DEF_DWARF_TYPE_TID(CL, ID) const DwarfType::eDataType CL::TID = ID

/**
 * @class DwarfType
 * @brief Base data type, others are derived from it.
 */
class DwarfType : public DwarfBaseElement
{
	public:
		/**
		 * @brief Types of data types.
		 */
		enum eDataType
		{
			BASE,               ///< Basic data type.
			// Composite types.
			ARRAY,              ///< Data type is an array.
			ENUMERATION,        ///< Data type is an enumeration.
			FUNCTION,           ///< Data type is a function.
			STRUCTURE,          ///< Data type is a structure.
			TYPEDEF,            ///< Data type is a typedef.
			UNION,              ///< Data type is an union.
			CLASS,              ///< Data type is a class.
			// Modifier types.
			CONSTANT,           ///< C or C++ const qualified type.
			PACKED,             ///< Pascal or Ada packed type.
			POINTER,            ///< Pointer to an object of the type being modified.
			REFERENCE,          ///< C++ (lvalue) reference to an object ot the type being modified.
			RESTRICT,           ///< C restrict qualified type.
			RVAL_REFERENCE,     ///< C++ rvalue to an object ot the type being modified.
			SHARED,             ///< UPC shared qualified type.
			VOLATILE            ///< C or C++ volatile qualified type.
		};

		/**
		 * @brief Mapping of eDataType enum to strings.
		 *        Entries must be in the same order as in eDataType.
		 */
		static const char * eDataTypeString[];

	public:
		DwarfType(DwarfTypeContainer *prnt, Dwarf_Off o);

		virtual void load(AttrProcessor &ap);
		virtual void dump() const override;
		virtual std::string toLLVMString() const;
		virtual std::string toLLVMStringIdentified() const;
		Dwarf_Unsigned getBitSize() const;
		Dwarf_Unsigned getByteSize() const;
		DwarfType *getUnderlyingType();
		std::string dumpNameAndOffset() const;

		//
		// All data types are referenced as pointers to this base class.
		// TODO: not sure about these, i might be dangerous to use strict T::TID.
		//
		template<typename T> bool constructed_as()
		{
			return (dynamic_cast<T*>(this) != nullptr ? true : false);
		}
		template<typename T> T* leaf_cast()
		{
			return dynamic_cast<T*>(this);
		}

	public:
		DEC_DWARF_TYPE_TID;
		Dwarf_Unsigned bitSize;  ///< Bit size of data type.
		Dwarf_Unsigned encoding; ///< DWARF Encoding of base type (valid only for base types).
		eDataType dataType;      ///< Type of data type.
};

/**
 * @class DwarfArrayType
 * @brief Array data type.
 */
class DwarfArrayType : public DwarfType
{
	public:
		using dimension_it = std::vector<Dwarf_Unsigned>::iterator;
		using const_dimension_it = std::vector<Dwarf_Unsigned>::const_iterator;

	public:
		DwarfArrayType(DwarfTypeContainer *prnt, Dwarf_Off o);
		virtual void load(AttrProcessor &ap) override;
		virtual void dump() const override;
		virtual std::string toLLVMString() const override;
		virtual std::string toLLVMStringIdentified() const override;
		void addDimension(Dwarf_Unsigned d);
		void updateSize();
		std::size_t dimensionCount();

		DEC_DWARF_TYPE_TID;
		DwarfType *baseType;                         ///< Pointer to data type object of array elements.
		std::vector<Dwarf_Unsigned> dimensionBounds; ///< Array bounds. bound(int[3]) = 2.
};

/**
 * @class DwarfEnumType
 * @brief Enumeration data type.
 */
class DwarfEnumType : public DwarfType
{
	public:
		/**
		 * @brief Structure representing single enumeration member.
		 */
		struct EnumMember
		{
			std::string name; ///< Name of member.
			Dwarf_Signed constVal; ///< Constant value of member.
		};

		using member_t = std::vector<EnumMember>         ;
		using member_const_it_t = member_t::const_iterator   ;

	public:
		DwarfEnumType(DwarfTypeContainer *prnt, Dwarf_Off o);
		virtual void load(AttrProcessor &ap) override;
		virtual void dump() const override;
		virtual std::string toLLVMString() const override;
		virtual std::string toLLVMStringIdentified() const override;
		void addMember(EnumMember m);
		std::size_t memberCount();

		DEC_DWARF_TYPE_TID;
		DwarfType *baseType; ///< Pointer to data type of elements. C is not using it.
		member_t members;    ///< Vector of enumeration members.
};

/**
 * @class DwarfStructType
 * @brief Structure data type.
 */
class DwarfStructType : public DwarfType
{
	public:
		/**
		 * @brief Structure representing single structure member.
		 */
		class StructMember
		{
			public:
				StructMember() :
					type(nullptr), location(nullptr), bitSize(EMPTY_UNSIGNED), bitOffset(EMPTY_UNSIGNED), access(DW_ACCESS_public)
				{}

				void setAccess(Dwarf_Unsigned a)
					{ access = (a==DW_ACCESS_public || a==DW_ACCESS_protected || a==DW_ACCESS_private) ? a : DW_ACCESS_public; }
				Dwarf_Unsigned getAccess() const
					{ return access; }

				std::string name;            ///< Name of this member.
				DwarfType *type;             ///< Pointer to data type of this member.
				DwarfLocationDesc* location; ///< Location of the member.
				Dwarf_Unsigned bitSize;      ///< Bit size of bit field.
				Dwarf_Unsigned bitOffset;    ///< Bit offset of bit field.

			private:
				Dwarf_Unsigned access;       ///< Member accessibility.
		};

	public:
		DwarfStructType(DwarfTypeContainer *prnt, Dwarf_Off o);
		~DwarfStructType();
		virtual void load(AttrProcessor &ap) override;
		virtual void dump() const override;
		virtual std::string toLLVMString() const override;
		virtual std::string toLLVMStringIdentified() const override;
		void addMember(StructMember m);
		void addStaticMember(StructMember m);
		std::size_t memberCount();

		DEC_DWARF_TYPE_TID;
		std::vector<StructMember> members; ///< Vector of structure members.
		std::vector<StructMember> staticMembers;
};

/**
 * @class DwarfStructType
 * @brief Structure data type.
 */
class DwarfUnionType : public DwarfStructType
{
	public:
		DwarfUnionType(DwarfTypeContainer *prnt, Dwarf_Off o);
		DEC_DWARF_TYPE_TID;
};

/**
 * @class DwarfClassType
 */
class DwarfClassType : public DwarfStructType
{
	public:
		/**
		 * @brief Class represents inheritance relationship.
		 */
		class InheritanceMember
		{
			public:
				InheritanceMember(DwarfClassType *b, Dwarf_Unsigned a) :
					base(b),
					access((a==DW_ACCESS_public || a==DW_ACCESS_protected || a==DW_ACCESS_private) ? a : DW_ACCESS_public)
				{

				}

				DwarfClassType *getBase() const  { return base;   }
				Dwarf_Unsigned getAccess() const { return access; }

			private:
				DwarfClassType *base;
				Dwarf_Unsigned access;
		};

	public:
		DwarfClassType(DwarfTypeContainer *prnt, Dwarf_Off o);
		virtual void load(AttrProcessor &ap) override;
		virtual void dump() const override;
		DEC_DWARF_TYPE_TID;

		std::vector<DwarfFunction*> memberFunctions;
		std::vector<InheritanceMember> baseClasses;
};

/**
 * @class DwarfTypedefType
 * @brief Typedef data type.
 */
class DwarfTypedefType : public DwarfType
{
	public:
		DwarfTypedefType(DwarfTypeContainer *prnt, Dwarf_Off o);
		virtual void load(AttrProcessor &ap) override;
		virtual void dump() const override;
		virtual std::string toLLVMString() const override;
		virtual std::string toLLVMStringIdentified() const override;

		DEC_DWARF_TYPE_TID;
		DwarfType *baseType; ///< Pointer to original data type od this typedef.
};

/**
 * @class DwarfFunctionType
 * @brief Function (subroutine) data type.
 */
class DwarfFunctionType : public DwarfType
{
	public:
		DwarfFunctionType(DwarfTypeContainer *prnt, Dwarf_Off o);
		~DwarfFunctionType();
		virtual void load(AttrProcessor &ap) override;
		virtual void dump() const override;
		virtual std::string toLLVMString() const override;
		virtual std::string toLLVMStringIdentified() const override;

		bool hasParams();
		DwarfVarContainer *getParams();
		const DwarfVarContainer *getParams() const;
		std::size_t getParamCount() const;

		DEC_DWARF_TYPE_TID;
		DwarfType *type;             ///< Data type of function.
		DwarfFunction *func;         ///< Real function of this type. This may be filled using name of the type.
		                             ///< Name is usually not set, and this is not used at the moment.
		bool isVariadic;             ///< If true, function has variadic argument following arguments stored in m_params.

	private:
		DwarfVarContainer *m_params; ///< Container with parameters of this function.
};

/**
 * @class DwarfModifierType
 * @brief Base class for all data type modifier classes.
 */
class DwarfModifierType : public DwarfType
{
	public:
		DwarfModifierType(DwarfTypeContainer *prnt, Dwarf_Off o);
		virtual void load(AttrProcessor &ap) override;
		virtual void dump() const override;
		virtual std::string toLLVMString() const override;
		virtual std::string toLLVMStringIdentified() const override;

		DwarfType *baseType; ///< Pointer to data type this pointer is pointing to.
};

/**
 * @class DwarfConstType
 * @brief Constant data type modifier.
 */
class DwarfConstType : public DwarfModifierType
{
	public:
		DwarfConstType(DwarfTypeContainer *prnt, Dwarf_Off o);
		DEC_DWARF_TYPE_TID;
};

/**
 * @class DwarfPackedType
 * @brief Packed data type modifier.
 */
class DwarfPackedType : public DwarfModifierType
{
	public:
		DwarfPackedType(DwarfTypeContainer *prnt, Dwarf_Off o);
		DEC_DWARF_TYPE_TID;
};

/**
 * @class DwarfPointerType
 * @brief Pointer data type modifier.
 */
class DwarfPointerType : public DwarfModifierType
{
	public:
		DwarfPointerType(DwarfTypeContainer *prnt, Dwarf_Off o);
		virtual std::string toLLVMString() const override;
		unsigned getPointerLevel();

		DEC_DWARF_TYPE_TID;
};

/**
 * @class DwarfReferenceType
 * @brief Reference data type modifier.
 */
class DwarfReferenceType : public DwarfModifierType
{
	public:
		DwarfReferenceType(DwarfTypeContainer *prnt, Dwarf_Off o);
		DEC_DWARF_TYPE_TID;
};

/**
 * @class DwarfRestrictType
 * @brief Restrict data type modifier.
 */
class DwarfRestrictType : public DwarfModifierType
{
	public:
		DwarfRestrictType(DwarfTypeContainer *prnt, Dwarf_Off o);
		DEC_DWARF_TYPE_TID;
};

/**
 * @class DwarfRValReferenceType
 * @brief Rvalue reference data type modifier.
 */
class DwarfRValReferenceType : public DwarfModifierType
{
	public:
		DwarfRValReferenceType(DwarfTypeContainer *prnt, Dwarf_Off o);
		DEC_DWARF_TYPE_TID;
};

/**
 * @class DwarfSharedType
 * @brief Shared data type modifier.
 */
class DwarfSharedType : public DwarfModifierType
{
	public:
		DwarfSharedType(DwarfTypeContainer *prnt, Dwarf_Off o);
		DEC_DWARF_TYPE_TID;
};

/**
 * @class DwarfVolatileType
 * @brief Volatile data type modifier.
 */
class DwarfVolatileType : public DwarfModifierType
{
	public:
		DwarfVolatileType(DwarfTypeContainer *prnt, Dwarf_Off o);
		DEC_DWARF_TYPE_TID;
};

/**
 * @class DwarfTypeContainer
 * @brief Data type container.
 */
class DwarfTypeContainer : public DwarfBaseContainer<DwarfType>
{
	public:
		DwarfTypeContainer(DwarfFile *file, DwarfBaseElement *elem = nullptr);
		virtual void dump() const override;

		DwarfType *checkIfLoaded(Dwarf_Off off);
		virtual DwarfType *loadAndGetDie(Dwarf_Die die, unsigned lvl) override;

		DwarfType *getTypeByName(std::string n);
		DwarfType *getVoid();

		int getDieFlags(Dwarf_Die die, unsigned lvl);

	private:
		DwarfType m_void;                            ///< Void data type.
		std::map<Dwarf_Off, DwarfType*> m_typeCache; ///< Cache for fast type search based on die offset.
};

} // namespace dwarfparser
} // namespace retdec

#endif
