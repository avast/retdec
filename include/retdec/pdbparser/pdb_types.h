/**
 * @file include/retdec/pdbparser/pdb_types.h
 * @brief Types
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_PDBPARSER_PDB_TYPES_H
#define RETDEC_PDBPARSER_PDB_TYPES_H

#include <cstdio>

#include "retdec/pdbparser/pdb_info.h"
#include "retdec/pdbparser/pdb_utils.h"

namespace retdec {
namespace pdbparser {

// PDB type definition
class PDBTypeDef;
// PDB type definition map (key is type index)
typedef std::map<int, PDBTypeDef *> PDBTypeDefIndexMap;
// PDB type definition map - for fully defined types (key is type name)
typedef std::map<std::string, PDBTypeDef *> PDBTypeDefNameMap;

// =================================================================
// PDB TYPE FIELD STRUCTURES
// =================================================================

// Field type
enum ePDBFieldType
{
	PDBFIELD_ENUMERATE, PDBFIELD_MEMBER
};

// Enum member
typedef struct _PDBTypeFieldEnumerate
{
		int value;
		char * name;
} PDBTypeFieldEnumerate;

// Struct or union member
typedef struct _PDBTypeFieldMember
{
		int offset;
		int type_index;
		PDBTypeDef * type_def;
		char * name;
} PDBTypeFieldMember;

// General type field
typedef struct _PDBTypeField
{
		ePDBFieldType field_type;
		union
		{
				PDBTypeFieldEnumerate Enumerate;
				PDBTypeFieldMember Member;
		};
} PDBTypeField;

// =================================================================
// PDB TYPE CLASSES
// =================================================================

// Type class
enum ePDBTypeClass
{
	PDBTYPE_BASE, PDBTYPE_FIELDLIST,  // Auxiliary only
	PDBTYPE_ENUM,
	PDBTYPE_ARRAY,
	PDBTYPE_POINTER,
	PDBTYPE_CONST,
	PDBTYPE_ARGLIST,  // Auxiliary only
	PDBTYPE_FUNCTION,
	PDBTYPE_STRUCT,
	PDBTYPE_UNION,
	PDBTYPE_CLASS
};

// Type definition (base class)
// Class fully defined here
class PDBTypeDef
{
		// Constructor and destructor
	protected:
		PDBTypeDef(int ind, ePDBTypeClass c, int bts = 0) :
				type_index(ind), type_class(c), size_bytes(bts)
		{
		}
		;
	public:
		virtual ~PDBTypeDef(void)
		{
		}
		;

		// Basic methods - parse and dump
// matula, this triggers clang warning, since 'parse' methods in child classes have different signature.
		virtual void dump(bool nested = false)
		{
			if (!nested)
				printf("/* %04x (%d bytes) */\n", type_index, size_bytes);
		}
		;
		virtual bool is_fully_defined(void)
		{
			return false;
		}
		;
		virtual std::string to_llvm(void)
		{
			return get_default_llvm();
		}
		;
		virtual std::string to_llvm_identified(void)
		{
			return to_llvm();
		}
		;
		std::string get_default_llvm(void)
		{
			return "i32";
		}
		;

		// Basic members
		int type_index;
		ePDBTypeClass type_class;
		int size_bytes;
};

enum ePDBBaseType
{
	PDBBASETYPE_VOID,
	PDBBASETYPE_BOOL,
	PDBBASETYPE_INT_SIGNED,
	PDBBASETYPE_INT_UNSIGNED,
	PDBBASETYPE_FLOAT,
	PDBBASETYPE_HRESULT,
	PDBBASETYPE_VARIADIC
};

// Base type
class PDBTypeBase : public PDBTypeDef
{
	public:
		// Constructor and destructor
		PDBTypeBase(int ind, ePDBBaseType t, bool ptr, int bits, const char * desc) :
				PDBTypeDef(ind, PDBTYPE_BASE, (ptr) ? 4 : bits / 8), base_type(t), is_pointer(ptr), size_bits(bits), description(
				        desc)
		{
		}
		;
		virtual ~PDBTypeBase(void)
		{
		}
		;

		// Basic methods - parse and dump
		virtual void parse(lfRecord *, int, PDBTypeDefIndexMap &)
		{
		}
		;
		virtual void dump(bool nested = false);
		virtual bool is_fully_defined(void)
		{
			return true;
		}
		;
		virtual std::string to_llvm(void);
		virtual std::string to_llvm_identified(void)
		{
			return to_llvm();
		}
		;

		// Type-specific members
		ePDBBaseType base_type;  // Base type (void, int, float...)
		bool is_pointer;  // Is pointer?
		int size_bits;  // Number of bits
		const char * description;  // Textual description
};

// Field list (auxiliary type only!!!)
class PDBTypeFieldList : public PDBTypeDef
{
	public:
		// Constructor and destructor
		PDBTypeFieldList(int ind) :
				PDBTypeDef(ind, PDBTYPE_FIELDLIST)
		{
		}
		;
		virtual ~PDBTypeFieldList(void)
		{
		}
		;

		// Basic methods - parse and dump
		virtual void parse(lfFieldList *record, int size, PDBTypeDefIndexMap &types);
		virtual void dump(bool nested = false);
		virtual bool is_fully_defined(void)
		{
			return false;
		}
		;
		virtual std::string to_llvm(void)
		{
			return get_default_llvm();
		}
		;
		virtual std::string to_llvm_identified(void)
		{
			return to_llvm();
		}
		;

		// Type-specific members
		std::vector<PDBTypeField> fields;  // Fields
};

// Enum
class PDBTypeEnum : public PDBTypeDef
{
	public:
		// Constructor and destructor
		PDBTypeEnum(int ind) :
				PDBTypeDef(ind, PDBTYPE_ENUM), enum_count(0), enum_members(nullptr), enum_name(nullptr)
		{
		}
		;
		virtual ~PDBTypeEnum(void)
		{
			if (enum_members != nullptr)
				delete[] enum_members;
		}
		;

		// Basic methods - parse and dump
		virtual void parse(lfEnum *record, int size, PDBTypeDefIndexMap &types);
		virtual void dump(bool nested = false);
		virtual bool is_fully_defined(void)
		{
			return enum_members != nullptr;
		}
		;
		virtual std::string to_llvm(void);
		virtual std::string to_llvm_identified(void)
		{
			return to_llvm();
		}
		;

		// Type-specific members
		unsigned int enum_count;  // Number of members
		PDBTypeFieldEnumerate ** enum_members;  // Members
		char * enum_name;  // Enum name
};

// Array
class PDBTypeArray : public PDBTypeDef
{
	public:
		// Constructor and destructor
		PDBTypeArray(int ind) :
				PDBTypeDef(ind, PDBTYPE_ARRAY), array_elemtype_index(0), array_elemtype_def(nullptr), array_idxtype_index(
				        0), array_idxtype_def(nullptr), array_count(0)
		{
		}
		;
		virtual ~PDBTypeArray(void)
		{
		}
		;

		// Basic methods - parse and dump
		virtual void parse(lfArray *record, int size, PDBTypeDefIndexMap &types);
		virtual void dump(bool nested = false);
		virtual bool is_fully_defined(void)
		{
			return true;
		}
		;
		virtual std::string to_llvm(void);
		virtual std::string to_llvm_identified(void)
		{
			return to_llvm();
		}
		;

		// Type-specific members
		int array_elemtype_index;  // Element type index
		PDBTypeDef * array_elemtype_def;  // Element type definition
		int array_idxtype_index;  // Indexing type index
		PDBTypeDef * array_idxtype_def;  // Indexing type definition
		int array_count;  // Number of elements
};

// Pointer
class PDBTypePointer : public PDBTypeDef
{
	public:
		// Constructor and destructor
		PDBTypePointer(int ind) :
				PDBTypeDef(ind, PDBTYPE_POINTER), ptr_utype_index(0), ptr_utype_def(nullptr)
		{
		}
		;
		virtual ~PDBTypePointer(void)
		{
		}
		;

		// Basic methods - parse and dump
		virtual void parse(lfPointer *record, int size, PDBTypeDefIndexMap &types);
		virtual void dump(bool nested = false);
		virtual bool is_fully_defined(void)
		{
			return true;
		}
		;
		virtual std::string to_llvm(void);
		virtual std::string to_llvm_identified(void)
		{
			return to_llvm();
		}
		;

		// Type-specific members
		int ptr_utype_index;  // Underlying type index
		PDBTypeDef * ptr_utype_def;  // Underlying type definition
};

// Constant
class PDBTypeConst : public PDBTypeDef
{
	public:
		// Constructor and destructor
		PDBTypeConst(int ind) :
				PDBTypeDef(ind, PDBTYPE_CONST), const_utype_index(0), const_utype_def(nullptr)
		{
		}
		;
		virtual ~PDBTypeConst(void)
		{
		}
		;

		// Basic methods - parse and dump
		virtual void parse(lfModifier *record, int, PDBTypeDefIndexMap &types);
		virtual void dump(bool nested = false);
		virtual bool is_fully_defined(void)
		{
			return true;
		}
		;
		virtual std::string to_llvm(void);
		virtual std::string to_llvm_identified(void)
		{
			return to_llvm();
		}
		;

		// Type-specific members
		int const_utype_index;  // Underlying type index
		PDBTypeDef * const_utype_def;  // Underlying type definition
};

// Argument list (auxiliary type only!!!)
// Class fully defined here
class PDBTypeArglist : public PDBTypeDef
{
	public:
		// Constructor and destructor
		PDBTypeArglist(int ind) :
				PDBTypeDef(ind, PDBTYPE_ARGLIST), arglist(nullptr)
		{
		}
		;
		virtual ~PDBTypeArglist(void)
		{
		}
		;

		// Basic methods - parse and dump
		virtual void parse(lfArgList *record, int, PDBTypeDefIndexMap &)
		{
			arglist = record;
		}
		;
		virtual void dump(bool nested = false)
		{
			PDBTypeDef::dump(nested);
			if (!nested)
				printf("/* Argument list */\n");
		}
		;
		virtual bool is_fully_defined(void)
		{
			return false;
		}
		;
		virtual std::string to_llvm(void)
		{
			return "...";
		}
		;
		virtual std::string to_llvm_identified(void)
		{
			return to_llvm();
		}
		;

		// Type-specific members
		lfArgList * arglist;  // Argument list record
};

// Function argument
typedef struct _PDBTypeFuncArg
{
		int type_index;
		PDBTypeDef * type_def;
} PDBTypeFuncArg;

// Function declaration
class PDBTypeFunction : public PDBTypeDef
{
	public:
		// Constructor and destructor
		PDBTypeFunction(int ind) :
				PDBTypeDef(ind, PDBTYPE_FUNCTION), func_rettype_index(0), func_rettype_def(nullptr), func_calltype(0), func_args_count(
				        0), func_args(nullptr), func_is_variadic(false), func_is_clsmember(false), func_clstype_index(0), func_clstype_def(
				        nullptr), func_thistype_index(0), func_thistype_def(nullptr)
		{
		}
		;
		virtual ~PDBTypeFunction(void)
		{
			if (func_args != nullptr)
				delete[] func_args;
		}
		;

		// Basic methods - parse and dump
		virtual void parse(lfProc *record, int size, PDBTypeDefIndexMap &types);
		void parse_mfunc(lfMFunc *record, int size, PDBTypeDefIndexMap &types);
		virtual void dump(bool nested = false);
		virtual bool is_fully_defined(void)
		{
			return func_args != nullptr;
		}
		;
		virtual std::string to_llvm(void);
		virtual std::string to_llvm_identified(void)
		{
			return to_llvm();
		}
		;

		// Type-specific members
		int func_rettype_index;  // Return value type index
		PDBTypeDef * func_rettype_def;  // Return value type definition
		int func_calltype;  // Calling convention
		int func_args_count;  // Number of arguments
		PDBTypeFuncArg * func_args;  // Arguments
		bool func_is_variadic;  // Variadic parameters function
		bool func_is_clsmember;  // Function is class method
		int func_clstype_index;  // Parent class type index
		PDBTypeDef * func_clstype_def;  // Parent class type definition
		int func_thistype_index;  // This-parameter type index
		PDBTypeDef * func_thistype_def;  // This-parameter class type definition
};

// Struct
class PDBTypeStruct : public PDBTypeDef
{
	public:
		// Constructor and destructor
		PDBTypeStruct(int ind) :
				PDBTypeDef(ind, PDBTYPE_STRUCT), struct_count(0)
		{
		}
		;
		virtual ~PDBTypeStruct(void)
		{
		}
		;

		// Basic methods - parse and dump
		virtual void parse(lfStructure *record, int size, PDBTypeDefIndexMap &types);
		virtual void dump(bool nested = false);
		virtual bool is_fully_defined(void)
		{
			return struct_count > 0;
		}
		;
		virtual std::string to_llvm(void);
		virtual std::string to_llvm_identified(void);

		// Type-specific members
		unsigned int struct_count;  // Number of members
		std::vector<PDBTypeFieldMember *> struct_members;  // Members
		std::string struct_name;  // Struct name
};

// Union
class PDBTypeUnion : public PDBTypeDef
{
	public:
		// Constructor and destructor
		PDBTypeUnion(int ind) :
				PDBTypeDef(ind, PDBTYPE_UNION), union_count(0), union_name(nullptr)
		{
		}
		;
		virtual ~PDBTypeUnion(void)
		{
		}
		;

		// Basic methods - parse and dump
		virtual void parse(lfUnion *record, int size, PDBTypeDefIndexMap &types);
		virtual void dump(bool nested = false);
		virtual bool is_fully_defined(void)
		{
			return union_count > 0;
		}
		;
		virtual std::string to_llvm(void);
		virtual std::string to_llvm_identified(void)
		{
			return to_llvm();
		}
		;

		// Type-specific members
		unsigned int union_count;  // Number of members
		std::vector<PDBTypeFieldMember *> union_members;  // Members
		char * union_name;  // Union name
};

// Class
class PDBTypeClass : public PDBTypeDef
{
	public:
		// Constructor and destructor
		PDBTypeClass(int ind) :
				PDBTypeDef(ind, PDBTYPE_CLASS), class_count(0), class_name(nullptr)
		{
		}
		;
		virtual ~PDBTypeClass(void)
		{
		}
		;

		// Basic methods - parse and dump
		virtual void parse(lfClass *record, int size, PDBTypeDefIndexMap &types);
		virtual void dump(bool nested = false);
		virtual bool is_fully_defined(void)
		{
			return class_count > 0;
		}
		;
		virtual std::string to_llvm(void);
		virtual std::string to_llvm_identified(void)
		{
			return to_llvm();
		}
		;

		// Type-specific members
		unsigned int class_count;  // Number of members
		char * class_name;  // Class name
		//TODO methods, attributes, etc...
};

// =================================================================
// MAIN CLASS PDBTypes
// =================================================================

class PDBTypes
{
	public:
		// Constructor and destructor
		PDBTypes(PDBStream *s) :
				pdb_tpi_size(s->size), pdb_tpi_data(s->data), parsed(false), tpi_header(
				        reinterpret_cast<HDR *>(s->data))
		{
		}
		;
		~PDBTypes(void);

		// Action methods
		void parse_types(void);

		// Getting methods
		PDBTypeDef * get_type_by_index(int index)
		{
			if (!parsed)
				return nullptr;
			else
				return types[index];
		}
		;
		PDBTypeDef * get_type_by_name(char *name)
		{
			if (!parsed)
				return nullptr;
			else
				return types_byname[name];
		}
		;

		// Printing methods
		void dump_types(void);
		void print_types(void);

	public:
		// Internal functions
		PHDR TPILoadTypeInfo(void);

		// Variables
		unsigned int pdb_tpi_size;  // size of TPI stream
		char * pdb_tpi_data;  // data from TPI stream
		bool parsed;  // types are parsed

		// Data structure pointers
		HDR * tpi_header;

		// Data containers
		PDBTypeDefIndexMap types;  // Map of type definitions (key is type index)
		PDBTypeDefIndexMap types_fully_defined;  // Map of fully defined types (key is type index)
		PDBTypeDefNameMap types_byname;  // Map of fully defined types (key is type name)
};

} // namespace pdbparser
} // namespace retdec

#endif
