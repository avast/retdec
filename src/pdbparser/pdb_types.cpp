/**
 * @file src/pdbparser/pdb_types.cpp
 * @brief Types
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>

#include "retdec/pdbparser/pdb_types.h"

using namespace std;

namespace retdec {
namespace pdbparser {

// =================================================================
//
// CLASS PDBTypeBase
//
// =================================================================

void PDBTypeBase::dump(bool nested)
{
	PDBTypeDef::dump(nested);
	printf("%s", description);
	if (!nested)
		puts("");
}

std::string PDBTypeBase::to_llvm(void)
{
	std::stringstream tmp;

	if (base_type == PDBBASETYPE_VOID)
	{
		tmp << "void";
	}
	else if (base_type == PDBBASETYPE_BOOL)
	{
		tmp << "i1";
	}
	else if (base_type == PDBBASETYPE_INT_SIGNED || base_type == PDBBASETYPE_INT_UNSIGNED
	        || base_type == PDBBASETYPE_HRESULT)
	{
		tmp << "i" << size_bits;
	}
	else if (base_type == PDBBASETYPE_FLOAT)
	{
		switch (size_bits)
		{
			case 16: tmp << "half"; break;
			case 32: tmp << "float"; break;
			case 64: tmp << "double"; break;
			case 128: tmp << "fp128"; break;
			case 80: tmp << "x86_fp80"; break;
			default: tmp << "double"; break;
		}
	}

	// check if it is pointer
	if (is_pointer)
	{
		tmp << "*";
	}
	return tmp.str();
}

// =================================================================
//
// CLASS PDBTypeFieldList
//
// =================================================================

void PDBTypeFieldList::parse(lfFieldList *record, int size, PDBTypeDefIndexMap &types)
{
	int position = 0;
	while (position < size - 2)
	{  // Process all subrecords
		lfSubRecord *subrecord =
		        reinterpret_cast<lfSubRecord *>(reinterpret_cast<char *>(&record->SubRecord) + position);  // Get pointer to current subrecord
		int subrecord_size = 0;
		PDBTypeField new_field;
		bool end = false;
		switch (subrecord->leaf)
		{
			case LF_ENUMERATE:
			{  // Enum member
				new_field.field_type = PDBFIELD_ENUMERATE;
				// Get value and name of enum member
				int value;
				char * name;
				name = reinterpret_cast<char *>(RecordValue(subrecord->Enumerate.value,
				        reinterpret_cast<PDB_DWORD *>(&value)));
				if (name == nullptr)
				{
					return;
				}
				new_field.Enumerate.name = name;
				new_field.Enumerate.value = value;
				// Add this field to fields vector
				fields.push_back(new_field);
				// Compute the subrecord size
				subrecord_size = (name - reinterpret_cast<char *>(subrecord)) + strlen(name) + 1;
				break;
			}
			case LF_MEMBER:
			{  // Struct member
				new_field.field_type = PDBFIELD_MEMBER;
				// Get type of struct member
				new_field.Member.type_index = subrecord->Member.index;
				new_field.Member.type_def = types[subrecord->Member.index];
				// Get offset and name of struct member
				int value;
				char * name;
				name = reinterpret_cast<char *>(RecordValue(subrecord->Member.offset,
				        reinterpret_cast<PDB_DWORD *>(&value)));
				if (name == nullptr)
				{
					return;
				}
				new_field.Member.name = name;
				new_field.Member.offset = value;
				// Add this field to fields vector
				fields.push_back(new_field);
				// Compute the subrecord size
				subrecord_size = (name - reinterpret_cast<char *>(subrecord)) + strlen(name) + 1;
				break;
			}
			case LF_NESTTYPE:
			{  // Nested typedef
			   //TODO (skipping only now)
				char * name = reinterpret_cast<char *>(subrecord->NestType.Name);
				if (name == nullptr)
				{
					return;
				}
				subrecord_size = (name - reinterpret_cast<char *>(subrecord)) + strlen(name) + 1;
				break;
			}
			default:
				end = true;
				break;
		}
		// Align the size to 4 bytes
		subrecord_size = (subrecord_size + (DWORD_ - 1)) & (0 - DWORD_);
		// Move position to next subrecord
		position += subrecord_size;
		if (end)
			break;
	}
}

void PDBTypeFieldList::dump(bool nested)
{
	PDBTypeDef::dump(nested);
	if (!nested)
		printf("/* Field list */\n");
}

// =================================================================
//
// CLASS PDBTypeEnum
//
// =================================================================

void PDBTypeEnum::parse(lfEnum *record, int, PDBTypeDefIndexMap &types)
{
	// Copy member count and name
	enum_count = record->count;
	enum_name = reinterpret_cast<char *>(record->Name);
	// Get enum size in bytes by underlying type
	if (record->utype > 0 && types[record->utype] != nullptr)
		size_bytes = types[record->utype]->size_bytes;
	// Fill the array of pointers to enum members
	if (record->field > 0 && types[record->field] != nullptr)
	{
		// Get the type definition with field list
		PDBTypeFieldList * fieldlist = reinterpret_cast<PDBTypeFieldList *>(types[record->field]);
		if (fieldlist->fields.size() != enum_count)
		{
			return;
		}
		// Allocate the array of pointers
		enum_members = new PDBTypeFieldEnumerate *[enum_count];
		for (unsigned int i = 0; i < enum_count; i++)
		{  // Copy pointers to enum members from field list
			assert(fieldlist->fields[i].field_type == PDBFIELD_ENUMERATE);
			enum_members[i] = &fieldlist->fields[i].Enumerate;  // Copying pointer
		}
	}
}

void PDBTypeEnum::dump(bool nested)
{
	PDBTypeDef::dump(nested);
	if (!nested)
		printf("enum ");
	printf("%s", enum_name);
	if (!nested)
	{
		if (enum_members != nullptr)
		{
			printf("\n{\n");
			for (unsigned int i = 0; i < enum_count; i++)
				printf("\t%s = %d,\n", enum_members[i]->name, enum_members[i]->value);
			printf("};\n");
		}
		else
			printf(";\n");
	}
}

std::string PDBTypeEnum::to_llvm(void)
{
	return get_default_llvm();
}

// =================================================================
//
// CLASS PDBTypeArray
//
// =================================================================

void PDBTypeArray::parse(lfArray *record, int, PDBTypeDefIndexMap &types)
{
	// Get element type
	array_elemtype_index = record->elemtype;
	array_elemtype_def = types[array_elemtype_index];
	// Get indexing type
	array_idxtype_index = record->idxtype;
	array_idxtype_def = types[array_idxtype_index];
	// Get size of the array
	int value;
	RecordValue(record->data, reinterpret_cast<PDB_DWORD *>(&value));
	size_bytes = value;
	// Get number of elements
	if (array_elemtype_def != nullptr && array_elemtype_def->size_bytes != 0)
		array_count = size_bytes / array_elemtype_def->size_bytes;
	else
		array_count = -1;
}

void PDBTypeArray::dump(bool nested)
{
	PDBTypeDef::dump(nested);
	// Dump element type
	if (array_elemtype_def != nullptr)
		array_elemtype_def->dump(true);
	else
		printf("(%04x)", array_elemtype_index);
	// Print number of elements
	printf("[%d]", array_count);
	if (!nested)
		puts("");
}

std::string PDBTypeArray::to_llvm(void)
{
	std::stringstream tmp;
	auto s = array_elemtype_def ? array_elemtype_def->to_llvm_identified() : get_default_llvm();
	tmp << "[" << array_count << " x " << s << "]";
	return tmp.str();
}

// =================================================================
//
// CLASS PDBTypePointer
//
// =================================================================

void PDBTypePointer::parse(lfPointer *record, int, PDBTypeDefIndexMap &types)
{
	// Get underlying type
	ptr_utype_index = record->body.utype;
	ptr_utype_def = types[ptr_utype_index];
	// TODO pointer type and const pointer
	size_bytes = 4;
}

void PDBTypePointer::dump(bool nested)
{
	PDBTypeDef::dump(nested);
	if (ptr_utype_def != nullptr)
	{
		ptr_utype_def->dump(true);
		if (!(ptr_utype_def->type_class == PDBTYPE_POINTER
		        || (ptr_utype_def->type_class == PDBTYPE_BASE
		                && (reinterpret_cast<PDBTypeBase *>(ptr_utype_def))->is_pointer)))
			printf(" ");
		printf("*");
	}
	else
		printf("(%04x) *", ptr_utype_index);
	if (!nested)
		puts("");
}

std::string PDBTypePointer::to_llvm(void)
{
	auto s = ptr_utype_def ? ptr_utype_def->to_llvm_identified() : get_default_llvm();
	return s + "*";
}

// =================================================================
//
// CLASS PDBTypeConst
//
// =================================================================

void PDBTypeConst::parse(lfModifier *record, int, PDBTypeDefIndexMap &types)
{
	const_utype_index = record->utype;
	const_utype_def = types[record->utype];
	if (const_utype_def != nullptr)
		size_bytes = const_utype_def->size_bytes;
}

void PDBTypeConst::dump(bool nested)
{
	PDBTypeDef::dump(nested);
	printf("const ");
	if (const_utype_def != nullptr)
		const_utype_def->dump(true);
	else
		printf("(%04x)", const_utype_index);
	if (!nested)
		puts("");
}

std::string PDBTypeConst::to_llvm(void)
{
	return const_utype_def ? const_utype_def->to_llvm_identified() : get_default_llvm();
}

// =================================================================
//
// CLASS PDBTypeFunction
//
// =================================================================

void PDBTypeFunction::parse(lfProc *record, int, PDBTypeDefIndexMap &types)
{
	// Get function return value type
	func_rettype_index = record->rvtype;
	func_rettype_def = types[record->rvtype];
	// Get calling convention
	func_calltype = record->calltype;
	// Get list of arguments
	func_args_count = record->parmcount;
	PDBTypeArglist * arglisttypedef = reinterpret_cast<PDBTypeArglist *>(types[record->arglist]);  // Get auxiliary type definition containing arglist
	if (arglisttypedef != nullptr)
	{
		assert(arglisttypedef->type_class == PDBTYPE_ARGLIST);
		lfArgList * arglist = arglisttypedef->arglist;
		if (record->parmcount == 0)
			func_args_count = 0;
		else
			assert(arglist->count == record->parmcount);
		func_args = new PDBTypeFuncArg[func_args_count];
		for (int i = 0; i < func_args_count; i++)
		{  // Process all arguments
			func_args[i].type_index = arglist->arg[i];
			func_args[i].type_def = types[arglist->arg[i]];
		}
		// Check if function is variadic
		if (func_args_count > 0 && func_args[func_args_count - 1].type_index == T_NOTYPE)
			func_is_variadic = true;
	}
	func_is_clsmember = false;
	func_clstype_index = 0;
	func_thistype_index = 0;
}

void PDBTypeFunction::parse_mfunc(lfMFunc *record, int, PDBTypeDefIndexMap &types)
{
	// Get function return value type
	func_rettype_index = record->rvtype;
	func_rettype_def = types[record->rvtype];
	// Get calling convention
	func_calltype = record->calltype;
	// Get list of arguments
	func_args_count = record->parmcount;
	PDBTypeArglist * arglisttypedef = reinterpret_cast<PDBTypeArglist *>(types[record->arglist]);  // Get auxiliary type definition containing arglist
	if (arglisttypedef != nullptr)
	{
		assert(arglisttypedef->type_class == PDBTYPE_ARGLIST);
		lfArgList * arglist = arglisttypedef->arglist;
		if (record->parmcount == 0)
			func_args_count = 0;
		else
			assert(arglist->count == record->parmcount);
		func_args = new PDBTypeFuncArg[func_args_count];
		for (int i = 0; i < func_args_count; i++)
		{  // Process all arguments
			func_args[i].type_index = arglist->arg[i];
			func_args[i].type_def = types[arglist->arg[i]];
		}
	}
	// Get function parent class and this-parameter type
	func_is_clsmember = true;
	func_clstype_index = record->classtype;
	func_clstype_def = types[record->classtype];
	func_thistype_index = record->thistype;
	func_thistype_def = (func_thistype_index) ? types[record->thistype] : nullptr;
}

void PDBTypeFunction::dump(bool nested)
{
	PDBTypeDef::dump(nested);
	// Print return value
	if (func_rettype_def != nullptr)
		func_rettype_def->dump(true);
	else
		printf("(%04x)", func_rettype_index);
	// Print function header
	if (func_is_clsmember)
		printf(" MFUNC (");
	else
		printf(" FUNC (");
	// Print arguments
	if (func_thistype_index)
	{  // Function has this-parameter
		printf("THIS ");
		if (func_thistype_def != nullptr)
			func_thistype_def->dump(true);
		else
			printf("(%04x)", func_thistype_index);
		if (func_args_count > 0)
			printf(", ");
	}
	if (func_args_count > 0)
	{  // Function has some arguments
		if (func_args != nullptr)
		{
			for (int i = 0; i < func_args_count; i++)
			{
				if (func_args[i].type_def != nullptr)
					func_args[i].type_def->dump(true);
				else
					printf("(%04x)", func_args[i].type_index);
				if (i < func_args_count - 1)
					printf(", ");
			};
		}
		else
			printf("(?)");
	}
	else if (!func_thistype_index)
		printf("void");
	printf(")");
	if (!nested)
		puts("");
	// TODO calling convention
}

std::string PDBTypeFunction::to_llvm(void)
{
	return get_default_llvm();
}

// =================================================================
//
// CLASS PDBTypeStruct
//
// =================================================================

void PDBTypeStruct::parse(lfStructure *record, int, PDBTypeDefIndexMap &types)
{
	// Get member count
	struct_count = record->count;
	// Get struct size and name
	int value;
	char * name;
	name = reinterpret_cast<char *>(RecordValue(record->data, reinterpret_cast<PDB_DWORD *>(&value)));
	size_bytes = value;
	if (name)
		struct_name = name;
	// Copy struct members
	if (record->field > 0 && types[record->field] != nullptr)
	{
		// Get field list with struct members
		PDBTypeFieldList * fieldlist = reinterpret_cast<PDBTypeFieldList *>(types[record->field]);
		// Copy all members from field list
		for (unsigned int i = 0; i < fieldlist->fields.size(); i++)
		{  // Copy pointers to struct members from field list
			if (fieldlist->fields[i].field_type == PDBFIELD_MEMBER)
				struct_members.push_back(&fieldlist->fields[i].Member);  // Get struct member
		}
	}

	static unsigned anonCntr = 0;
	if (struct_name.empty())
	{
		struct_name = "anon_struct_" + std::to_string(anonCntr++);
	}
}

void PDBTypeStruct::dump(bool nested)
{
	PDBTypeDef::dump(nested);
	printf("struct %s", struct_name.c_str());
	if (!nested)
	{
		if (struct_members.size() > 0)
		{
			printf("\n{\n");
			for (unsigned int i = 0; i < struct_members.size(); i++)
			{
				printf("/*%03x*/ ", struct_members[i]->offset);
				if (struct_members[i]->type_def != nullptr)
					struct_members[i]->type_def->dump(true);
				else
					printf("(%04x)", struct_members[i]->type_index);
				printf(" %s;\n", struct_members[i]->name);
			}
			printf("};\n");
		}
		else
			printf(";\n");
	}
}

std::string PDBTypeStruct::to_llvm(void)
{
	bool first = true;
	std::stringstream ret;

	if (!struct_name.empty())
		ret << "%" << struct_name << " = type ";
	ret << "{";

	for (unsigned int i = 0; i < struct_members.size(); i++)
	{
		if (!first)
			ret << ",";
		else
			first = false;

		if (struct_members[i]->type_def)
			ret << " " << struct_members[i]->type_def->to_llvm_identified();
		else
			ret << " " << get_default_llvm();
	}

	ret << " }";
	return ret.str();
}

std::string PDBTypeStruct::to_llvm_identified(void)
{
	return "%" + struct_name;
}

// =================================================================
//
// CLASS PDBTypeUnion
//
// =================================================================

void PDBTypeUnion::parse(lfUnion *record, int, PDBTypeDefIndexMap &types)
{
	// Copy member count
	union_count = record->count;
	// Get union size and name
	int value;
	char * name;
	name = reinterpret_cast<char *>(RecordValue(record->data, reinterpret_cast<PDB_DWORD *>(&value)));
	size_bytes = value;
	union_name = name;
	// Copy union members
	if (record->field > 0 && types[record->field] != nullptr)
	{
		// Get field list with union members
		PDBTypeFieldList * fieldlist = reinterpret_cast<PDBTypeFieldList *>(types[record->field]);
		// Copy all members from field list
		for (unsigned int i = 0; i < fieldlist->fields.size(); i++)
		{  // Copy pointers to struct members from field list
			if (fieldlist->fields[i].field_type == PDBFIELD_MEMBER)
				union_members.push_back(&fieldlist->fields[i].Member);  // Get struct member
		}
	}
}

void PDBTypeUnion::dump(bool nested)
{
	PDBTypeDef::dump(nested);
	printf("union %s", union_name);
	if (!nested)
	{
		if (union_members.size() > 0)
		{
			printf("\n{\n");
			for (unsigned int i = 0; i < union_members.size(); i++)
			{
				printf("/*%03x*/ ", union_members[i]->offset);
				if (union_members[i]->type_def != nullptr)
					union_members[i]->type_def->dump(true);
				else
					printf("(%04x)", union_members[i]->type_index);
				printf(" %s;\n", union_members[i]->name);
			}
			printf("};\n");
		}
		else
			printf(";\n");
	}
}

std::string PDBTypeUnion::to_llvm(void)
{
	return get_default_llvm();
}

// =================================================================
//
// CLASS PDBTypeClass
//
// =================================================================

void PDBTypeClass::parse(lfClass *record, int, PDBTypeDefIndexMap &)
{
	// Copy member count
	class_count = record->count;
	// Get struct size and name
	int value;
	char * name;
	name = reinterpret_cast<char *>(RecordValue(record->data, reinterpret_cast<PDB_DWORD *>(&value)));
	size_bytes = value;
	class_name = name;
}

void PDBTypeClass::dump(bool nested)
{
	PDBTypeDef::dump(nested);
	printf("class %s", class_name);
	if (!nested)
		puts("");
}

std::string PDBTypeClass::to_llvm(void)
{
	return get_default_llvm();
}

// =================================================================
//
// CLASS PDBTypes
//
// =================================================================

// =================================================================
// PRIVATE METHODS
// =================================================================

// =================================================================
// TYPE INFO BROWSER
// =================================================================

#define SKIP(_p,_d)      (reinterpret_cast<PDB_PVOID>(reinterpret_cast<PDB_PBYTE>(_p) + (_d)))

PDB_PBYTE MethodValue(CV_fldattr_t attr, PDB_PDWORD pdData, PDB_PDWORD pdValue)
{
	PDB_DWORD dValue = -1;
	PDB_PBYTE pbText = nullptr;

	if (pdData != nullptr)
	{
		switch (attr.mprop)
		{
			case CV_MTintro:
			case CV_MTpureintro:
			{
				dValue = *pdData;
				pbText = reinterpret_cast<PDB_PBYTE>(pdData + 1);
				break;
			}
			default:
			{
				pbText = reinterpret_cast<PDB_PBYTE>(pdData);
				break;
			}
		}
	}
	if (pdValue != nullptr)
		*pdValue = dValue;
	return pbText;
}

// -----------------------------------------------------------------

PDB_VOID DisplayArray(PlfArray pla, PDB_DWORD, PDB_DWORD)
{
	PDB_DWORD dBytes;
	RecordValue(pla->data, &dBytes);

	printf((" array  | eltype: %08X idxtpe: %08X bytes:  %08X\r\n"), pla->elemtype, pla->idxtype, dBytes);
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayBitfield(PlfBitfield plb, PDB_DWORD, PDB_DWORD)
{
	printf((" bitfield (%08X) %02X : %02X\r\n"), plb->type, plb->position, plb->length);
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayClass(PlfClass plc, PDB_DWORD, PDB_DWORD)
{
	PDB_DWORD dBytes;
	PDB_PBYTE pbName = RecordValue(plc->data, &dBytes);

	printf((" class  | fields: %08X bytes:  %08X count:  %04hX derived: %08X vshape: %08X [%s]\r\n"), plc->field,
	        dBytes, plc->count, plc->derived, plc->vshape, pbName);
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayStructure(PlfStructure pls, PDB_DWORD, PDB_DWORD)
{
	PDB_DWORD dBytes;
	PDB_PBYTE pbName = RecordValue(pls->data, &dBytes);

	printf((" struct | fields: %08X bytes:  %08X count:  %04hX derived: %08X vshape: %08X [%s]\r\n"), pls->field,
	        dBytes, pls->count, pls->derived, pls->vshape, pbName);
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayUnion(PlfUnion plu, PDB_DWORD, PDB_DWORD)
{
	PDB_DWORD dBytes;
	PDB_PBYTE pbName = RecordValue(plu->data, &dBytes);

	printf((" union  | fields: %08X bytes:  %08X count:  %04hX [%s]\r\n"), plu->field, dBytes, plu->count, pbName);
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayEnum(PlfEnum ple, PDB_DWORD, PDB_DWORD)
{
	printf((" enum   | fields: %08X utype:  %08X count:  %04hX [%s]\r\n"), ple->field, ple->utype, ple->count,
	        ple->Name);
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayPointer(PlfPointer plp, PDB_DWORD, PDB_DWORD)
{
	printf((" pointer| utype:  %08X\r\n"), plp->body.utype);
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayProc(PlfProc plp, PDB_DWORD, PDB_DWORD)
{
	printf((" proc   | rvtype: %08X arglst: %08X parcnt: %04X calltype: %02X\r\n"), plp->rvtype, plp->arglist,
	        plp->parmcount, plp->calltype);
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayMFunc(PlfMFunc plmf, PDB_DWORD, PDB_DWORD)
{
	printf(
	        (" mfunc  | rvtype: %08X arglst: %08X parcnt: %04X calltype: %02X clstype: %08X thistype: %08X thisadjust: %08X\r\n"),
	        plmf->rvtype, plmf->arglist, plmf->parmcount, plmf->calltype, plmf->classtype, plmf->thistype,
	        plmf->thisadjust);
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayArgList(PlfArgList plal, PDB_DWORD, PDB_DWORD)
{
	PDB_DWORD i;

	printf((" arglist| count:  %08X"), plal->count);

	for (i = 0; i < plal->count; i++)
	{
		printf((" type:   %08X"), plal->arg[i]);
	}
	printf(("\r\n"));
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayVTShape(PlfVTShape plvts, PDB_DWORD, PDB_DWORD)
{
	PDB_DWORD i;
	PDB_BYTE b;

	printf((" vtshape| count:  %08X"), plvts->count);

	for (i = 0; i < plvts->count; i++)
	{
		b = plvts->desc[i / 2];
		printf((" %X"), (i & 1 ? b & 0xF : b >> 4));
	}
	printf(("\r\n"));
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayFieldList(PlfFieldList plfl, PDB_DWORD, PDB_DWORD dSize)
{
	PlfSubRecord plsr;
	PDB_DWORD dValue, dOffset, i, n;
	PDB_PBYTE pbName, pbNext;

	printf(("\r\n"));

	for (i = 0; dSize - i >= lfFieldList_; i += n)
	{
		plsr = reinterpret_cast<PlfSubRecord>(SKIP(&plfl->SubRecord, i));

		printf(("        %04hX"), plsr->leaf);

		switch (plsr->leaf)
		{
			case LF_ENUMERATE:
			{
				pbName = RecordValue(plsr->Enumerate.value, &dValue);

				printf((" const | value:  %08X [%s]\r\n"), dValue, pbName);

				n = (reinterpret_cast<PDB_DWORD_PTR>(pbName) - reinterpret_cast<PDB_DWORD_PTR>(plsr))
				        + strlen(reinterpret_cast<const char *>(pbName)) + 1;
				break;
			}
			case LF_MEMBER:
			{
				pbName = RecordValue(plsr->Member.offset, &dOffset);

				printf((" field | offset: %08X type:   %08X [%s]\r\n"), dOffset, plsr->Member.index, pbName);

				n = (reinterpret_cast<PDB_DWORD_PTR>(pbName) - reinterpret_cast<PDB_DWORD_PTR>(plsr))
				        + strlen(reinterpret_cast<const char *>(pbName)) + 1;
				break;
			}
			case LF_BCLASS:
			{
				pbNext = RecordValue(plsr->BClass.offset, &dOffset);

				printf((" bclass %08X (%08X)\r\n"), dOffset, plsr->BClass.index);

				n = reinterpret_cast<PDB_DWORD_PTR>(pbNext) - reinterpret_cast<PDB_DWORD_PTR>(plsr);
				break;
			}
			case LF_VFUNCTAB:
			{
				printf((" vfunction table (%08X)\r\n"), plsr->VFuncTab.type);

				n = lfVFuncTab_;
				break;
			}
			case LF_ONEMETHOD:
			{
				pbName = MethodValue(plsr->OneMethod.attr, plsr->OneMethod.vbaseoff, &dValue);

				printf((" single %08X (%08X) [%s]\r\n"), dValue, plsr->OneMethod.index, pbName);

				n = (reinterpret_cast<PDB_DWORD_PTR>(pbName) - reinterpret_cast<PDB_DWORD_PTR>(plsr))
				        + strlen(reinterpret_cast<const char *>(pbName)) + 1;
				break;
			}
			case LF_METHOD:
			{
				printf((" method %08X (%08X) [%s]\r\n"), plsr->Method.count, plsr->Method.mList, plsr->Method.Name);

				n = (reinterpret_cast<PDB_DWORD_PTR>(plsr->Method.Name) - reinterpret_cast<PDB_DWORD_PTR>(plsr))
				        + strlen(reinterpret_cast<const char *>(plsr->Method.Name)) + 1;
				break;
			}
			case LF_NESTTYPE:
			{
				printf((" nested typedef | type:   %08X [%s]\r\n"), plsr->NestType.index, plsr->NestType.Name);

				n = (reinterpret_cast<PDB_DWORD_PTR>(plsr->NestType.Name) - reinterpret_cast<PDB_DWORD_PTR>(plsr))
				        + strlen(reinterpret_cast<const char *>(plsr->NestType.Name)) + 1;
				break;
			}
			default:
			{
				printf((" member ###\r\n"));
				n = 0;
				break;
			}
		}
		if (!(n = (n + (DWORD_ - 1)) & (0 - DWORD_)))
			break;
	}
	return;
}

// -----------------------------------------------------------------

PDB_VOID DisplayRecord(PlfRecord, PDB_DWORD, PDB_DWORD)
{
	printf((" ???\r\n"));
	return;
}

// -----------------------------------------------------------------

bool DisplayTypes(char * ptSource, int ptSize)
{
	PHDR pHdr;
	PlfRecord plr;
	char * pData;
	PDB_DWORD dData, dTypes, dBase, dSize, i;
	bool fOk = FALSE;

	if (true)
	{
		fOk = TRUE;

		if (true)
		{
			pHdr = reinterpret_cast<PHDR>(ptSource);
			dData = ptSize;

			if ((dData >= HDR_) && (dData >= pHdr->cbHdr + pHdr->cbGprec) && (pHdr->tiMac > pHdr->tiMin))
			{
				dTypes = pHdr->tiMac - pHdr->tiMin;
				dBase = pHdr->cbHdr;
				pData = reinterpret_cast<char *>(SKIP(pHdr, dBase));

				printf("\r\n"
						"TPI Version:  %u\r\n"
						"Index range:  %X..%X\r\n"
						"Type count:   %u\r\n", pHdr->vers, pHdr->tiMin, pHdr->tiMac - 1, dTypes);

				printf("\r\n"
						"HDR.vers                      = %u\r\n"
						"HDR.cbHdr                     = 0x%08X\r\n"
						"HDR.tiMin                     = 0x%08X\r\n"
						"HDR.tiMac                     = 0x%08X\r\n"
						"HDR.cbGprec                   = 0x%08X\r\n"
						"HDR.tpihash.sn                = 0x%04hX\r\n"
						"HDR.tpihash.snPad             = 0x%04hX\r\n"
						"HDR.tpihash.cbHashKey         = 0x%08X\r\n"
						"HDR.tpihash.cHashBuckets      = 0x%08X\r\n"
						"HDR.tpihash.offcbHashVals.off = 0x%08X\r\n"
						"HDR.tpihash.offcbHashVals.cb  = 0x%08X\r\n"
						"HDR.tpihash.offcbTiOff.off    = 0x%08X\r\n"
						"HDR.tpihash.offcbTiOff.cb     = 0x%08X\r\n"
						"HDR.tpihash.offcbHashAdj.off  = 0x%08X\r\n"
						"HDR.tpihash.offcbHashAdj.cb   = 0x%08X\r\n", pHdr->vers, pHdr->cbHdr, pHdr->tiMin, pHdr->tiMac,
				        pHdr->cbGprec, pHdr->tpihash.sn, pHdr->tpihash.snPad, pHdr->tpihash.cbHashKey,
				        pHdr->tpihash.cHashBuckets, pHdr->tpihash.offcbHashVals.off, pHdr->tpihash.offcbHashVals.cb,
				        pHdr->tpihash.offcbTiOff.off, pHdr->tpihash.offcbTiOff.cb, pHdr->tpihash.offcbHashAdj.off,
				        pHdr->tpihash.offcbHashAdj.cb);

				printf("\r\n");

				for (i = 0; i < dTypes; i++)
				{
					dSize = *reinterpret_cast<PDB_PWORD>(pData);
					dBase += WORD_;
					plr = reinterpret_cast<PlfRecord>(SKIP(pHdr, dBase));

					printf("%6X: %04hX %08lX", pHdr->tiMin + i, plr->leaf, static_cast<unsigned long int>(dBase - WORD_));

					switch (plr->leaf)
					{
						case LF_MODIFIER:
						{
							printf((" modif  | type:   %08X\r\n"), plr->Array.elemtype);
							break;
						}
						case LF_ARRAY:
						{
							DisplayArray(&plr->Array, dBase, dSize);
							break;
						}
						case LF_BITFIELD:
						{
							DisplayBitfield(&plr->Bitfield, dBase, dSize);
							break;
						}
						case LF_CLASS:
						{
							DisplayClass(&plr->Class, dBase, dSize);
							break;
						}
						case LF_STRUCTURE:
						{
							DisplayStructure(&plr->Structure, dBase, dSize);
							break;
						}
						case LF_UNION:
						{
							DisplayUnion(&plr->Union, dBase, dSize);
							break;
						}
						case LF_ENUM:
						{
							DisplayEnum(&plr->Enum, dBase, dSize);
							break;
						}
						case LF_POINTER:
						{
							DisplayPointer(&plr->Pointer, dBase, dSize);
							break;
						}
						case LF_PROCEDURE:
						{
							DisplayProc(&plr->Proc, dBase, dSize);
							break;
						}
						case LF_MFUNCTION:
						{
							DisplayMFunc(&plr->MFunc, dBase, dSize);
							break;
						}
						case LF_ARGLIST:
							//case LF_METHODLIST:
						{
							DisplayArgList(&plr->ArgList, dBase, dSize);
							break;
						}
						case LF_VTSHAPE:
						{
							DisplayVTShape(&plr->VTShape, dBase, dSize);
							break;
						}
						case LF_FIELDLIST:
						{
							DisplayFieldList(&plr->FieldList, dBase, dSize);
							break;
						}
						default:
						{
							DisplayRecord(plr, dBase, dSize);
							break;
						}
					}
					dBase += dSize;
					pData = reinterpret_cast<char *>(SKIP(pHdr, dBase));
				}
				printf("\r\n"
						"Offset:  %08X\r\n", dBase);
			}
		}
	}
	return fOk;
}

// =================================================================
// PUBLIC METHODS
// =================================================================

void PDBTypes::parse_types(void)
{
	if (parsed)
		return;
	// Base types
	types[T_NOTYPE] = new PDBTypeBase(0x00000000, PDBBASETYPE_VARIADIC, false, 0, "...");
	types[T_VOID] = new PDBTypeBase(0x00000003, PDBBASETYPE_VOID, false, 0, "void");
	types[T_32PVOID] = new PDBTypeBase(0x00000403, PDBBASETYPE_VOID, true, 0, "void *");
	types[T_HRESULT] = new PDBTypeBase(0x00000008, PDBBASETYPE_HRESULT, false, 32, "HRESULT");
	types[T_32PHRESULT] = new PDBTypeBase(0x00000408, PDBBASETYPE_HRESULT, true, 32, "HRESULT *");
	types[T_CHAR] = new PDBTypeBase(0x00000010, PDBBASETYPE_INT_SIGNED, false, 8, "char");
	types[T_32PCHAR] = new PDBTypeBase(0x00000410, PDBBASETYPE_INT_SIGNED, true, 8, "char *");
	types[T_UCHAR] = new PDBTypeBase(0x00000020, PDBBASETYPE_INT_UNSIGNED, false, 8, "unsigned char");
	types[T_32PUCHAR] = new PDBTypeBase(0x00000420, PDBBASETYPE_INT_UNSIGNED, true, 8, "unsigned char *");
	types[T_RCHAR] = new PDBTypeBase(0x00000070, PDBBASETYPE_INT_SIGNED, false, 8, "char");
	types[T_32PRCHAR] = new PDBTypeBase(0x00000470, PDBBASETYPE_INT_SIGNED, true, 8, "char *");
	types[T_WCHAR] = new PDBTypeBase(0x00000071, PDBBASETYPE_INT_SIGNED, false, 16, "wchar_t");
	types[T_32PWCHAR] = new PDBTypeBase(0x00000471, PDBBASETYPE_INT_SIGNED, true, 16, "wchar_t *");
	types[T_INT1] = new PDBTypeBase(0x00000068, PDBBASETYPE_INT_SIGNED, false, 8, "char");
	types[T_32PINT1] = new PDBTypeBase(0x00000468, PDBBASETYPE_INT_SIGNED, true, 8, "char *");
	types[T_UINT1] = new PDBTypeBase(0x00000069, PDBBASETYPE_INT_UNSIGNED, false, 8, "unsigned char");
	types[T_32PUINT1] = new PDBTypeBase(0x00000469, PDBBASETYPE_INT_UNSIGNED, true, 8, "unsigned char *");
	types[T_SHORT] = new PDBTypeBase(0x00000011, PDBBASETYPE_INT_SIGNED, false, 16, "short");
	types[T_32PSHORT] = new PDBTypeBase(0x00000411, PDBBASETYPE_INT_SIGNED, true, 16, "short *");
	types[T_USHORT] = new PDBTypeBase(0x00000021, PDBBASETYPE_INT_UNSIGNED, false, 16, "unsigned short");
	types[T_32PUSHORT] = new PDBTypeBase(0x00000421, PDBBASETYPE_INT_UNSIGNED, true, 16, "unsigned short *");
	types[T_INT2] = new PDBTypeBase(0x00000072, PDBBASETYPE_INT_SIGNED, false, 16, "short");
	types[T_32PINT2] = new PDBTypeBase(0x00000472, PDBBASETYPE_INT_SIGNED, true, 16, "short *");
	types[T_UINT2] = new PDBTypeBase(0x00000073, PDBBASETYPE_INT_UNSIGNED, false, 16, "unsigned short");
	types[T_32PUINT2] = new PDBTypeBase(0x00000473, PDBBASETYPE_INT_UNSIGNED, true, 16, "unsigned short *");
	types[T_LONG] = new PDBTypeBase(0x00000012, PDBBASETYPE_INT_SIGNED, false, 32, "long");
	types[T_32PLONG] = new PDBTypeBase(0x00000412, PDBBASETYPE_INT_SIGNED, true, 32, "long *");
	types[T_ULONG] = new PDBTypeBase(0x00000022, PDBBASETYPE_INT_UNSIGNED, false, 32, "unsigned long");
	types[T_32PULONG] = new PDBTypeBase(0x00000422, PDBBASETYPE_INT_UNSIGNED, true, 32, "unsigned long *");
	types[T_INT4] = new PDBTypeBase(0x00000074, PDBBASETYPE_INT_SIGNED, false, 32, "int");
	types[T_32PINT4] = new PDBTypeBase(0x00000474, PDBBASETYPE_INT_SIGNED, true, 32, "int *");
	types[T_UINT4] = new PDBTypeBase(0x00000075, PDBBASETYPE_INT_UNSIGNED, false, 32, "unsigned int");
	types[T_32PUINT4] = new PDBTypeBase(0x00000475, PDBBASETYPE_INT_UNSIGNED, true, 32, "unsigned int *");
	types[T_QUAD] = new PDBTypeBase(0x00000013, PDBBASETYPE_INT_SIGNED, false, 64, "long long");
	types[T_32PQUAD] = new PDBTypeBase(0x00000413, PDBBASETYPE_INT_SIGNED, true, 64, "long long *");
	types[T_UQUAD] = new PDBTypeBase(0x00000023, PDBBASETYPE_INT_UNSIGNED, false, 64, "unsigned long long");
	types[T_32PUQUAD] = new PDBTypeBase(0x00000423, PDBBASETYPE_INT_UNSIGNED, true, 64, "unsigned long long *");
	types[T_INT8] = new PDBTypeBase(0x00000076, PDBBASETYPE_INT_SIGNED, false, 64, "long long");
	types[T_32PINT8] = new PDBTypeBase(0x00000476, PDBBASETYPE_INT_SIGNED, true, 64, "long long *");
	types[T_UINT8] = new PDBTypeBase(0x00000077, PDBBASETYPE_INT_UNSIGNED, false, 64, "unsigned long long");
	types[T_32PUINT8] = new PDBTypeBase(0x00000477, PDBBASETYPE_INT_UNSIGNED, true, 64, "unsigned long long *");
	// INT128
	types[T_REAL32] = new PDBTypeBase(0x00000040, PDBBASETYPE_FLOAT, false, 32, "float");
	types[T_32PREAL32] = new PDBTypeBase(0x00000440, PDBBASETYPE_FLOAT, true, 32, "float *");
	types[T_REAL48] = new PDBTypeBase(0x00000044, PDBBASETYPE_FLOAT, false, 48, "float48");
	types[T_32PREAL48] = new PDBTypeBase(0x00000444, PDBBASETYPE_FLOAT, true, 48, "float48 *");
	types[T_REAL64] = new PDBTypeBase(0x00000041, PDBBASETYPE_FLOAT, false, 64, "double");
	types[T_32PREAL64] = new PDBTypeBase(0x00000441, PDBBASETYPE_FLOAT, true, 64, "double *");
	types[T_REAL80] = new PDBTypeBase(0x00000042, PDBBASETYPE_FLOAT, false, 80, "float80");
	types[T_32PREAL80] = new PDBTypeBase(0x00000442, PDBBASETYPE_FLOAT, true, 80, "float80 *");
	types[T_REAL128] = new PDBTypeBase(0x00000043, PDBBASETYPE_FLOAT, false, 128, "float128");
	types[T_32PREAL128] = new PDBTypeBase(0x00000443, PDBBASETYPE_FLOAT, true, 128, "float128 *");
	// CPLX
	types[T_BOOL08] = new PDBTypeBase(0x00000030, PDBBASETYPE_BOOL, false, 8, "bool");
	types[T_32PBOOL08] = new PDBTypeBase(0x00000430, PDBBASETYPE_BOOL, true, 8, "bool *");
	types[T_BOOL16] = new PDBTypeBase(0x00000031, PDBBASETYPE_BOOL, false, 16, "bool");
	types[T_32PBOOL16] = new PDBTypeBase(0x00000431, PDBBASETYPE_BOOL, true, 16, "bool *");
	types[T_BOOL32] = new PDBTypeBase(0x00000032, PDBBASETYPE_BOOL, false, 32, "bool");
	types[T_32PBOOL32] = new PDBTypeBase(0x00000432, PDBBASETYPE_BOOL, true, 32, "bool *");
	types[T_BOOL64] = new PDBTypeBase(0x00000033, PDBBASETYPE_BOOL, false, 64, "bool");
	types[T_32PBOOL64] = new PDBTypeBase(0x00000433, PDBBASETYPE_BOOL, true, 64, "bool *");
	// NCVPTR

	// User-defined types
	unsigned int position = sizeof(HDR);
	int index = tpi_header->tiMin;
	while (position < pdb_tpi_size)
	{  // Process all data-type records in TPI stream
		PDBGeneralSymbol * symbol = reinterpret_cast<PDBGeneralSymbol *>(pdb_tpi_data + position);
		lfRecord * record = reinterpret_cast<lfRecord *>(pdb_tpi_data + position + 2);

		switch (record->leaf)
		{
			case LF_FIELDLIST:
			{
				PDBTypeFieldList *new_type = new PDBTypeFieldList(index);
				new_type->parse(&record->FieldList, symbol->size, types);
				types[index] = new_type;
				break;
			}
			case LF_ENUM:
			{
				PDBTypeEnum *new_type = new PDBTypeEnum(index);
				new_type->parse(&record->Enum, symbol->size, types);
				types[index] = new_type;
				if (new_type->is_fully_defined())
				{
					types_fully_defined[index] = new_type;
					types_byname[new_type->enum_name] = new_type;
				}
				break;
			}
			case LF_ARRAY:
			{
				PDBTypeArray *new_type = new PDBTypeArray(index);
				new_type->parse(&record->Array, symbol->size, types);
				types[index] = new_type;
				break;
			}
			case LF_POINTER:
			{
				PDBTypePointer *new_type = new PDBTypePointer(index);
				new_type->parse(&record->Pointer, symbol->size, types);
				types[index] = new_type;
				break;
			}
			case LF_MODIFIER:
			{
				PDBTypeConst *new_type = new PDBTypeConst(index);
				new_type->parse(&record->Modifier, symbol->size, types);
				types[index] = new_type;
				break;
			}
			case LF_ARGLIST:
			{
				PDBTypeArglist *new_type = new PDBTypeArglist(index);
				new_type->parse(&record->ArgList, symbol->size, types);
				types[index] = new_type;
				break;
			}
			case LF_PROCEDURE:
			{
				PDBTypeFunction *new_type = new PDBTypeFunction(index);
				new_type->parse(&record->Proc, symbol->size, types);
				types[index] = new_type;
				break;
			}
			case LF_MFUNCTION:
			{
				PDBTypeFunction *new_type = new PDBTypeFunction(index);
				new_type->parse_mfunc(&record->MFunc, symbol->size, types);
				types[index] = new_type;
				break;
			}
			case LF_STRUCTURE:
			{
				PDBTypeStruct *new_type = new PDBTypeStruct(index);
				new_type->parse(&record->Structure, symbol->size, types);
				types[index] = new_type;
				if (new_type->is_fully_defined())
				{
					types_fully_defined[index] = new_type;
					types_byname[new_type->struct_name] = new_type;
				}
				break;
			}
			case LF_UNION:
			{
				PDBTypeUnion *new_type = new PDBTypeUnion(index);
				new_type->parse(&record->Union, symbol->size, types);
				types[index] = new_type;
				if (new_type->is_fully_defined())
				{
					types_fully_defined[index] = new_type;
					types_byname[new_type->union_name] = new_type;
				}
				break;
			}
			case LF_CLASS:
			{
				PDBTypeClass *new_type = new PDBTypeClass(index);
				new_type->parse(&record->Class, symbol->size, types);
				types[index] = new_type;
				if (new_type->is_fully_defined())
				{
					types_fully_defined[index] = new_type;
					types_byname[new_type->class_name] = new_type;
				}
				break;
			}
			default:
				break;
		}

		position += symbol->size + 2;  // Go to next record
		index++;
	}
	parsed = true;
}

void PDBTypes::dump_types(void)
{
	puts("******* TPI list of types (dump) *******");
	DisplayTypes(pdb_tpi_data, pdb_tpi_size);
	puts("");
}

void PDBTypes::print_types(void)
{
	puts("******* TPI list of types (parsed types) *******");
	if (!parsed)
	{
		puts("Types not parsed yet!\n");
		return;
	}
	for (PDBTypeDefIndexMap::iterator it = types_fully_defined.begin(); it != types_fully_defined.end(); ++it)
	{
		if (it->second != nullptr)
		{
			it->second->dump();
			puts("");
		}
	}
	puts("");
}

PDBTypes::~PDBTypes(void)
{
	for (PDBTypeDefIndexMap::iterator it = types.begin(); it != types.end(); ++it)
	{  // Delete all parsed types
		if (it->second != nullptr)
			delete it->second;
	}
}

} // namespace pdbparser
} // namespace retdec
