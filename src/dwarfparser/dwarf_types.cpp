/**
 * @file src/dwarfparser/dwarf_types.cpp
 * @brief Implementaion of classes representing data types.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <iostream>
#include <sstream>

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#include "retdec/dwarfparser/dwarf_file.h"
#include "retdec/dwarfparser/dwarf_types.h"
#include "retdec/dwarfparser/dwarf_vars.h"

using namespace std;

namespace retdec {
namespace dwarfparser {

/*
 * =============================================================================
 * DwarfTypeContainer
 * =============================================================================
 */

/**
 * @brief ctor.
 * @param file Pointer to dwarfparser representation of DWARF file which owns this container.
 * @param elem Pointer to parent element that owns this container.
 */
DwarfTypeContainer::DwarfTypeContainer(DwarfFile *file, DwarfBaseElement *elem) :
		DwarfBaseContainer<DwarfType>(file, elem),
		m_void(this, 0)
{
	m_void.name = "void";
	m_void.bitSize = 0;
	m_void.dataType = DwarfType::BASE;
}

/**
 * @brief Test if provided DIE was already loaded.
 * @param off DIE offset to test.
 * @return Pointer to object that was created from die or nullptr if not loaded yet.
 */
DwarfType *DwarfTypeContainer::checkIfLoaded(Dwarf_Off off)
{
	map<Dwarf_Off, DwarfType*>::iterator fIt;
	fIt = m_typeCache.find(off);
	if (fIt == m_typeCache.end())
		return nullptr;
	else
		return (fIt->second);
}

/**
 * @brief Get all data from data type DIE and return newly created object.
 * @param die Data type unit DIE.
 * @param lvl Level (depth) of this die.
 * @return Pointer to newly created data type object or nullptr if failed.
 */
DwarfType *DwarfTypeContainer::loadAndGetDie(Dwarf_Die die, unsigned)
{
	DwarfType *newType = nullptr;

	AttrProcessor ap(m_parentFile->m_dbg, die, m_parentFile);
	Dwarf_Off off = ap.getDieOff();

	// Disabled, if is too slow, it is better to just create another type.
	// Die was already loaded.
	if ((newType = checkIfLoaded(off)) != nullptr)
	{
		return newType;
	}

	// Get DIE tag.
	Dwarf_Half tag = 0;
	if (dwarf_tag(die, &tag, &m_error) != DW_DLV_OK)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return nullptr;
	}

	//
	// Do not try to find declarations for unprocessed types.
	//
	switch (tag)
	{
		case DW_TAG_file_type:
		case DW_TAG_interface_type:
		case DW_TAG_ptr_to_member_type:
		case DW_TAG_set_type:
		case DW_TAG_string_type:
		case DW_TAG_thrown_type:
		case DW_TAG_unspecified_type:
			return nullptr;
			break;

		default:
			// continue for all other types.
			break;
	}

	//
	// If this DIE have DW_AT_specification, then it inherits from some other DIE with DW_AT_declaration.
	// TODO: This expects that DW_AT_declaration will be before DW_AT_specification, otherwise it wont be
	// discovered (searching in already processed DIEs).
	// It also expects that each DW_AT_declaration is specified only once -- original DIE offset will be
	// replaced by the current one, so it wont be possible to find it again.
	// Even if we did not do this, it would not be easy to inherit twice -- original DIE could not be
	// directly completed by entries in this one, because other inheritance probably could have other entries.
	// There would need to be some deep copy mechanism -- copy original to new object and complete it.
	//
	Dwarf_Off ref = EMPTY_UNSIGNED;
	ap.get(DW_AT_specification, ref);

	// This is indeed a specification DIE.
	bool found = false;
	if (ref != EMPTY_UNSIGNED)
	{
		newType = static_cast<DwarfType*>( this->getElemByOffset(ref) );

		if (newType != nullptr)
		{
			found = true;
			newType->addOffset( ap.getDieOff() );
		}
	}

	// This is not a specification DIE, or declaration was not found.
	if (newType == nullptr)
	{
		// Decide what to do based on tag type.
		switch (tag)
		{
			//
			// Base type.
			//
			case DW_TAG_base_type: newType = new DwarfType(this, off); break;

			//
			// Composite types.
			//
			case DW_TAG_array_type:       newType = new DwarfArrayType(this, off);    break;
			case DW_TAG_enumeration_type: newType = new DwarfEnumType(this, off);     break;
			case DW_TAG_structure_type:   newType = new DwarfStructType(this, off);   break;
			case DW_TAG_union_type:       newType = new DwarfUnionType(this, off);    break;
			case DW_TAG_subroutine_type:  newType = new DwarfFunctionType(this, off); break;
			case DW_TAG_typedef:          newType = new DwarfTypedefType(this, off);  break;
			case DW_TAG_class_type:       newType = new DwarfClassType(this, off);    break;

			//
			// Modifier types.
			//
			case DW_TAG_const_type:            newType = new DwarfConstType(this, off);         break;
			case DW_TAG_packed_type:           newType = new DwarfPackedType(this, off);        break;
			case DW_TAG_pointer_type:          newType = new DwarfPointerType(this, off);       break;
			case DW_TAG_reference_type:        newType = new DwarfReferenceType(this, off);     break;
			case DW_TAG_restrict_type:         newType = new DwarfRestrictType(this, off);      break;
			case DW_TAG_rvalue_reference_type: newType = new DwarfRValReferenceType(this, off); break;
			case DW_TAG_shared_type:           newType = new DwarfSharedType(this, off);        break;
			case DW_TAG_volatile_type:         newType = new DwarfVolatileType(this, off);      break;

			//
			// Unprocessed tags.
			//
			case DW_TAG_file_type:
			case DW_TAG_interface_type:
			case DW_TAG_ptr_to_member_type:
			case DW_TAG_set_type:
			case DW_TAG_string_type:
			case DW_TAG_thrown_type:
			case DW_TAG_unspecified_type:
			default:
				delete newType;
				return nullptr;
		}
	}

	static std::map<Dwarf_Off, DwarfType*> inProgress;
	auto fIt = inProgress.find(off);
	if (fIt != inProgress.end())
	{
		auto* ret = fIt->second;
		inProgress.erase(off);
		delete newType;
		return ret;
	}
	else
	{
		inProgress[off] = newType;
	}

	// Load and save new type.
	newType->load(ap);

	inProgress.erase(off);

	if (!found)
		m_data.push_back(newType);

	// Add to cache.
	m_typeCache[off] = newType;

	return newType;
}

/**
 * @brief Print contents of this container.
 */
void DwarfTypeContainer::dump() const
{
	cout << endl;
	cout << "==================== Types ====================" << endl;

	if (m_data.empty())
	{
		cout << "NO base type information." << endl;
		return;
	}

	DwarfBaseContainer<DwarfType>::dump();
	cout << endl;
}

/**
 * @brief Get data type by its name.
 * @param n Name of data type to get.
 * @return Pointer to data type object if found, nullptr otherwise.
 */
DwarfType *DwarfTypeContainer::getTypeByName(string n)
{
	for (iterator it=begin(); it!=end(); ++it)
	{
		if ((*it)->name == n)
		{
			return (*it);
		}
	}

	return nullptr;
}

/**
 * @brief Get void data type.
 * @return Pointer to void data type.
 */
DwarfType *DwarfTypeContainer::getVoid()
{
	return &m_void;
}

/**
 * @brief Load provided DIE as data type and return its flags.
 * @param die Data type unit DIE.
 * @param lvl Level (depth) of this die.
 * @return Flags of loaded data type.
 *
 * TODO: toto sa mi nepaci, naco to je, neda sa to lepsie?
 */
int DwarfTypeContainer::getDieFlags(Dwarf_Die die, unsigned lvl)
{
	loadAndGetDie(die, lvl);

	int flags = 0;
	int f = 0;

	// Get DIE tag.
	Dwarf_Half tag = 0;
	if (dwarf_tag(die, &tag, &m_error) != DW_DLV_OK)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return DwarfVar::EMPTY;
	}

	AttrProcessor ap(m_parentFile->m_dbg, die, m_parentFile);

	// Decide what to do based on tag type.
	switch (tag)
	{
		case DW_TAG_const_type:
			flags += DwarfVar::CONSTANT;
			ap.geti(DW_AT_type, f);
			break;

		case DW_TAG_pointer_type:
			flags += DwarfVar::POINTER;
			ap.geti(DW_AT_type, f);
			break;

		case DW_TAG_restrict_type:
			flags += DwarfVar::RESTRICT;
			ap.geti(DW_AT_type, f);
			break;

		case DW_TAG_volatile_type:
			flags += DwarfVar::VOLATILE;
			ap.geti(DW_AT_type, f);
			break;

		default:

			break;
	}

	flags += f;
	return flags;
}

/*
 * =============================================================================
 * DwarfType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfType, DwarfType::BASE);

const char * DwarfType::eDataTypeString[] =
{
	"BASE TYPE",
	"ARRAY",
	"ENUMERATION",
	"FUNCTION",
	"STRUCTURE",
	"TYPEDEF",
	"UNION",
	"CLASS",
	"CONSTANT",
	"PACKED",
	"POINTER",
	"REFERENCE",
	"RESTRICT",
	"RVAL_REFERENCE",
	"SHARED",
	"VOLATILE"
};

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfType::DwarfType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfBaseElement(DwarfBaseElement::TYPE, reinterpret_cast<DwarfBaseContainer<DwarfBaseElement>*>(prnt), o),
		bitSize(EMPTY_UNSIGNED),
		encoding(EMPTY_UNSIGNED),
		dataType(BASE)
{

}

/**
 * @brief Load base attributes -- name and bitsize.
 * @param ap Reference to helper class providing access to attributes.
 */
void DwarfType::load(AttrProcessor &ap)
{
	string n;
	Dwarf_Unsigned e;

	ap.get(DW_AT_name, n);
	ap.get(DW_AT_encoding, e);
	if (n != EMPTY_STR) name = n;
	if (e != EMPTY_UNSIGNED) encoding = e;

	Dwarf_Unsigned bitSz = EMPTY_UNSIGNED;
	ap.get(DW_AT_bit_size, bitSz);
	if (bitSz == EMPTY_UNSIGNED)
	{
		ap.get(DW_AT_byte_size, bitSz);
		if (bitSz != EMPTY_UNSIGNED)
		{
			bitSz *= BITS_IN_BYTE;
		}
	}

	if (bitSz != EMPTY_UNSIGNED) bitSize = bitSz;
}

/**
 * @brief Print contents of this class.
 */
void DwarfType::dump() const
{
	cout << dumpNameAndOffset() << endl;
	cout << "\t" << eDataTypeString[dataType] << endl;

	if (bitSize != EMPTY_UNSIGNED)
		cout << "\tBit size    :  " << bitSize << " (" << getByteSize() << " bytes)" << endl;
	else
		cout << "\tBit size    :  NOT_SET" << endl;
	cout << "\tLLVM IR     :  " << toLLVMString() << endl;

	cout << endl;
}

/**
 * @brief Dump name of type and offset of DIE it comes from.
 * @return Name and offset of type.
 */
string DwarfType::dumpNameAndOffset() const
{
	stringstream ss;
	if (name.empty())
		ss << "<EMPTY_NAME>";
	else
		ss << name;
	ss << "\t" << getDwarfdump2OffsetString();

	return ss.str();
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 * @return String representing this type.
 */
string DwarfType::toLLVMString() const
{
	stringstream ret;

	//
	// Void.
	//
	if (name == "void")
		return "void";

	//
	// Check.
	//
	if ((dataType != BASE) ||
		(encoding == EMPTY_UNSIGNED))
	{
		return "";
	}

	//
	// Boolean.
	//
	if (encoding == DW_ATE_boolean)
	{
		ret << "i1";
	}

	//
	// Integer and char.
	//
	if (encoding == DW_ATE_signed ||
		encoding == DW_ATE_signed_char ||
		encoding == DW_ATE_unsigned ||
		encoding == DW_ATE_unsigned_char ||
		encoding == DW_ATE_signed_fixed ||
		encoding == DW_ATE_unsigned_fixed)
	{
		ret << "i" << getBitSize();
	}

	//
	// Floating point.
	//
	if (encoding == DW_ATE_complex_float ||
		encoding == DW_ATE_float ||
		encoding == DW_ATE_imaginary_float ||
		encoding == DW_ATE_decimal_float)
	{
		switch (getBitSize())
		{
			case 16: ret << "half"; break;
			case 32: ret << "float"; break;
			case 64: ret << "double"; break;
			case 128: ret << "fp128"; break;
			case 80: ret << "x86_fp80"; break;
			default: ret << "double"; break;
		}
	}

	//
	// Not processed at the moment.
	//
	if (encoding == DW_ATE_address ||
		encoding == DW_ATE_packed_decimal ||
		encoding == DW_ATE_numeric_string ||
		encoding == DW_ATE_edited ||
		//encoding == DW_ATE_UTF || // Defined in DWARF specification, missing in libdwarf.
		encoding == DW_ATE_lo_user ||
		encoding == DW_ATE_hi_user)
	{
		return "";
	}

	return ret.str();
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 *        If possible then use type identifier instead of full definition.
 * @return String representing this type.
 */
string DwarfType::toLLVMStringIdentified() const
{
	return toLLVMString();
}

/**
 * @brief Get bit size of data type.
 * @return Bit size of data type.
 */
Dwarf_Unsigned DwarfType::getBitSize() const
{
	return bitSize;
}

/**
 * @brief Get byte size of data type.
 * @return Byte size of data type.
 */
Dwarf_Unsigned DwarfType::getByteSize() const
{
	if (bitSize == EMPTY_UNSIGNED)
		return EMPTY_UNSIGNED;

	if (bitSize % BITS_IN_BYTE != 0)
		DWARF_WARNING("Bitsize: \"" << bitSize << "\" modulo bits in byte: \"" << BITS_IN_BYTE << "\" is not zero.");

	return (bitSize / BITS_IN_BYTE);
}

/**
 * @brief Returns underlying type behind this type.
 *        Underlying is the first non-modifier data type.
 *        Non-modifier data types return themselves.
 * @return Pointer to underlying type.
 */
DwarfType *DwarfType::getUnderlyingType()
{
	DwarfType *res = this;
	DwarfModifierType *tmp = nullptr;

	while ((tmp = dynamic_cast<DwarfModifierType*>(res)))
	{
		res = tmp->baseType;
	}

	return res;
}

/*
 * =============================================================================
 * DwarfArrayType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfArrayType, DwarfType::ARRAY);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfArrayType::DwarfArrayType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfType(prnt, o),
		baseType(nullptr)
{
	dataType = DwarfType::ARRAY;
}

/**
 * @brief Load array specific attributes.
 * @param ap Reference to helper class providing access to attributes.
 */
void DwarfArrayType::load(AttrProcessor &ap)
{
	this->DwarfType::load(ap);

	DwarfType *t = nullptr;
	ap.get(DW_AT_type, t);
	if (t != nullptr && (baseType == nullptr || t != getParentFile()->getTypes()->getVoid())) baseType = t;

	bitSize = 0;

	if (baseType == nullptr)
	{
		DWARF_ERROR("DwarfArrayType::load -- no base type of array.");
		assert(baseType != nullptr);
	}
}

/**
 * @brief Print contents of this class.
 */
void DwarfArrayType::dump() const
{
	this->DwarfType::dump();

	cout << "\tBase. type  :  " << baseType->dumpNameAndOffset() << endl;
	cout << "\tDimensions  :  " << dimensionBounds.size() << endl;
	for (std::size_t i=0; i<dimensionBounds.size(); i++)
	{
		cout << "\t  bound #" << i << "  :  " << dimensionBounds[i] << endl;
	}
	cout << endl;
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 * @return String representing this type.
 */
string DwarfArrayType::toLLVMString() const
{
	stringstream ret;

	for (std::size_t i=0; i<dimensionBounds.size(); i++)
		ret << "[ " << dimensionBounds[i]+1 << " x ";

	ret << baseType->toLLVMStringIdentified();

	for (std::size_t i=0; i<dimensionBounds.size(); i++)
		ret << " ]";

	return ret.str();
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 *        If possible then use type identifier instead of full definition.
 * @return String representing this type.
 */
string DwarfArrayType::toLLVMStringIdentified() const
{
	return toLLVMString();
}

/**
 * @brief Add array dimension.
 * @param d Dimension to add.
 */
void DwarfArrayType::addDimension(Dwarf_Unsigned d)
{
	dimensionBounds.push_back(d);
	updateSize();
}

/**
 * @brief Update array bit size.
 */
void DwarfArrayType::updateSize()
{
	Dwarf_Unsigned sz = 0;

	for (std::size_t i=0; i<dimensionBounds.size(); i++)
	{
		sz += dimensionBounds[i] + 1;
	}
	sz *= baseType->bitSize;

	bitSize = sz;
}

/**
 * @brief Get number of array dimensions.
 * @return Number of array dimensions.
 */
std::size_t DwarfArrayType::dimensionCount()
{
	return dimensionBounds.size();
}

/*
 * =============================================================================
 * DwarfEnumType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfEnumType, DwarfType::ENUMERATION);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfEnumType::DwarfEnumType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfType(prnt, o),
		baseType(nullptr)
{
	dataType = DwarfType::ENUMERATION;
}

/**
 * @brief Load enumeration specific attributes.
 * @param ap Reference to helper class providing access to attributes.
 */
void DwarfEnumType::load(AttrProcessor &ap)
{
	this->DwarfType::load(ap);

	DwarfType *t = nullptr;
	ap.get(DW_AT_type, t);
	if (t != nullptr && (baseType == nullptr || t != getParentFile()->getTypes()->getVoid())) baseType = t;

	if (baseType == nullptr)
	{
		DWARF_ERROR("DwarfEnumType::load -- no base type of enumeration.");
		assert(baseType != nullptr);
	}
}

/**
 * @brief Print contents of this class.
 */
void DwarfEnumType::dump() const
{
	this->DwarfType::dump();

	cout << "\tBase. type  :  " << baseType->dumpNameAndOffset() << endl;
	cout << "\tEnumerators :  " << members.size() << endl;
	for (std::size_t i=0; i<members.size(); i++)
	{
		cout << "\t  enum #" << i << "   :  " << members[i].name
			 << "  (" << members[i].constVal << ")" << endl;
	}
	cout << endl;
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 * @return String representing this type.
 */
string DwarfEnumType::toLLVMString() const
{
	return "i32";
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 *        If possible then use type identifier instead of full definition.
 * @return String representing this type.
 */
string DwarfEnumType::toLLVMStringIdentified() const
{
	return toLLVMString();
}

/**
 * @brief Add enumeration member.
 * @brief m Member to add.
 */
void DwarfEnumType::addMember(EnumMember m)
{
	members.push_back(m);
}

/**
 * @brief Get number of enumeration members.
 * @return Number of enumeration members.
 */
std::size_t DwarfEnumType::memberCount()
{
	return members.size();
}

/*
 * =============================================================================
 * DwarfStructType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfStructType, DwarfType::STRUCTURE);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfStructType::DwarfStructType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfType(prnt, o)
{
	dataType = DwarfType::STRUCTURE;
}

/**
 * @brief dctor.
 */
DwarfStructType::~DwarfStructType()
{
	for (std::size_t i=0; i<members.size(); i++)
	{
		delete  members[i].location;
		members[i].location = nullptr;
	}
}

/**
 * @brief Load structure specific attributes.
 * @param ap Reference to helper class providing access to attributes.
 */
void DwarfStructType::load(AttrProcessor &ap)
{
	this->DwarfType::load(ap);

	static unsigned anonCntr = 0;
	if (name.empty())
	{
		name = "anon_struct_" + std::to_string(anonCntr++);
	}
}

/**
 * @brief Print contents of this class.
 */
void DwarfStructType::dump() const
{
	this->DwarfType::dump();

	cout << "\tMembers     :  " << members.size() << endl;
	for (std::size_t i=0; i<members.size(); i++)
	{
		const char *out;
		dwarf_get_ACCESS_name(members[i].getAccess(), &out);

		cout << "\t  member #" << i << " :  " << members[i].name
		     << ", type : " << members[i].type->getDwarfdump2OffsetString()
		     << ", access : " << out
		     << endl;
	}
	cout << endl;
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 * @return String representing this type.
 */
string DwarfStructType::toLLVMString() const
{
	bool first = true;
	stringstream ret;

	if (!name.empty())
		ret << "%" << name << " = type ";
	ret << "{";

	vector<StructMember>::const_iterator iter;
	for (iter=members.begin(); iter != members.end(); ++iter)
	{
		if (!first)
			ret << ",";
		else
			first = false;

		ret << " " << (*iter).type->toLLVMStringIdentified();
	}

	if (members.empty())
	{
		ret << "i32";
	}

	ret << " }";
	return ret.str();
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 *        If possible then use type identifier instead of full definition.
 * @return String representing this type.
 */
string DwarfStructType::toLLVMStringIdentified() const
{
	return ( "%" + name );
}

/**
 * @brief Add structure member.
 * @param m Member to add.
 */
void DwarfStructType::addMember(StructMember m)
{
	members.push_back(m);
}

/**
 * @brief Add static structure member.
 * @param m Member to add.
 */
void DwarfStructType::addStaticMember(StructMember m)
{
	staticMembers.push_back(m);
}

/**
 * @brief Get number of structure members.
 * @return Number of structure members.
 */
std::size_t DwarfStructType::memberCount()
{
	return members.size();
}

/*
 * =============================================================================
 * DwarfUnionType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfUnionType, DwarfType::UNION);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfUnionType::DwarfUnionType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfStructType(prnt, o)
{
	dataType = DwarfType::UNION;
}

/*
 * =============================================================================
 * DwarfClassType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfClassType, DwarfType::CLASS);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfClassType::DwarfClassType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfStructType(prnt, o)
{
	dataType = DwarfType::CLASS;
}

/**
 * @brief Load class specific attributes.
 * @param ap Reference to helper class providing access to attributes.
 */
void DwarfClassType::load(AttrProcessor &ap)
{
	this->DwarfStructType::load(ap);
}

/**
 * @brief Print contents of this class.
 */
void DwarfClassType::dump() const
{
	this->DwarfStructType::dump();

	cout << "\tFunction Members     :  " << memberFunctions.size() << endl;
	for (std::size_t i=0; i<memberFunctions.size(); i++)
	{
		cout << "\t  function #" << i << " :  " << memberFunctions[i]->name
		     << memberFunctions[i]->getDwarfdump2OffsetString() << endl;
	}
	cout << endl;

	cout << "\tBase Classes         :  " << baseClasses.size() << endl;
	for (std::size_t i=0; i<baseClasses.size(); i++)
	{
		const char *out;
		dwarf_get_ACCESS_name(baseClasses[i].getAccess(), &out);

		cout << "\t  class #" << i << " :  " << baseClasses[i].getBase()->name
		     << baseClasses[i].getBase()->getDwarfdump2OffsetString()
		     << ", access : " << out << endl;
	}
	cout << endl;
}

/*
 * =============================================================================
 * DwarfTypedefType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfTypedefType, DwarfType::TYPEDEF);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfTypedefType::DwarfTypedefType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfType(prnt, o),
		baseType(nullptr)
{
	dataType = DwarfType::TYPEDEF;
}

/**
 * @brief Load typedef specific attributes.
 * @param ap Reference to helper class providing access to attributes.
 */
void DwarfTypedefType::load(AttrProcessor &ap)
{
	this->DwarfType::load(ap);

	DwarfType *t = nullptr;
	ap.get(DW_AT_type, t);
	if (t != nullptr && (baseType == nullptr || t != getParentFile()->getTypes()->getVoid())) baseType = t;

	bitSize = baseType->bitSize;

	if (baseType == nullptr)
	{
		DWARF_ERROR("DwarfTypedefType::load -- no base type of typedef.");
		assert(baseType != nullptr);
	}

	if (baseType->name.empty())
	{
		baseType->name = name;
	}
}

/**
 * @brief Print contents of this class.
 */
void DwarfTypedefType::dump() const
{
	this->DwarfType::dump();

	cout << "\tOrig. type  :  " << baseType->dumpNameAndOffset() << endl;
	cout << endl;
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 * @return String representing this type.
 */
string DwarfTypedefType::toLLVMString() const
{
	return baseType->toLLVMString();
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 *        If possible then use type identifier instead of full definition.
 * @return String representing this type.
 */
string DwarfTypedefType::toLLVMStringIdentified() const
{
	return baseType->toLLVMStringIdentified();
}

/*
 * =============================================================================
 * DwarfFunctionType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfFunctionType, DwarfType::FUNCTION);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfFunctionType::DwarfFunctionType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfType(prnt, o),
		type(nullptr),
		func(nullptr),
		isVariadic(false)
{
	dataType = DwarfType::FUNCTION;
	m_params = new DwarfVarContainer(getParentFile(), this);
}

/**
 * @brief dctor.
 */
DwarfFunctionType::~DwarfFunctionType()
{
	delete m_params;
}

/**
 * @brief Load pointer specific attributes.
 * @param ap Reference to helper class providing access to attributes.
 */
void DwarfFunctionType::load(AttrProcessor &ap)
{
	this->DwarfType::load(ap);

	DwarfType *t = nullptr;
	ap.get(DW_AT_type, t); // type returned by subroutine, if entry not found, it is set to void.
	if (t != nullptr && (type == nullptr || t != getParentFile()->getTypes()->getVoid())) type = t;

	if (type == nullptr)
	{
		DWARF_ERROR("DwarfFunctionType::load -- no return type of function.");
		assert(type != nullptr);
	}

	//
	// If types of the arguments necessary, then this entry owns next
	// argument description entries -> "m_parentFile->m_activeFunc = nullptr"
	// in "DwarfTypeContainer::loadAndGet" ???
	// So all next DW_TAG_formal_parameter DIEs will be associated with this
	// function type.
	//
}

/**
 * @brief Print contents of this class.
 */
void DwarfFunctionType::dump() const
{
	this->DwarfType::dump();

	if (func)
		cout << "\tReal func. :  " << func->name << endl;
	else
		cout << "\tReal func. :  UNKNOWN" << endl;
	cout << "\tParams cnt.:  " << dec << getParamCount() << endl;
	DwarfVarContainer::iterator iter = m_params->begin();
	while (iter != m_params->end())
	{
		cout << "\t   ";
		(*iter)->dump();
		++iter;
	}
	if (isVariadic)
		cout << "\t   ... variadic argument" << endl;
	cout << endl;
}

/**
 * @brief Convert function type to string that represents it in LLVM IR.
 * @return String representing this type.
 */
string DwarfFunctionType::toLLVMString() const
{
	static std::set<const DwarfType*> inProgress;
	if (inProgress.count(this))
	{
		inProgress.erase(this);
		return "i32";
	}
	else
	{
		inProgress.insert(this);
	}

	bool first = true;
	stringstream ret;

	ret << type->toLLVMStringIdentified();
	ret << " (";
	DwarfVarContainer::iterator iter;
	for (iter=m_params->begin(); iter!=m_params->end(); ++iter)
	{
		if (!first)
			ret << ", ";
		else
			first = false;

		ret << (*iter)->type->toLLVMStringIdentified();
	}
	ret << ")";

	inProgress.erase(this);
	return ret.str();
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 *        If possible then use type identifier instead of full definition.
 * @return String representing this type.
 */
string DwarfFunctionType::toLLVMStringIdentified() const
{
	return toLLVMString();
}

/**
 * @brief Test if function has parameters.
 * @return True if function has parameters, false otherwise.
 */
bool DwarfFunctionType::hasParams()
{
	return (m_params->size() != 0);
}

/**
 * @brief Get function's parameters.
 * @return Pointer to container of parameters.
 */
DwarfVarContainer *DwarfFunctionType::getParams()
{
	return m_params;
}

/**
 * @brief Get function's parameters.
 * @return Pointer to constant container of parameters.
 */
const DwarfVarContainer *DwarfFunctionType::getParams() const
{
	return m_params;
}

/**
 * @brief Get number of function's parameters.
 * @return Number of functions parameters.
 */
std::size_t DwarfFunctionType::getParamCount() const
{
	return m_params->size();
}

/*
 * =============================================================================
 * DwarfModifierType
 * =============================================================================
 */

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfModifierType::DwarfModifierType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfType(prnt, o),
		baseType(nullptr)
{

}

/**
 * @brief Load modifier specific attributes.
 * @param ap Reference to helper class providing access to attributes.
 */
void DwarfModifierType::load(AttrProcessor &ap)
{
	this->DwarfType::load(ap);

	DwarfType *t = nullptr;
	ap.get(DW_AT_type, t); // type returned by subroutine, if entry not found, it is set to void.
	if (t != nullptr && (baseType == nullptr || t != getParentFile()->getTypes()->getVoid())) baseType = t;
}

/**
 * @brief Print contents of this class.
 */
void DwarfModifierType::dump() const
{
	this->DwarfType::dump();

	cout << "\tModifier of :  " << baseType->dumpNameAndOffset() << endl;
	cout << endl;
}

/**
 * @brief Convert modifier type to string that represents it in LLVM IR.
 * @return String representing this type.
 */
string DwarfModifierType::toLLVMString() const
{
	return baseType->toLLVMStringIdentified();
}

/**
 * @brief Convert type to string that represents it in LLVM IR.
 *        If possible then use type identifier instead of full definition.
 * @return String representing this type.
 */
string DwarfModifierType::toLLVMStringIdentified() const
{
	return toLLVMString();
}

/*
 * =============================================================================
 * DwarfConstType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfConstType, DwarfType::CONSTANT);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfConstType::DwarfConstType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfModifierType(prnt, o)
{
	dataType = DwarfType::CONSTANT;
}

/*
 * =============================================================================
 * DwarfPackedType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfPackedType, DwarfType::PACKED);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfPackedType::DwarfPackedType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfModifierType(prnt, o)
{
	dataType = DwarfType::PACKED;
}

/*
 * =============================================================================
 * DwarfPointerType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfPointerType, DwarfType::POINTER);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfPointerType::DwarfPointerType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfModifierType(prnt, o)
{
	dataType = DwarfType::POINTER;
}

/**
 * @brief Convert pointer type to string that represents it in LLVM IR.
 * @return String representing this type.
 */
string DwarfPointerType::toLLVMString() const
{
	return baseType->toLLVMStringIdentified() + "*";
}

/**
 * @brief Returns pointer level -- count of pointers type between this
 *        pointer (including) and underlying type.
 *        Underlying is first non-pointer data type.
 * @return Pointer level.
 */
unsigned DwarfPointerType::getPointerLevel()
{
	unsigned res = 1;
	DwarfType *temp = nullptr;

	temp = baseType;
	while (temp->constructed_as<DwarfPointerType>())
	{
		temp = temp->leaf_cast<DwarfPointerType>()->baseType;
		res++;
	}

	return res;
}

/*
 * =============================================================================
 * DwarfReferenceType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfReferenceType, DwarfType::REFERENCE);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfReferenceType::DwarfReferenceType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfModifierType(prnt, o)
{
	dataType = DwarfType::REFERENCE;
}

/*
 * =============================================================================
 * DwarfRestrictType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfRestrictType, DwarfType::RESTRICT);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfRestrictType::DwarfRestrictType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfModifierType(prnt, o)
{
	dataType = DwarfType::RESTRICT;
}

/*
 * =============================================================================
 * DwarfRValReferenceType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfRValReferenceType, DwarfType::RVAL_REFERENCE);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfRValReferenceType::DwarfRValReferenceType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfModifierType(prnt, o)
{
	dataType = DwarfType::RVAL_REFERENCE;
}

/*
 * =============================================================================
 * DwarfSharedType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfSharedType, DwarfType::SHARED);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfSharedType::DwarfSharedType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfModifierType(prnt, o)
{
	dataType = DwarfType::SHARED;
}

/*
 * =============================================================================
 * DwarfVolatileType
 * =============================================================================
 */

DEF_DWARF_TYPE_TID(DwarfVolatileType, DwarfType::VOLATILE);

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 */
DwarfVolatileType::DwarfVolatileType(DwarfTypeContainer *prnt, Dwarf_Off o) :
		DwarfModifierType(prnt, o)
{
	dataType = DwarfType::VOLATILE;
}

} // namespace dwarfparser
} // namespace retdec
