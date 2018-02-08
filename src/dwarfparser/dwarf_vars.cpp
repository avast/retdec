/**
 * @file src/dwarfparser/dwarf_vars.cpp
 * @brief Implementataion of classes representing variables.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <iostream>

#include "retdec/dwarfparser/dwarf_file.h"
#include "retdec/dwarfparser/dwarf_functions.h"
#include "retdec/dwarfparser/dwarf_vars.h"

using namespace std;

namespace retdec {
namespace dwarfparser {

/**
 * @brief ctor.
 * @param file Pointer to dwarfparser representation of DWARF file which owns this container.
 * @param elem Pointer to parent element that owns this container.
 */
DwarfVarContainer::DwarfVarContainer(DwarfFile *file, DwarfBaseElement *elem) :
		DwarfBaseContainer<DwarfVar>(file, elem)
{

}

/**
 * @brief Print contents of this container.
 */
void DwarfVarContainer::dump() const
{
	cout << endl;
	cout << "==================== Variables ====================" << endl;

	// Is Empty?
	if (m_data.empty())
	{
		cout << "NO variable information." << endl;
		return;
	}

	// Header.
	cout << setw(30) << left << "Variable name";
	cout << setw(25) << left << "Variable type name";
	cout << setw(20) << left << "Flags" << endl;

	// Variables.
	DwarfBaseContainer<DwarfVar>::dump();

	cout << endl;
}

/**
 * @brief Get all data from function DIE.
 * @param die Function DIE.
 * @param lvl Level (depth) of this die.
 * @return Pointer to variable object if found, nullptr otherwise.
 */
DwarfVar *DwarfVarContainer::loadAndGetDie(Dwarf_Die die, unsigned)
{
	// Use special class to get attributes that we want.
	AttrProcessor ap(m_parentFile->m_dbg, die, m_parentFile);

	// TODO: Variables with DW_AT_declaration attribute are skipped at the moment.
	// These DIEs do not contain DW_AT_location attribute.
	// For each such DIE there should be another one that defines variable and
	// contains location.
	Dwarf_Bool isDeclr;
	ap.get(DW_AT_declaration, isDeclr);
	if (isDeclr)
		return nullptr;

	// TODO: Variables with DW_AT_abstract_origin are skipped at them moment.
	// They are inline instances of inline subprograms.
	// They mess-up subprogram parameters.
	Dwarf_Off ref = EMPTY_UNSIGNED;
	ap.get(DW_AT_abstract_origin, ref);
	if (ref != EMPTY_UNSIGNED)
		return nullptr;

	DwarfVar *v = new DwarfVar(this, ap.getDieOff());

	ap.get(DW_AT_name, v->name);
	ap.get(DW_AT_type, v->type);
	ap.geti(DW_AT_type, v->flags);

	ap.get(DW_AT_location, v->location);
	if (v->location)
	{
		v->location->setParent(v);
		if (m_parentElem != nullptr)
		{
			if (dynamic_cast<DwarfFunctionType*>(m_parentElem))
			{
				// no frame base
			}
			else if (DwarfFunction *f = dynamic_cast<DwarfFunction*>(m_parentElem))
			{
				v->location->setBaseFunc(f);
			}
			else
			{
				DWARF_WARNING("loadDie(): Unable to set frame base for variable: \"" << v->name << "\".");
			}
		}
	}

	Dwarf_Half tag = 0;
	dwarf_tag(die, &tag, &m_error);

	if (tag == DW_TAG_variable)
	{
		m_data.push_back(v);
		return v;
	}
	else if (tag == DW_TAG_formal_parameter)
	{
		return addParameter(v);
	}
	else
	{
		DWARF_ERROR("Unexpected tag.");
		return nullptr;
	}
}

/**
 * @brief Get variable by its name.
 * @param n Name of variable to get.
 * @return Pointer to variable object if found, nullptr otherwise.
 */
DwarfVar *DwarfVarContainer::getVarByName(string n)
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
 * @brief Add parameter co container. Check if it has unique name.
 * @param n Parameter to add.
 * @return Added parameter or existing one.
 *
 * TODO: podla mena to nie je 100%, v jednom DIE nemusi byt meno nastavene.
 * V jednom samplu sa dali unikatne prepojit podla DW_AT_decl_file + DW_AT_decl_line.
 * neviem ale ci je toto nastaven vzdy, ideal by bolo kontextove nacitanie, ktore by vedelo
 * ku ktorej funkcii parameter partri, ktory v poradi je a ak by na tom indexe uz nieco
 * existovalo tak by sa to len aktualizovalo a nevytvaralo nove.
 */
DwarfVar *DwarfVarContainer::addParameter(DwarfVar *n)
{
	if (n == nullptr)
		return n;

	for (iterator it=begin(); it!=end(); ++it)
	{
		// not empty -> params for DW_TAG_subroutine_type do not have names,
		// this may cause some other problems.
		//
		if (!n->name.empty() && (*it)->name == n->name)
		{
			(*it)->mergeWith(n);
			delete n;
			return (*it);
		}
	}

	m_data.push_back(n);
	return n;
}

/**
 * @brief ctor.
 * @param prnt Pointer to parent container owning this element.
 * @param off  Offset associated with this element in DWARF file - unique ID.
 * @param t    Type of DwarfBaseElement object.
 */
DwarfVar::DwarfVar(DwarfVarContainer *prnt, Dwarf_Off off,
		DwarfBaseElement::type_t t) :
				DwarfBaseElement(t, reinterpret_cast<DwarfBaseContainer<DwarfBaseElement>*>(prnt), off),
		flags(EMPTY),
		type(nullptr),
		location(nullptr)
{

}

/**
 * @brief dctor.
 */
DwarfVar::~DwarfVar()
{
	delete location;
}

/**
 * @brief Print contents of this class.
 */
void DwarfVar::dump() const
{
	string f;
	if (isConstant())
		f += " Const. ";
	if (isPointer())
		f += " Ptr. ";
	if (isRestrict())
		f += " Rest. ";
	if (isVolatile())
		f += " Volat. ";

	cout << setw(30) << left << name;
	cout << setw(25) << left << type->name;
	cout << setw(20) << left << f;
	cout << getDwarfdump2OffsetString() << endl;
}

/**
 * @brief Merge this variable with the provided one.
 *        Members that are not set in this are set from other.
 * @param o Other variable.
 */
void DwarfVar::mergeWith(DwarfVar *o)
{
	if (name.empty()) name = o->name;
	if (flags == EMPTY) flags = o->flags;
	if (type == nullptr) type = o->type;
	if (location == nullptr) { location = o->location; o->location = nullptr; }
}

/**
 * @brief Some variables may not have locations.
 * @return True if this variable has location, false otherwise.
 */
bool DwarfVar::hasLocation()
{
	return (location != nullptr);
}

/**
 * @brief Compute location of variable.
 * @param n  Pointer to string that will be filled by method.
 *        If variable location is address this is a name of address space.
 *        If variable location is register this is a name of register array.
 * @param a  Pointer to value that will be filled by method.
 *        If variable location is address this is an address in address space.
 *        If variable location is register this is a number in register array.
 * @param pc Program counter value. Does not need to be specified if resources was
 *        initialized.
 * @return Type of variable location - address or register.
 */
DwarfLocationDesc::cLocType DwarfVar::getLocation(string *n, Dwarf_Addr *a, Dwarf_Addr pc)
{
	if (location)
		return (location->computeLocation(n, a, pc));
	else
		return DwarfLocationDesc::FAIL;
}

/**
 * @brief If variable is on stack, get its offset from stack pointer;
 * @param a      Pointer to offset that will be filled by method.
 *        If variable is not on stack it will be set to zero.
 * @param deref  Pointer to boolean value that will be filled by method.
 *        If true then on address counted using returned offset is an
 *        address of variable data.
 *        If false then there are actual data on counted address.
 *        If variable is not on stack it will be set to false.
 * @param pc     Actual program counter.
 * @param regNum Register number.
 * @return True if variable on stack, false otherwise.
 */
bool DwarfVar::isOnStack(Dwarf_Signed *a, bool *deref, Dwarf_Addr pc, int *regNum)
{
	if (location)
		return location->isOnStack(a, deref, pc, regNum);
	else
		return false;
}

/**
 * @brief Test if variable is a constant.
 * @return True if variable is a constant, false otherwise.
 */
bool DwarfVar::isConstant() const
{
	return (flags & CONSTANT);
}

/**
 * @brief Test if variable is a pointer.
 * @return True if variable is a pointer, false otherwise.
 */
bool DwarfVar::isPointer() const
{
	return (flags & POINTER);
}

/**
 * @brief Test if variable is restrict.
 * @return True if variable is restrict, false otherwise.
 */
bool DwarfVar::isRestrict() const
{
	return (flags & RESTRICT);
}

/**
 * @brief Test if variable is volatile.
 * @return True if variable is volatile, false otherwise.
 */
bool DwarfVar::isVolatile() const
{
	return (flags & VOLATILE);
}

} // namespace dwarfparser
} // namespace retdec
