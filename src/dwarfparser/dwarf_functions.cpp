/**
 * @file src/dwarfparser/dwarf_functions.cpp
 * @brief Implementation of classes representing functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "retdec/dwarfparser/dwarf_base.h"
#include "retdec/dwarfparser/dwarf_file.h"
#include "retdec/dwarfparser/dwarf_functions.h"

using namespace std;

namespace retdec {
namespace dwarfparser {

/**
 * @brief ctor.
 * @param file Pointer to dwarfparser representation of DWARF file which owns this container.
 * @param elem Pointer to parent element that owns this container.
 */
DwarfFunctionContainer::DwarfFunctionContainer(DwarfFile *file, DwarfBaseElement *elem) :
		DwarfBaseContainer<DwarfFunction>(file, elem)
{

}

/**
 * @brief dctor.
 */
DwarfFunctionContainer::~DwarfFunctionContainer()
{

}

/**
 * @brief Get all data from function DIE.
 * @param die Function DIE.
 * @param lvl Level (depth) of this die.
 * @return Pointer to newly created data type object or nullptr if failed.
 */
DwarfFunction *DwarfFunctionContainer::loadAndGetDie(Dwarf_Die die, unsigned)
{
	// Use special class to get attributes that we want.
	AttrProcessor ap(m_parentFile->m_dbg, die, m_parentFile);

	DwarfFunction *f = nullptr;

	// If this has DW_AT_abstract_origin, then this is second part of some other declaration.
	// Find first one and just actualize it. Otherwise create new function declaration.
	// TODO: This expects that the first part without DW_AT_abstract_origin was already
	// processed. I'm not sure if it is possible/common that second part is before first one.
	Dwarf_Off ref = EMPTY_UNSIGNED;
	ap.get(DW_AT_abstract_origin, ref);

	if (ref == EMPTY_UNSIGNED)
		ap.get(DW_AT_specification, ref);

	if (ref != EMPTY_UNSIGNED)
	{
		f = static_cast<DwarfFunction*>( this->getElemByOffset(ref) );

		if (f)
		{
			f->addOffset( ap.getDieOff() );
		}
	}
	else if ( (f = static_cast<DwarfFunction*>( this->getElemByOffset( ap.getDieOff() )) ) )
	{
//     if (f)
//         f->addOffset( ap.getDieOff() ); // adds the same offset for the second time?

		// This will probably get function info for the second time, but it is not big problem.
	}
	else
	{
		const string *fileName = nullptr;
		ap.get(DW_AT_decl_file, fileName);

		f = new DwarfFunction(this, ap.getDieOff(), *fileName);
		if (f != nullptr)
			m_data.push_back(f);
	}

	if (f == nullptr)
	{
		DWARF_ERROR("Function was not found/created.");
		return nullptr;
	}

	// We can not load directly to f->*, because if may overwrite already loaded values.
	string name;
	string linkName;
	Dwarf_Addr low, high;
	Dwarf_Unsigned line;
	DwarfType *type;
	DwarfLocationDesc *frame;

	ap.get(DW_AT_name, name);

	ap.get(DW_AT_linkage_name, linkName);
	if (linkName.empty())
		ap.get(DW_AT_MIPS_linkage_name, linkName);
	if (linkName.empty())
		ap.get(DW_AT_HP_linkage_name, linkName);

	ap.get(DW_AT_low_pc, low);
	ap.get(DW_AT_high_pc, high);
	ap.get(DW_AT_decl_line, line);
	ap.get(DW_AT_type, type);
	ap.get(DW_AT_frame_base, frame);

	if (name != EMPTY_STR) f->name = name;
	if (linkName != EMPTY_STR)
	{
		f->linkageName = linkName;
		if (f->name.empty())
			f->name = linkName;
	}
	if (low != EMPTY_ADDR) f->lowAddr = low;
	if (high != EMPTY_ADDR) f->highAddr = high;
	if (line != EMPTY_UNSIGNED) f->line = line;
	if (type != nullptr) f->type = type;
	else f->type = m_parentFile->getTypes()->getVoid();
	if (f->frameBase == nullptr && frame != nullptr)
	{
		f->frameBase = frame;
		f->frameBase->setParent(f);
	}

	// Offset from low address.
	if (f->highAddr < f->lowAddr)
		f->highAddr += f->lowAddr;

	// Set function as active.
	// TODO: Functions with DW_AT_declaration attribute are skipped at the moment.
	// For each such DIE there should be another one that defines function.
	Dwarf_Bool isDeclr;
	ap.get(DW_AT_declaration, isDeclr);

	if (!isDeclr)
		f->isDeclaration = false;

	return f;
}

/**
 * @brief Print contents of this container.
 */
void DwarfFunctionContainer::dump() const
{
	cout << endl;
	cout << "==================== Functions ====================" << endl;

	DwarfBaseContainer<DwarfFunction>::dump();

	cout << endl;
}

/**
 * @brief Get function by its name.
 * @param n Name of function to get.
 * @return Pointer to function object if found, nullptr otherwise.
 */
DwarfFunction *DwarfFunctionContainer::getFunctionByName(string n)
{
	for (iterator it=begin(); it!=end(); ++it)
	{
		if ((*it)->name == n)
			return (*it);
	}

	return nullptr;
}

/**
 * @brief ctor -- create local containers.
 * @param prnt Pointer to parent container owning this element.
 * @param o    Original libdwarf DIE offset.
 * @param n    Reference to source file name where function is declared.
 */
DwarfFunction::DwarfFunction(DwarfFunctionContainer *prnt, Dwarf_Off o, const string &n) :
		DwarfVar(reinterpret_cast<DwarfVarContainer*>(prnt), o, DwarfBaseElement::FUNCTION),
		lowAddr(0),
		highAddr(0),
		line(0),
		file(n),
		frameBase(nullptr),
		isVariadic(false),
		isDeclaration(true),
		isTemplateInstance(false),
		isVariadicTemplateInstance(false),
		isTemplateTemplateInstance(false),
		m_vars(getParentFile(), this),
		m_params(getParentFile(), this)
{

}

/**
 * @brief dctor -- destroy local containers.
 */
DwarfFunction::~DwarfFunction()
{
	delete frameBase;
}

/**
 * @brief Print contents of this class.
 */
void DwarfFunction::dump() const
{
	cout << "Function: \"" << name << "\"  " << getDwarfdump2OffsetString() << endl;
	cout << "\tLink name   :  " << linkageName << endl;
	cout << "\tType        :  " << type->name << endl;
	cout << "\tLine        :  " << dec << line << endl;
	cout << "\tAddr. range :  " << hex << lowAddr
		 << " - " << highAddr << endl;
	cout << "\tSrc. file   :  " << file << endl;
	cout << endl;

	cout << "\tParams cnt. :  " << dec << m_params.size() << endl;
	DwarfVarContainer::const_iterator iter = m_params.begin();
	while (iter != m_params.end())
	{
		cout << "\t   ";
		(*iter)->dump();
		++iter;
	}
	if (isVariadic)
		cout << "\t   ... variadic argument" << endl;
	cout << endl;

	cout << "\tVars cnt.   :  " << dec << m_vars.size() << endl;
	iter = m_vars.begin();
	while (iter != m_vars.end())
	{
		cout << "\t   ";
		(*iter)->dump();
		++iter;
	}

	cout << endl;
}

/**
 * @brief Test if function has local variables.
 * @return True if function has local variables, false otherwise.
 */
bool DwarfFunction::hasVars() const
{
	return (m_vars.size() != 0);
}

/**
 * @brief Test if function has parameters.
 * @return True if function has parameters, false otherwise.
 */
bool DwarfFunction::hasParams() const
{
	return (m_params.size() != 0);
}

/**
 * @brief Get local variables.
 * @return Pointer to container of local variables.
 */
DwarfVarContainer *DwarfFunction::getVars()
{
	return &m_vars;
}

/**
 * @brief Get parameters.
 * @return Pointer to container of parameters.
 */
DwarfVarContainer *DwarfFunction::getParams()
{
	return &m_params;
}

/**
 * @brief Get number of function's parameters.
 * @return Number of functions parameters.
 */
std::size_t DwarfFunction::getParamCount() const
{
	return m_params.size();
}

/**
 * @brief Find out if this function has frame base.
 * @return True if function has frame base, false otherwise.
 */
bool DwarfFunction::hasFrameBase() const
{
	return (frameBase != nullptr);
}

/**
 * @brief Compute and return value of function's frame base.
 * @param n  Pointer to string that will be filled by method.
 *        If location is address this is a name of address space.
 *        If location is register this is a name of register array.
 * @param a  Pointer to value that will be filled by method.
 *        If location is address this is an address in address space.
 *        If location is register this is a number in register array.
 * @param pc Program counter value.
 * @return Type of location - address or register.
 * @note Frame base should be always address.
 */
DwarfLocationDesc::cLocType DwarfFunction::getFrameBase(string *n, Dwarf_Addr *a, Dwarf_Addr pc)
{
	if (frameBase)
		return (frameBase->computeLocation(n, a, pc));
	else
		return DwarfLocationDesc::FAIL;
}

} // namespace dwarfparser
} // namespace retdec
