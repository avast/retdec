/**
 * @file src/dwarfparser/dwarf_base.cpp
 * @brief Implementation of base classes used in dwarfparser.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cstdlib>
#include <sstream>

#include "retdec/dwarfparser/dwarf_base.h"
#include "retdec/dwarfparser/dwarf_file.h"
#include "retdec/dwarfparser/dwarf_functions.h"

using namespace std;

namespace retdec {
namespace dwarfparser {

/**
 * @brief ctor.
 * @param type Type of the base element.
 * @param prnt Pointer to parent container that contains this element.
 * @param off  Offset associated with this element in DWARF file - unique ID.
 */
DwarfBaseElement::DwarfBaseElement(type_t type, DwarfBaseContainer<DwarfBaseElement> *prnt, Dwarf_Off off) :
	m_type(type),
	m_parent(prnt),
	m_cuParent(m_parent->getParentFile()->m_activeCU)
{
	if (m_parent)
		m_parent->off2data[off] = this;
}

/**
 *
 */
void DwarfBaseElement::addOffset(Dwarf_Off o)
{
	if (m_parent)
		m_parent->off2data[o] = this;
}

/**
 *
 */
string DwarfBaseElement::getDwarfdump2OffsetString() const
{
	stringstream ret;
	ret << "(";
	ret << ")";
	return ret.str();
}

/**
 * @brief Get libdwarf's debug file.
 */
Dwarf_Debug &DwarfBaseElement::getLibdwarfDebug() const
{
	return getParentFile()->getDwarfDebug();
}

} // namespace dwarfparser
} // namespace retdec
