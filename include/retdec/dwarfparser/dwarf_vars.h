/**
 * @file include/retdec/dwarfparser/dwarf_vars.h
 * @brief Declaration of classes representing variables.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DWARFPARSER_DWARF_VARS_H
#define RETDEC_DWARFPARSER_DWARF_VARS_H

#include <cstdlib>

#include "retdec/dwarfparser/dwarf_base.h"
#include "retdec/dwarfparser/dwarf_locations.h"
#include "retdec/dwarfparser/dwarf_types.h"

namespace retdec {
namespace dwarfparser {

// Extern forward declarations.
class DwarfFile;

// Locale forward declarations.
class DwarfVar;
class DwarfVarContainer;

/**
 * @class DwarfVar
 * @brief Variable object.
 */
class DwarfVar : public DwarfBaseElement
{
	public:
		/**
		 * @brief Variable flags.
		 */
		enum eFlags
		{
			EMPTY    = 0,      ///< Empty.
			CONSTANT = 1 << 1, ///< This is constant, not variable.
			POINTER  = 1 << 2, ///< Variable is a pointer.
			RESTRICT = 1 << 3, ///< Variable is restrict.
			VOLATILE = 1 << 4  ///< Variable is volatile.
		};

	public:
		DwarfVar(DwarfVarContainer *prnt, Dwarf_Off off, DwarfBaseElement::type_t t = DwarfBaseElement::VAR);
		virtual ~DwarfVar() override;
		virtual void dump() const override;

		bool hasLocation();
		void mergeWith(DwarfVar *o);
		DwarfLocationDesc::cLocType getLocation(std::string *n, Dwarf_Addr *a, Dwarf_Addr pc=0);
		bool isOnStack(Dwarf_Signed *a, bool *deref, Dwarf_Addr pc = 0, int *regNum=nullptr);

		bool isConstant() const;
		bool isPointer() const;
		bool isRestrict() const;
		bool isVolatile() const;

	public:
		int flags;                   ///< Flags of variable.
		DwarfType *type;             ///< Data type of variable.
		DwarfLocationDesc *location; ///< Location descriptor of variable.
};

/**
 * @class DwarfVarContainer
 * @brief Variable container.
 */
class DwarfVarContainer : public DwarfBaseContainer<DwarfVar>
{
	public:
		DwarfVarContainer(DwarfFile *file, DwarfBaseElement *elem = nullptr);
		virtual void dump() const override;

		virtual DwarfVar *loadAndGetDie(Dwarf_Die die, unsigned lvl) override;
		DwarfVar *getVarByName(std::string n);

		DwarfVar *addParameter(DwarfVar *n);
};

} // namespace dwarfparser
} // namespace retdec

#endif
