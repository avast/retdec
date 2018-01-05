/**
 * @file include/retdec/dwarfparser/dwarf_locations.h
 * @brief Declaration of classes representing locations.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DWARFPARSER_DWARF_LOCATIONS_H
#define RETDEC_DWARFPARSER_DWARF_LOCATIONS_H

#include <cstdlib>
#include <vector>

#include "retdec/dwarfparser/dwarf_base.h"
#include "retdec/dwarfparser/dwarf_resources.h"

namespace retdec {
namespace dwarfparser {

// Extern forward declarations.
class DwarfFunction;

// Locale forward declarations.
class DwarfLocationDesc;

/**
 * @class DwarfLocationDesc
 * @brief Class represents location description used by DWARF.
 */
class DwarfLocationDesc
{
	public:
		/**
		 * @brief Type of location.
		 */
		enum eLocType
		{
			REGISTER = 0,      ///< Register.
			ADDRESS  = 1 << 1, ///< Address.
			VALUE    = 1 << 2, ///< Actual value of the object.
			FAIL     = 1 << 3  ///< Invalid.
		};

		/**
		 * @class cLocType.
		 * @brief Class representing location type.
		 */
		class cLocType
		{
			public:
				cLocType(eLocType tt);
				bool isRegister();
				bool isAddress();
				bool isValue();
				bool failed();
			private:
				eLocType t; ///< Location type.
		};

		/**
		 * @brief Basic unit of location description.
		 */
		struct Atom
		{
			Dwarf_Small opcode; ///< Operation code.
			Dwarf_Unsigned op1; ///< Operand #1.
			Dwarf_Unsigned op2; ///< Operand #2.
			Dwarf_Unsigned off; ///< Offset in locexpr used in OP_BRA.
		};

		/**
		 * @brief DWARF expression.
		 */
		class Expression
		{
			public:
			Dwarf_Addr lowAddr; ///< Lowest address of active range.
			Dwarf_Addr highAddr; ///< Highest address of active range.
			std::vector<Atom> atoms; ///< Vector of expression's atoms.
			std::size_t count() const {return atoms.size();}
		};

	public:
		DwarfLocationDesc();

		cLocType computeLocation(std::string *n, Dwarf_Addr *a, Dwarf_Addr pc = 0,
			Dwarf_Addr base = 0, bool hasBase = false);

		void addExpr(Expression e);
		void setBaseFunc(DwarfFunction *f);
		DwarfLocationDesc *getBaseLoc();
		void setParent(DwarfBaseElement *p);
		DwarfCU *getCuParent();
		std::string getParentName();
		DwarfResources *getResources();
		std::size_t count() const;
		bool isEmpty();
		bool isNormal() const;
		bool isList();
		bool isOnStack(Dwarf_Signed *off, bool *deref, Dwarf_Addr pc = 0, int *regNum=nullptr);
		void dump();

	private:
		cLocType evaluateExpression(Expression &expr, std::string *retN, Dwarf_Addr *retA,
			Dwarf_Addr pc = 0, Dwarf_Addr base = 0, bool hasBase = false);

	private:
		std::vector<Expression> m_exprs; ///< Vector of expressions of this location.
		DwarfFunction *m_baseFunc;       ///< Pointer to base function containing frame base location.
		DwarfBaseElement *m_parent;      ///< Pointer to object which owns this location.
};

} // namespace dwarfparser
} // namespace retdec

#endif
