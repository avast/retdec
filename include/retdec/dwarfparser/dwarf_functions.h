/**
 * @file include/retdec/dwarfparser/dwarf_functions.h
 * @brief Declaration of classes representing functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DWARFPARSER_DWARF_FUNCTIONS_H
#define RETDEC_DWARFPARSER_DWARF_FUNCTIONS_H

#include <cstdlib>

#include "retdec/dwarfparser/dwarf_base.h"
#include "retdec/dwarfparser/dwarf_vars.h"

namespace retdec {
namespace dwarfparser {

// Extern forward declarations.
class DwarfFile;

// Locale forward declarations.
class DwarfFunction;
class DwarfFunctionContainer;

/**
 * @class DwarfFunction
 * @brief Function object.
 */
class DwarfFunction : public DwarfVar
{
	public:
		DwarfFunction(DwarfFunctionContainer *prnt, Dwarf_Off o, const std::string &n);
		virtual ~DwarfFunction() override;
		virtual void dump() const override;

		bool hasVars() const;
		bool hasParams() const;
		DwarfVarContainer *getVars();
		DwarfVarContainer *getParams();
		std::size_t getParamCount() const;
		bool hasFrameBase() const;
		DwarfLocationDesc::cLocType getFrameBase(std::string *n, Dwarf_Addr *a, Dwarf_Addr pc = 0);

	public:
		std::string linkageName;      ///< Mangled name, sometimes only this one is in DWARF, then use it as name as well.
		Dwarf_Addr lowAddr;           ///< Lowest address of active range.
		Dwarf_Addr highAddr;          ///< Highest address of active range.
		Dwarf_Unsigned line;          ///< Function declaration line number.
		const std::string &file;      ///< Source file name where function is declared.
		DwarfLocationDesc *frameBase; ///< Frame base location descriptor.
		bool isVariadic;              ///< If true, function has variadic argument following arguments stored in m_params.
		bool isDeclaration;           ///<
		bool isTemplateInstance;
		bool isVariadicTemplateInstance;
		bool isTemplateTemplateInstance;

	private:
		DwarfVarContainer m_vars;     ///< Container with local variables of this function.
		DwarfVarContainer m_params;   ///< Container with parameters of this function.
};

/**
 * @class DwarfFunctionContainer
 * @brief Function container.
 */
class DwarfFunctionContainer : public DwarfBaseContainer<DwarfFunction>
{
	public:
		DwarfFunctionContainer(DwarfFile *file, DwarfBaseElement *elem = nullptr);
		virtual ~DwarfFunctionContainer() override;
		virtual void dump() const override;

		virtual DwarfFunction *loadAndGetDie(Dwarf_Die die, unsigned lvl) override;
		DwarfFunction *getFunctionByName(std::string n);
};

} // namespace dwarfparser
} // namespace retdec

#endif
