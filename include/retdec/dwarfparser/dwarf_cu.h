/**
 * @file include/retdec/dwarfparser/dwarf_cu.h
 * @brief Declaration of classes representing Compilation Units.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DWARFPARSER_DWARF_CU_H
#define RETDEC_DWARFPARSER_DWARF_CU_H

#include <cstdlib>
#include <list>

#include "retdec/dwarfparser/dwarf_base.h"

namespace retdec {
namespace dwarfparser {

// Extern forward declarations.
class DwarfFile;

// Locale forward declarations.
class DwarfCU;
class DwarfCUContainer;

/**
 * @class DwarfCU
 * @brief Compilation unit object.
 */
class DwarfCU : public DwarfBaseElement
{
	public:
		DwarfCU(DwarfCUContainer *prnt, Dwarf_Off o);
		virtual void dump() const override;

		std::size_t srcFilesCount();
		void addSrcFile(std::string f);
		std::string *getSrcFile(unsigned idx);
		int findSrcFile(std::string f, const std::string **ret);
		bool IsLanguageC() const;
		bool IsLanguageCpp() const;

	public:
		std::string compDir;               ///< Name of compilation directory.
		std::string producer;              ///< Name of compiler used to create CU.
		Dwarf_Addr lowAddr;                ///< Lowest address of active range, base for loclists.
		Dwarf_Addr highAddr;               ///< Highest address of active range.
		Dwarf_Unsigned language;           ///< A code indicating the source language.

	private:
		std::list<std::string> m_srcFiles; ///< List of source file of this compilation unit.
};

/**
 * @class DwarfCUContainer
 * @brief Compilation unit container.
 */
class DwarfCUContainer : public DwarfBaseContainer<DwarfCU>
{
	public:
		DwarfCUContainer(DwarfFile *file, DwarfBaseElement *elem = nullptr);
		virtual DwarfCU *loadAndGetDie(Dwarf_Die cuDie, unsigned lvl) override;
		virtual void dump() const override;
};

} // namespace dwarfparser
} // namespace retdec

#endif
