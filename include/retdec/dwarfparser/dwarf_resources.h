/**
 * @file include/retdec/dwarfparser/dwarf_resources.h
 * @brief Declaration of classes representing resources.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DWARFPARSER_DWARF_RESOURCES_H
#define RETDEC_DWARFPARSER_DWARF_RESOURCES_H

#include <map>
#include <vector>

#include "retdec/dwarfparser/dwarf_parserdefs.h"

namespace retdec {
namespace dwarfparser {

// Extern forward declarations.

// Locale forward declarations.
class DwarfResources;

/**
 * @class DwarfResources
 * @brief Provide access to local resources.
 *        Must be initialized before use.
 *        To initialize use initAccess() and initPcReg().
 */
class DwarfResources
{
	public:
		/**
		 * @brief Representation of real architecture register.
		 */
		struct RealReg
		{
			RealReg() : arrayNum(0) {}
			RealReg(std::string s, unsigned n) : name(s), arrayNum(n) {}
			std::string name; ///< Name of register array which contains this register.
			unsigned arrayNum; ///< Index number of this register in register array.
		};

	public:
		void initMappingDefault(eDefaultMap m = MIPS);
		void dump();

		Dwarf_Signed getReg(Dwarf_Half n);
		Dwarf_Signed getReg(std::string name, Dwarf_Addr number);
		Dwarf_Signed getAddr(Dwarf_Addr a);
		Dwarf_Addr getPcReg();
		void setReg(Dwarf_Half reg, std::string *n, Dwarf_Addr *a);

	private:
		std::map<Dwarf_Half, RealReg> m_regMaps; ///< Mapping of DWARF register numbers to
		                                         ///< architecture registers.
};

} // namespace dwarfparser
} // namespace retdec

#endif
