/**
 * @file include/retdec/dwarfparser/dwarf_utils.h
 * @brief Declaration of utility functions and classes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DWARFPARSER_DWARF_UTILS_H
#define RETDEC_DWARFPARSER_DWARF_UTILS_H

#include <string>

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

namespace retdec {
namespace dwarfparser {

class DwarfType;
class DwarfLocationDesc;

// Extern forward declarations.

// Locale forward declarations.
class AttrProcessor;

/**
 * Safe encapsulation of libdwarf functions that are getting
 * data from attributes.
 */
	Dwarf_Addr getAttrAddr(Dwarf_Attribute attr);
	Dwarf_Unsigned getAttrNumb(Dwarf_Attribute attr);
	std::string getAttrStr(Dwarf_Attribute attr);
	Dwarf_Off getAttrRef(Dwarf_Attribute attr);
	Dwarf_Off getAttrGlobalRef(Dwarf_Attribute attr);
	Dwarf_Bool getAttrFlag(Dwarf_Attribute attr);
	Dwarf_Block *getAttrBlock(Dwarf_Attribute attr);
	Dwarf_Sig8 getAttrSig(Dwarf_Attribute attr);
	void getAttrExprLoc(Dwarf_Attribute attr, Dwarf_Unsigned *exprlen, Dwarf_Ptr *ptr);

	std::string getDwarfError(Dwarf_Error &error);

	bool getDieFromOffset(Dwarf_Debug dbg, Dwarf_Off off, Dwarf_Die &die);

/**
 * @class AttrProcessor
 * @brief Helper class providing access to DIE's attributes.
 *        Class is initialized with DIE which attributes will be processed.
 */
class AttrProcessor
{
	public:
		AttrProcessor(Dwarf_Debug dbg, Dwarf_Die die, DwarfFile *parent);

		bool get(Dwarf_Half attrCode, std::string& ret);
		bool get(Dwarf_Half attrCode, const std::string* &ret);
		bool get(Dwarf_Half attrCode, Dwarf_Unsigned& ret);
		bool get(Dwarf_Half attrCode, Dwarf_Signed& ret);
		bool get(Dwarf_Half attrCode, Dwarf_Bool& ret);
		bool get(Dwarf_Half attrCode, DwarfLocationDesc* &ret);
		bool get(Dwarf_Half attrCode, DwarfType* &ret);
		bool geti(Dwarf_Half attrCode, int& ret);

		Dwarf_Off getDieOff();

	private:
		Dwarf_Debug m_dbg;   ///< Libdwarf structure representing DWARF file.
		Dwarf_Die m_die;     ///< Source DIE which atributes will be processed.
		DwarfFile *m_parent; ///< Parent dwarfparser representation of DWARF file.

		int m_res;           ///< Global return value.
		Dwarf_Error m_error; ///< Global error code.
};

} // namespace dwarfparser
} // namespace retdec

#endif
