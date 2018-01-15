/**
 * @file include/retdec/dwarfparser/dwarf_file.h
 * @brief Declarations of DwarfFile class which provides high-level access
 *        to DWARF debugging informations.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

/*
 * TODO:
 * - Multiple CUs -> CUs should own other info that are inside them.
 *   At the moment each object contains pointer to its CU.
 *   It would be better designed if CU elements would contain all the different
 *   containers (lines, functions, types, ...).
 *   Problem is that there would be many containers for each element type, and
 *   it is much easier for user of this library to have all functions, types, etc.
 *   in single container -- methods getFunctions(), etc.
 *   Possible solution would be to create new container when get*() method is called,
 *   this container would contain all element from all CU containers of the type.
 *   But I'm not sure that this is the best solution.
 * - add some method that enables printing debug info in all classes.
 * - class holding and managing active context, accessible from other classes.
 * - DW_AT_abstract_origin problem -- associate object with original DIE.
 * - void data type - is it the best solution ???
 */

#ifndef RETDEC_DWARFPARSER_DWARF_FILE_H
#define RETDEC_DWARFPARSER_DWARF_FILE_H

#include <string>

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#include "retdec/fileformat-libdwarf-interface/bin_interface.h"

#include "retdec/dwarfparser/dwarf_cu.h"
#include "retdec/dwarfparser/dwarf_functions.h"
#include "retdec/dwarfparser/dwarf_linenumbers.h"
#include "retdec/dwarfparser/dwarf_locations.h"
#include "retdec/dwarfparser/dwarf_parserdefs.h"
#include "retdec/dwarfparser/dwarf_resources.h"
#include "retdec/dwarfparser/dwarf_types.h"
#include "retdec/dwarfparser/dwarf_utils.h"
#include "retdec/dwarfparser/dwarf_vars.h"

namespace retdec {
namespace dwarfparser {

// Extern forward declarations.

// Locale forward declarations.
class DwarfFile;

/**
 * @class DwarfFile
 * @brief Main class containing all DWARF information.
 */
class DwarfFile
{
	//
	// Public methods.
	//
	public:
		DwarfFile(std::string fileName, retdec::fileformat::FileFormat *fileParser = nullptr);
		~DwarfFile();
		bool hasDwarfInfo();

	//
	// Functions getting particular DWARF records.
	//
	public:
		DwarfCUContainer *getCUs();
		DwarfLineContainer *getLines();
		DwarfFunctionContainer *getFunctions();
		DwarfTypeContainer *getTypes();
		DwarfVarContainer *getGlobalVars();
		Dwarf_Debug &getDwarfDebug();

	//
	// Private methods.
	//
	private:
		bool loadFile(std::string fileName, retdec::fileformat::FileFormat *fileParser);
		void loadFileCUs();
		void loadCUtree(Dwarf_Die die, DwarfBaseElement* parent, int lvl);
		void loadDIE(Dwarf_Die die, DwarfBaseElement* &parent, int lvl);
		void makeStructTypesUnique();

	//
	// Containers storing high-level representation of DWARF data.
	//
	private:
		DwarfCUContainer m_CUs;             ///< Compilation units.
		DwarfLineContainer m_lines;         ///< Line numbers.
		DwarfFunctionContainer m_functions; ///< Functions.
		DwarfTypeContainer m_types;         ///< Data types.
		DwarfVarContainer m_globalVars;     ///< Global variables.

	//
	// Some auxiliary variables.
	//
	private:
		bool m_hasDwarf;     ///< Loaded file contains some DWARF information.
		int m_res;           ///< Global return value.
		Dwarf_Debug m_dbg;   ///< Libdwarf structure representing DWARF file.
		int m_fd;            ///< File descriptor used in dwarf_init().
		Dwarf_Error m_error; ///< Global libdwarf error code.

	//
	// Variables keep track of the context of DWARF tree.
	//
	private:
		DwarfCU *m_activeCU;

	//
	// Resources.
	//
	public:
		void initMapping(eDefaultMap m);
		DwarfResources resources; ///< Class representing resources.

	//
	// These classes need to access DWARF context tree.
	//
	template <class T> friend class DwarfBaseContainer;
	friend class DwarfCUContainer;
	friend class DwarfLineContainer;
	friend class DwarfFunctionContainer;
	friend class DwarfVarContainer;
	friend class DwarfTypeContainer;
	friend class DwarfBaseElement;
	friend class DwarfCU;
	friend class DwarfArrayType;
	friend class DwarfEnumType;
	friend class DwarfStructType;
	friend class DwarfLocationDesc;
	friend class AttrProcessor;
};

} // namespace dwarfparser
} // namespace retdec

#endif
