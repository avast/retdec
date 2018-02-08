/**
 * @file src/dwarfparser/dwarf_file.cpp
 * @brief Implementaion of DwarfFile class which provides high-level access
 *        to DWARF debugging informations.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstdlib>
#include <fcntl.h>

#include "retdec/utils/os.h"
#include "retdec/dwarfparser/dwarf_file.h"

#ifdef OS_WINDOWS
	#include <io.h>
#else
	#include <unistd.h>
#endif

using namespace std;

namespace retdec {
namespace dwarfparser {

/**
 * @brief ctor -- create containers and load data from input file.
 * @param fileName Name of file to open.
 * @param fileParser Parser of input file (optional)
 */
DwarfFile::DwarfFile(string fileName, retdec::fileformat::FileFormat *fileParser) :
		m_CUs(this),
		m_lines(this),
		m_functions(this),
		m_types(this),
		m_globalVars(this),
		m_hasDwarf(false),
		m_res(0),
		m_dbg(nullptr),
		m_fd(0),
		m_error(nullptr),
		m_activeCU(nullptr)
{
	loadFile(fileName, fileParser);
}

/**
 * @brief dctor -- destroy containers.
 */
DwarfFile::~DwarfFile()
{
	if (m_fd && m_dbg)
	{
		dwarf_finish(m_dbg, &m_error);
#ifdef OS_WINDOWS
		_close(m_fd);
#else
		close(m_fd);
#endif
	}
	else
	{
		dwarf_object_finish(m_dbg, &m_error);
	}
}

/**
 * @brief Open file and get DWARF info.
 * @param fileName Name of file to open.
 * @param fileParser Parser of input file (optional)
 * @return True if input file contains DWARF information, false otherwise.
 *
 * Binary interface is used to access input file at first.
 * If it fails standard ELF interface provided by libdwarf is used.
 */
bool DwarfFile::loadFile(string fileName, retdec::fileformat::FileFormat *fileParser)
{
	Dwarf_Handler errHand = nullptr;
	Dwarf_Ptr errArg = nullptr;

	// It is possible to load input file with our backend.
	BinInt binInt(fileName, fileParser);
	if (binInt.success())
	{
		m_res = dwarf_object_init(binInt.getInt(),
				errHand, errArg, &m_dbg, &m_error);

		// Input file has no DWARF information.
		if (m_res == DW_DLV_NO_ENTRY)
		{
			DWARF_WARNING("File: \"" << fileName << "\" has no DWARF information.");
			return false;
		}
		// Something went wrong.
		else if (m_res != DW_DLV_OK)
		{
			DWARF_ERROR("Libdwarf error: " << getDwarfError(m_error));
			return false;
		}

		resources.initMappingDefault();

		loadFileCUs();
		m_hasDwarf = true;
	}

	// Our binary backend can not be used
	// --> try to use ELF interface.
	else
	{
		DWARF_WARNING("Using ELF interface.");

#ifdef OS_WINDOWS
		if ((m_fd = _open(fileName.c_str(), _O_RDONLY, 0)) < 0)
#else
		if ((m_fd = open(fileName.c_str(), O_RDONLY, 0)) < 0)
#endif
		{
			DWARF_ERROR("File: \"" << fileName << "\" can not be opened.");
			return false;
		}

		m_res = dwarf_init(m_fd, DW_DLC_READ, errHand, errArg, &m_dbg, &m_error);

		if (m_res == DW_DLV_NO_ENTRY)
		{
			DWARF_WARNING("File: \"" << fileName << "\" has no DWARF information.");
			return false;
		}
		else if(m_res != DW_DLV_OK)
		{
			DWARF_ERROR("Libdwarf error: " << getDwarfError(m_error));
			return false;
		}

		// Init register mapping by default values.
		resources.initMappingDefault();

		loadFileCUs();
		m_hasDwarf = true;
	}

	makeStructTypesUnique();

	return m_hasDwarf;
}

/**
 * Same-named structures may exist. We need to rename them -> make them unique,
 * otherwise, string based (LLVM) type representation can not be used.
 * Several same named structures would be generated and it would not be possible
 * to distinguish their uses from one another.
 */
void DwarfFile::makeStructTypesUnique()
{
	std::map<std::string, unsigned> typeMap;
	for (auto& t : m_types)
	{
		if (t->constructed_as<DwarfStructType>())
		{
			auto fIt = typeMap.find(t->name);
			if (fIt == typeMap.end())
			{
				typeMap[t->name] = 1;
			}
			else
			{
				t->name = t->name + "_" + std::to_string(fIt->second);
				++fIt->second;
			}
		}
	}
}

/**
 * @brief Find out if input file contains DWARF information.
 * @return True if input file contains DWARF information, false otherwise.
 */
bool DwarfFile::hasDwarfInfo()
{
	return m_hasDwarf;
}

/**
 * @brief Iterate over DWARF file's CUs.
 */
void DwarfFile::loadFileCUs()
{
	Dwarf_Unsigned cu_header_length = 0;
	Dwarf_Half version_stamp = 0;
	Dwarf_Unsigned abbrev_offset = 0;
	Dwarf_Half address_size = 0;
	Dwarf_Half offset_size = 0;
	Dwarf_Half extension_size = 0;
	Dwarf_Sig8 signature;
	Dwarf_Unsigned typeoffset = 0;
	Dwarf_Unsigned next_cu_header = 0;

	// Iterate over CU headers.
	while (dwarf_next_cu_header_c(
				m_dbg,
				is_info,
				&cu_header_length,
				&version_stamp,
				&abbrev_offset,
				&address_size,
				&offset_size,
				&extension_size,
				&signature,
				&typeoffset,
				&next_cu_header,
				&m_error) == DW_DLV_OK)
	{
		Dwarf_Die cuDie = nullptr;

		// CU have single sibling - CU DIE.
		// nullptr - descriptor of first die in CU.
		m_res = dwarf_siblingof_b(m_dbg, nullptr, is_info, &cuDie, &m_error);
		if (m_res == DW_DLV_ERROR)
		{
			DWARF_ERROR("Libdwarf error: " << getDwarfError(m_error));
			return;
		}
		else if (m_res == DW_DLV_NO_ENTRY)
		{
			return;
		}

		int lvl = 0;
		loadCUtree(cuDie, nullptr, lvl);

		dwarf_dealloc(m_dbg, cuDie, DW_DLA_DIE);
	}
}

/**
 * @brief Gets a CU DIE at first and recursively load all DIEs in tree.
 * @param inDie Input die
 * @param parent Parent element or nullptr.
 * @param lvl   Level (depth) of this die.
 */
void DwarfFile::loadCUtree(Dwarf_Die inDie, DwarfBaseElement* parent, int lvl)
{
	Dwarf_Die curDie = inDie;
	DwarfBaseElement* siblingElement = parent;

	loadDIE(curDie, siblingElement, lvl);

	// Siblings and childs.
	while (1)
	{
		// Get child.
		Dwarf_Die child = nullptr;
		m_res = dwarf_child(curDie, &child, &m_error);

		if(m_res == DW_DLV_ERROR)
		{
			DWARF_ERROR("Libdwarf error: " << getDwarfError(m_error));
			return;
		}

		// Has child -> recursion.
		if(m_res == DW_DLV_OK)
		{
			loadCUtree(child, siblingElement, lvl+1);
		}

		// No entry -> no child.
		Dwarf_Die sib_die = nullptr;
		m_res = dwarf_siblingof_b(m_dbg, curDie, is_info, &sib_die, &m_error);

		if(m_res == DW_DLV_ERROR)
		{
			DWARF_ERROR("Libdwarf error: " << getDwarfError(m_error));
			return;
		}

		// Done at this level.
		if(m_res == DW_DLV_NO_ENTRY)
		{
			break;
		}

		// res == DW_DLV_OK
		if(curDie != inDie)
		{
			dwarf_dealloc(m_dbg, curDie, DW_DLA_DIE);
		}

		curDie = sib_die;
		siblingElement = parent;
		loadDIE(curDie, siblingElement, lvl);
	}
}

/**
 * @brief Get DIE and load all its contents to dwarfparser representation.
 * @param die    DIE to load.
 * @param parent Input parent element. Output newly loaded element or nullptr.
 * @param lvl    Level (depth) of this die.
 */
void DwarfFile::loadDIE(Dwarf_Die die, DwarfBaseElement* &parent, int lvl)
{
	DwarfBaseElement* parentElement = parent;
	parent = nullptr;

	// DIE name -- unused, but without it there is a SEG FAULT for some reason.
	//
	char *dieName = nullptr;
	bool localname = false;

	m_res = dwarf_diename(die, &dieName, &m_error);

	if(m_res == DW_DLV_ERROR)
	{
		DWARF_ERROR("Libdwarf error: " << getDwarfError(m_error));
		return;
	}
	if(m_res == DW_DLV_NO_ENTRY)
	{
		localname = true;
	}

	// DIE TAG.
	Dwarf_Half tag = 0;
	if (dwarf_tag(die, &tag, &m_error) != DW_DLV_OK)
	{
		DWARF_ERROR("Libdwarf error: " << getDwarfError(m_error));
		return;
	}

	AttrProcessor ap(m_dbg, die, this);

	// Decide what to do based on tag type.
	switch (tag)
	{
		//
		// Compilation unit.
		//
		case DW_TAG_compile_unit:
		{
			parent = m_CUs.loadAndGetDie(die, lvl);
			m_lines.loadAndGetDie(die, lvl);

			break;
		}

		//
		// Subprogram name == DIE name.
		//
		case DW_TAG_subprogram:
		{
			DwarfFunction *tmp = m_functions.loadAndGetDie(die, lvl);
			parent = tmp;

			DwarfClassType *activeClass = dynamic_cast<DwarfClassType*>(parentElement);
			if (tmp && activeClass)
			{
				activeClass->memberFunctions.push_back(tmp); // TODO: nejak obojsmerne nastavit.
			}
			break;
		}

		//
		// Class inheritance.
		//
		case DW_TAG_inheritance:
		{
			DwarfType *type = nullptr;
			Dwarf_Unsigned access;

			ap.get(DW_AT_type, type);
			ap.get(DW_AT_accessibility, access);

			DwarfClassType *activeClass = dynamic_cast<DwarfClassType*>(parentElement);
			DwarfClassType *base = dynamic_cast<DwarfClassType*>(type);
			if (base && activeClass)
			{
				DwarfClassType::InheritanceMember inh(base, access);
				activeClass->baseClasses.push_back(inh);
			}

			break;
		}

		//
		// Send all type related DIEs to type class.
		//
		case DW_TAG_array_type:
		case DW_TAG_base_type:
		case DW_TAG_class_type:
		case DW_TAG_const_type:
		case DW_TAG_enumeration_type: // May be used as DW_TAG_subrange_type
		case DW_TAG_file_type:
		case DW_TAG_interface_type:
		case DW_TAG_packed_type:
		case DW_TAG_pointer_type:
		case DW_TAG_ptr_to_member_type:
		case DW_TAG_reference_type:
		case DW_TAG_restrict_type:
		case DW_TAG_rvalue_reference_type:
		case DW_TAG_set_type:
		case DW_TAG_shared_type:
		case DW_TAG_string_type:
		case DW_TAG_structure_type:
		case DW_TAG_subroutine_type:
		case DW_TAG_thrown_type:
		case DW_TAG_typedef:
		case DW_TAG_union_type:
		case DW_TAG_unspecified_type:
		case DW_TAG_volatile_type:
		{
			auto p = m_types.loadAndGetDie(die, lvl);
			Dwarf_Die child = nullptr;
			if (dwarf_child(die, &child, &m_error) == DW_DLV_OK)
			{
				parent = p;
			}
			break;
		}

		//
		// Belongs to active array.
		//
		case DW_TAG_subrange_type:
		{
			DwarfArrayType *activeArray = dynamic_cast<DwarfArrayType *>(parentElement);
			if (activeArray != nullptr)
			{
				Dwarf_Unsigned bound;
				ap.get(DW_AT_upper_bound, bound);
				activeArray->addDimension(bound);
			}
			break;
		}

		//
		// Belongs to active enumeration.
		//
		case DW_TAG_enumerator:
		{
			DwarfEnumType *activeEnum = dynamic_cast<DwarfEnumType *>(parentElement);
			if (activeEnum != nullptr)
			{
				DwarfEnumType::EnumMember m;
				ap.get(DW_AT_name, m.name);
				ap.get(DW_AT_const_value, m.constVal);
				activeEnum->addMember(m);
			}
			break;
		}

		//
		// Belongs to active structure.
		//
		case DW_TAG_member:
		{
			DwarfStructType *activeStruct = dynamic_cast<DwarfStructType *>(parentElement);
			if (activeStruct != nullptr)
			{
				DwarfStructType::StructMember m;
				m.type = nullptr;
				m.location = nullptr;
				m.bitSize = EMPTY_UNSIGNED;
				m.bitOffset = EMPTY_UNSIGNED;
				ap.get(DW_AT_name, m.name);
				ap.get(DW_AT_type, m.type);
				ap.get(DW_AT_data_member_location, m.location);
				ap.get(DW_AT_bit_size, m.bitSize);
				ap.get(DW_AT_bit_offset, m.bitOffset);

				Dwarf_Bool isStatic;
				ap.get(DW_AT_external, isStatic);

				Dwarf_Unsigned a;
				ap.get(DW_AT_accessibility, a);
				m.setAccess(a);

				if (m.location != nullptr)
				{
					m.location->setParent(activeStruct);
				}
				if (isStatic)
					activeStruct->addStaticMember(m);
				else
					activeStruct->addMember(m);
			}
			break;
		}

		//
		// Variables and constants.
		//
		case DW_TAG_variable:
		{
			// Global variable.
			if (dynamic_cast<DwarfCU*>(parentElement)) //DwarfCU *activeCu
			{
				m_globalVars.loadAndGetDie(die, lvl);
			}
			// Variable belongs to some function.
			else if (DwarfFunction *activeFunc = dynamic_cast<DwarfFunction *>(parentElement))
			{
				activeFunc->getVars()->loadAndGetDie(die, lvl);
			}

			break;
		}

		//
		// Function parameters -- belong to active function or function type.
		//
		case DW_TAG_formal_parameter:
		{
			DwarfFunction *activeFunc = dynamic_cast<DwarfFunction *>(parentElement);
			if (activeFunc != nullptr && !activeFunc->isDeclaration)
			{
				activeFunc->getParams()->loadAndGetDie(die, lvl);
			}
			else
			{
				DwarfFunctionType *activeFuncType = dynamic_cast<DwarfFunctionType *>(parentElement);
				if (activeFuncType != nullptr)
				{
					activeFuncType->getParams()->loadAndGetDie(die, lvl);
				}
			}
			break;
		}

		//
		// Variadic parameters.
		//
		case DW_TAG_unspecified_parameters:
		{
			DwarfFunction *activeFunc =
				dynamic_cast<DwarfFunction *>(parentElement);
			if (activeFunc != nullptr)
			{
				activeFunc->isVariadic = true;
			}
			else
			{
				DwarfFunctionType *activeFuncType =
					dynamic_cast<DwarfFunctionType *>(parentElement);
				if (activeFuncType != nullptr)
				{
					activeFuncType->isVariadic = true;
				}
			}
			break;
		}

		//
		// Block -- not processed at the moment, but we want to keep old parent
		// so that DIEs on lower level connect with parents even if block DIEs
		// in the middle are not processed.
		//
		case DW_TAG_catch_block:
		case DW_TAG_common_block:
		case DW_TAG_label:
		case DW_TAG_lexical_block:
		case DW_TAG_module:
		case DW_TAG_namespace:
		case DW_TAG_partial_unit:
		case DW_TAG_try_block:
		{
			parent = parentElement;
			break;
		}

		//
		// DW_TAG_template_type_parameter is in standard.
		//
		case DW_TAG_template_type_parameter:
		{
			DwarfFunction *activeFunc = dynamic_cast<DwarfFunction *>(parentElement);
			if (activeFunc != nullptr && !activeFunc->isDeclaration)
			{
				activeFunc->isTemplateInstance = true;
			}
			break;
		}

		//
		// GNU extension for variadic templates.
		//
		case DW_TAG_GNU_template_parameter_pack:
		case DW_TAG_GNU_formal_parameter_pack:
		{
			DwarfFunction *activeFunc = dynamic_cast<DwarfFunction *>(parentElement);
			if (activeFunc != nullptr && !activeFunc->isDeclaration)
			{
				activeFunc->isVariadicTemplateInstance = true;
			}
			break;
		}

		//
		// GNU extension for template template arguments.
		//
		case DW_TAG_GNU_template_template_parameter:
		{
			DwarfFunction *activeFunc = dynamic_cast<DwarfFunction *>(parentElement);
			if (activeFunc != nullptr && !activeFunc->isDeclaration)
			{
				activeFunc->isTemplateTemplateInstance = true;
			}
			break;
		}

		//
		// Unprocessed tags.
		//
		case DW_TAG_access_declaration:
		case DW_TAG_common_inclusion:
		case DW_TAG_condition:
		case DW_TAG_constant: // in languages with true named constants
		case DW_TAG_dwarf_procedure:
		case DW_TAG_entry_point:
		case DW_TAG_friend:
		case DW_TAG_imported_declaration:
		case DW_TAG_imported_module:
		case DW_TAG_imported_unit:
		case DW_TAG_inlined_subroutine:
		case DW_TAG_namelist:
		case DW_TAG_namelist_item:
		case DW_TAG_template_alias:
		case DW_TAG_template_value_parameter:
		case DW_TAG_type_unit:
		case DW_TAG_variant:
		case DW_TAG_variant_part:
		case DW_TAG_with_stmt:
		default:
		{
			break;
		}
	}

	// Free DIE dieName.
	if(!localname)
	{
		dwarf_dealloc(m_dbg, dieName, DW_DLA_STRING);
	}
}

/**
 * @brief Get reference to Libdwarf representation.
 * @return reference to Libdwarf representation.
 */
Dwarf_Debug &DwarfFile::getDwarfDebug()
{
	return m_dbg;
}

/**
 * @brief Get all compilation units.
 * @return Compilation units.
 */
DwarfCUContainer *DwarfFile::getCUs()
{
	return &m_CUs;
}

/**
 * @brief Get lines information.
 * @return Lines.
 */
DwarfLineContainer *DwarfFile::getLines()
{
	return &m_lines;
}

/**
 * @brief Get all functions.
 * @return Functions.
 */
DwarfFunctionContainer *DwarfFile::getFunctions()
{
	return &m_functions;
}

/**
 * @brief Get all data types.
 * @return Data types.
 */
DwarfTypeContainer *DwarfFile::getTypes()
{
	return &m_types;
}

/**
 * @brief Get all global variables.
 * @return Global variables.
 */
DwarfVarContainer *DwarfFile::getGlobalVars()
{
	return &m_globalVars;
}

/**
 * @brief Init mapping of DWARF register numbers to names using
 *        default -- well known mapping for architectures.
 * @param m Architecture which default mapping will be used.
 * @note Use this method if mappingSecPresent() returns false -> input file
 *       doesn't contain section with DWARF register numbers mapping.
 */
void DwarfFile::initMapping(eDefaultMap m)
{
	resources.initMappingDefault(m);
}

} // namespace dwarfparser
} // namespace retdec
