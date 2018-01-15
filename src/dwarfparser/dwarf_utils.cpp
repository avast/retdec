/**
 * @file src/dwarfparser/dwarf_utils.cpp
 * @brief Implementation of utility functions and classes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstdlib>

#include "retdec/dwarfparser/dwarf_file.h"
#include "retdec/dwarfparser/dwarf_utils.h"

using namespace std;

namespace retdec {
namespace dwarfparser {

//
// Taken from dwarfdump2/print_die.cpp
//
static int get_form_values(Dwarf_Attribute attrib, Dwarf_Half & theform, Dwarf_Half & directform)
{
	Dwarf_Error err = nullptr;
	int res = dwarf_whatform(attrib, &theform, &err);
	dwarf_whatform_direct(attrib, &directform, &err);
	return res;
}

//
// Taken from dwarfdump2/print_die.cpp
//
/*
* This is a slightly simplistic rendering of the FORM
* issue, it is not precise. However it is really only
* here so we can detect and report an error (producing
* incorrect DWARF) by a particular compiler (a quite unusual error,
* noticed in April 2010).
* So this simplistic form suffices.  See the libdwarf get_loclist_n()
* function source for the precise test.
*/
static bool is_location_form(int form)
{
	if(form == DW_FORM_block1 ||
		form == DW_FORM_block2 ||
		form == DW_FORM_block4 ||
		form == DW_FORM_block ||
		form == DW_FORM_data4 ||
		form == DW_FORM_data8 ||
		form == DW_FORM_sec_offset) {
		return true;
	}
	return false;
}

/**
 * @brief Get address from attribute.
 * @param attr Address class attribute.
 * @return Address represented by the attribute.
 */
Dwarf_Addr getAttrAddr(Dwarf_Attribute attr)
{
	Dwarf_Error error = nullptr;
	Dwarf_Addr retVal = 0;

	if (dwarf_formaddr(attr, &retVal, &error) == DW_DLV_OK)
	{
		return retVal;
	}
	else
	{
		DWARF_ERROR(getDwarfError(error));
		return EMPTY_ADDR;
	}
}

/**
 * @brief Get value of the attribute.
 * @param attr Constant class attribute.
 * @return Value of the attrinute.
 */
Dwarf_Unsigned getAttrNumb(Dwarf_Attribute attr)
{
	Dwarf_Error error = nullptr;

	Dwarf_Unsigned uRetVal = 0;
	if (dwarf_formudata(attr, &uRetVal, &error) == DW_DLV_OK)
	{
		return uRetVal;
	}

	Dwarf_Signed sRetVal = 0;
	if (dwarf_formsdata(attr, &sRetVal, &error) == DW_DLV_OK)
	{
		return sRetVal;
	}

	DWARF_ERROR(getDwarfError(error));
	return EMPTY_UNSIGNED;
}

/**
 * @brief Get string from the attribute.
 * @param attr String class attribute.
 * @return String containing the value of the attribute.
 */
string getAttrStr(Dwarf_Attribute attr)
{
	Dwarf_Error error = nullptr;

	char *name = nullptr;
	if (dwarf_formstring(attr, &name, &error) == DW_DLV_OK)
	{
		return string(name);
	}
	else
	{
		DWARF_ERROR(getDwarfError(error));
		return EMPTY_STR;
	}
}

/**
 * @brief Get reference from the attribute.
 * @param attr Reference class attribute.
 * @return Offset represented by the attribute.
 */
Dwarf_Off getAttrRef(Dwarf_Attribute attr)
{
	Dwarf_Error error = nullptr;

	Dwarf_Off retVal;
	if (dwarf_formref(attr, &retVal, &error) == DW_DLV_OK)
	{
		return retVal;
	}
	else
	{
		DWARF_ERROR(getDwarfError(error));
		return EMPTY_OFF;
	}
}

/**
 * @brief Get global reference from the attribute.
 * @param attr Reference or other section-references class
 *        attribute.
 * @return Global offset represented by the attribute.
 */
Dwarf_Off getAttrGlobalRef(Dwarf_Attribute attr)
{
	Dwarf_Error error = nullptr;

	Dwarf_Off retVal;
	if (dwarf_global_formref(attr, &retVal, &error) == DW_DLV_OK)
	{
		return retVal;
	}
	else
	{
		DWARF_ERROR(getDwarfError(error));
		return EMPTY_OFF;
	}
}

/**
 * @brief Get flag from the attribute.
 * @param attr Attribute.
 * @return True if attribute has a non-zero value, else false.
 */
Dwarf_Bool getAttrFlag(Dwarf_Attribute attr)
{
	Dwarf_Error error = nullptr;

	Dwarf_Bool retVal;
	if (dwarf_formflag(attr, &retVal, &error) == DW_DLV_OK)
	{
		return retVal;
	}
	else
	{
		DWARF_ERROR(getDwarfError(error));
		return false;
	}
}

/**
 * @brief Get block from the attribute.
 * @param attr Block class attribute.
 * @return Pointer to block structure represented by the attribute,
 */
Dwarf_Block *getAttrBlock(Dwarf_Attribute attr)
{
	Dwarf_Error error = nullptr;

	Dwarf_Block *retVal = nullptr;
	if (dwarf_formblock(attr, &retVal, &error) == DW_DLV_OK)
	{
		return retVal;
	}
	else
	{
		DWARF_ERROR(getDwarfError(error));
		return nullptr;
	}
}

/**
 * @brief Get 8 byte signature from the attribute.
 * @param attr Attribute of DW_FORM_ref_sig8 form.
 * @return 8 byte signature represented by the attribute.
 */
Dwarf_Sig8 getAttrSig(Dwarf_Attribute attr)
{
	Dwarf_Error error = nullptr;

	Dwarf_Sig8 retVal;
	if (dwarf_formsig8(attr, &retVal, &error) == DW_DLV_OK)
	{
		return retVal;
	}
	else
	{
		DWARF_ERROR(getDwarfError(error));
		return Dwarf_Sig8();
	}
}

/**
 * @brief Gets length of the location expression and pointer to
 *        the bytes of the location expression from the attribute.
 * @param attr    Attribute of DW_FORM_exprloc form.
 * @param exprlen Pointer to location expression length to set.
 * @param ptr     Pointer to location expression pointer to set.
 */
void getAttrExprLoc(Dwarf_Attribute attr, Dwarf_Unsigned *exprlen,
		Dwarf_Ptr *ptr)
{
	Dwarf_Error error = nullptr;

	if (dwarf_formexprloc(attr, exprlen, ptr, &error) != DW_DLV_OK)
	{
		DWARF_ERROR(getDwarfError(error));
		// non-recoverable --  exit(1) ???
	}
}

/**
 * @brief Gets libdwarf error message to provided error code.
 * @param error Error code.
 * @return Error message as strings.
 */
string getDwarfError(Dwarf_Error &error)
{
	return string(dwarf_errmsg(error));
}

/**
 * @brief Gets DIE from provided offset.
 * @param dbg Debug file.
 * @param off Offset.
 * @param die Found die.
 * @return True if success, false otherwise.
 */
bool getDieFromOffset(Dwarf_Debug dbg, Dwarf_Off off, Dwarf_Die &die)
{
	bool is_info = true;
	Dwarf_Error error;
	int res = dwarf_offdie_b(dbg, off, is_info, &die, &error);

	if (res == DW_DLV_ERROR)
	{
		DWARF_ERROR(getDwarfError(error));
		return false;
	}

	if (res == DW_DLV_NO_ENTRY)
	{
		return false;
	}

	return true;
}

/**
 * @brief ctor -- initialize class with DIE which attributes will be processed.
 * @param dbg    Libdwarf structure representing DWARF file.
 * @param die    Source DIE which atributes will be processed.
 * @param parent Parent dwarfparser representation of DWARF file.
 */
AttrProcessor::AttrProcessor(Dwarf_Debug dbg, Dwarf_Die die, DwarfFile *parent) :
		m_dbg(dbg),
		m_die(die),
		m_parent(parent),
		m_res(DW_DLV_OK),
		m_error(nullptr)
{

}

/**
 * @brief Get offset of source DIE.
 * @return DIE offset.
 */
Dwarf_Off AttrProcessor::getDieOff()
{
	Dwarf_Off offset;
	if (dwarf_dieoffset(m_die, &offset, &m_error) != DW_DLV_OK)
	{
		DWARF_ERROR(getDwarfError(m_error));
		return EMPTY_OFF;
	}

	return offset;
}

/**
 * @brief Get attribute value from source DIE and return it in.
 * @param attrCode Attribute code to get.
 * @param ret      Pointer to return value which will be filled with result.
 *        Caller must provide pointer to expected data type.
 * @return True if specified attribute was found, false otherwise.
 * @note
 * AttrCodes in switch are not in alphabetical order,
 * codes are grouped based on mechanism of getting attr values.
 * But codes inside one group should by ordered alphabetically,
 * so if you are adding some, place it in correct place here and
 * in getEmpty() method as well.
 *
 * TODO: because it may be called at already initialized member of some object, it
 * will rewrite (getEmpty) this member if attr not found for the second time:
 * DW_AT_abstract_origin in functions, DW_AT_specification in types, ...
 * It would be better to refactorize all work with this function, all ret must by initialized
 * to empty value before call and there will be no getEmpty() function, if attr not found,
 * ret wont be changed -- default empty value if not processed yet, previous value if already
 * found and processed.
 */

bool AttrProcessor::get(Dwarf_Half attrCode, std::string& ret)
{
	ret = EMPTY_STR;

	Dwarf_Attribute attr;
	m_res = dwarf_attr(m_die, attrCode, &attr, &m_error);
	if (m_res != DW_DLV_OK)
	{
		if (m_res == DW_DLV_ERROR)
			DWARF_ERROR(getDwarfError(m_error));
		return false;
	}

	bool r = true;
	switch (attrCode)
	{
		case DW_AT_comp_dir:
		case DW_AT_linkage_name:
		case DW_AT_MIPS_linkage_name:
		case DW_AT_HP_linkage_name:
		case DW_AT_name:
		case DW_AT_producer:
		{
			ret = getAttrStr(attr);
			break;
		}
		default:
		{
			r = false;
		}
	}

	dwarf_dealloc(m_dbg, attr, DW_DLA_ATTR);
	return r;
}

bool AttrProcessor::get(Dwarf_Half attrCode, const std::string* &ret)
{
	ret = &EMPTY_STR;

	Dwarf_Attribute attr;
	m_res = dwarf_attr(m_die, attrCode, &attr, &m_error);
	if (m_res != DW_DLV_OK)
	{
		if (m_res == DW_DLV_ERROR)
			DWARF_ERROR(getDwarfError(m_error));
		return false;
	}

	bool r = true;
	switch (attrCode)
	{
		case DW_AT_decl_file:
		{
			Dwarf_Unsigned fileNum = getAttrNumb(attr);
			DwarfCU *lastCU = m_parent->m_activeCU;

			if(lastCU &&
				(fileNum > 0) &&
				(lastCU->srcFilesCount() > (fileNum-1)))
			{
				ret = lastCU->getSrcFile(fileNum-1);
			}
			else
			{
				r = false;
			}

			break;
		}
		default:
		{
			r = false;
		}
	}

	dwarf_dealloc(m_dbg, attr, DW_DLA_ATTR);
	return r;
}

bool AttrProcessor::get(Dwarf_Half attrCode, Dwarf_Signed& ret)
{
	ret = EMPTY_SIGNED;

	Dwarf_Attribute attr;
	m_res = dwarf_attr(m_die, attrCode, &attr, &m_error);
	if (m_res != DW_DLV_OK)
	{
		if (m_res == DW_DLV_ERROR)
			DWARF_ERROR(getDwarfError(m_error));
		return false;
	}

	bool r = true;
	switch (attrCode)
	{
		case DW_AT_const_value: // !!! block, constant, string
		{
			ret = getAttrNumb(attr);
			break;
		}
		default:
		{
			r = false;
		}
	}

	dwarf_dealloc(m_dbg, attr, DW_DLA_ATTR);
	return r;
}

bool AttrProcessor::get(Dwarf_Half attrCode, Dwarf_Unsigned& ret)
{
	ret = EMPTY_UNSIGNED;

	Dwarf_Attribute attr;
	m_res = dwarf_attr(m_die, attrCode, &attr, &m_error);
	if (m_res != DW_DLV_OK)
	{
		if (m_res == DW_DLV_ERROR)
			DWARF_ERROR(getDwarfError(m_error));
		return false;
	}

	bool r = true;
	switch (attrCode)
	{
		case DW_AT_low_pc:
		{
			ret = getAttrAddr(attr);
			break;
		}
		case DW_AT_high_pc:
		{
			Dwarf_Half theform;
			dwarf_whatform(attr,&theform,&m_error);

			if (theform == DW_FORM_addr)
				ret = getAttrAddr(attr); // address class
			else
				ret = getAttrNumb(attr); // constant class - offset from low

			break;
		}
		case DW_AT_abstract_origin:
		case DW_AT_sibling:
		case DW_AT_specification:
		{
			ret = getAttrGlobalRef(attr);
			break;
		}
		case DW_AT_ordering:
		case DW_AT_byte_size: // !!! constant, exprloc, reference
		case DW_AT_bit_offset: // !!! constant, exprloc, reference
		case DW_AT_bit_size: // !!! constant, exprloc, reference
		case DW_AT_language:
		case DW_AT_discr_value:
		case DW_AT_visibility:
		case DW_AT_const_value: // !!! block, constant, string
		case DW_AT_inline:
		case DW_AT_upper_bound: // !!! constant, exprloc, reference
		case DW_AT_accessibility:
		case DW_AT_address_class:
		case DW_AT_calling_convention:
		case DW_AT_decl_column:
		//case DW_AT_decl_file: // !!! implemented below
		case DW_AT_decl_line:
		case DW_AT_encoding:
		case DW_AT_identifier_case:
		case DW_AT_virtuality:
		case DW_AT_call_column:
		case DW_AT_call_file:
		case DW_AT_call_line:
		case DW_AT_binary_scale:
		case DW_AT_decimal_scale:
		case DW_AT_decimal_sign:
		case DW_AT_digit_count:
		case DW_AT_endianity:
		case DW_AT_data_bit_offset:
		{
			ret = getAttrNumb(attr);
			break;
		}
		default:
		{
			r = false;
		}
	}

	dwarf_dealloc(m_dbg, attr, DW_DLA_ATTR);
	return r;
}

bool AttrProcessor::get(Dwarf_Half attrCode, Dwarf_Bool& ret)
{
	ret = false;

	Dwarf_Attribute attr;
	m_res = dwarf_attr(m_die, attrCode, &attr, &m_error);
	if (m_res != DW_DLV_OK)
	{
		if (m_res == DW_DLV_ERROR)
			DWARF_ERROR(getDwarfError(m_error));
		return false;
	}

	bool r = true;
	switch (attrCode)
	{
		case DW_AT_is_optional:
		case DW_AT_prototyped:
		case DW_AT_artificial:
		case DW_AT_declaration:
		case DW_AT_external:
		case DW_AT_variable_parameter:
		case DW_AT_use_UTF8:
		case DW_AT_mutable:
		case DW_AT_threads_scaled:
		case DW_AT_explicit:
		case DW_AT_elemental:
		case DW_AT_pure:
		case DW_AT_recursive:
		case DW_AT_main_subprogram:
		case DW_AT_const_expr:
		case DW_AT_enum_class:
		{
			ret = getAttrFlag(attr);
			break;
		}
		default:
		{
			r = false;
		}
	}

	dwarf_dealloc(m_dbg, attr, DW_DLA_ATTR);
	return r;
}

bool AttrProcessor::get(Dwarf_Half attrCode, DwarfLocationDesc* &ret)
{
	ret = nullptr;

	Dwarf_Attribute attr;
	m_res = dwarf_attr(m_die, attrCode, &attr, &m_error);
	if (m_res != DW_DLV_OK)
	{
		if (m_res == DW_DLV_ERROR)
			DWARF_ERROR(getDwarfError(m_error));
		return false;
	}

	bool r = true;
	switch (attrCode)
	{
		case DW_AT_location:
		case DW_AT_data_member_location:
		case DW_AT_frame_base:
		{
			ret = new DwarfLocationDesc();

			Dwarf_Half theform = 0;
			Dwarf_Half directform = 0;
			get_form_values(attr, theform, directform);

			// Location form - original form working on ARM, MIPS.
			if (is_location_form(theform))
			{
				Dwarf_Locdesc **locs; // list of location descriptions
				Dwarf_Signed cnt; // number of list records

				m_res = dwarf_loclist_n(attr, &locs, &cnt, &m_error);
				if (m_res != DW_DLV_OK)
				{
					delete ret;
					ret = nullptr;
					return false;
				}

				// List of expressions.
				for (int i=0; i<cnt; i++)
				{
					DwarfLocationDesc::Expression e;

					e.lowAddr = locs[i]->ld_lopc;
					e.highAddr = locs[i]->ld_hipc;

					// List of atoms in one expression.
					for (int j=0; j<locs[i]->ld_cents;j++)
					{
						Dwarf_Loc *atom = &(locs[i]->ld_s[j]);

						DwarfLocationDesc::Atom a;

						a.opcode = atom->lr_atom;
						a.op1 = atom->lr_number;
						a.op2 = atom->lr_number2;
						a.off = atom->lr_offset;

						e.atoms.push_back(a);
					}

					ret->addExpr(e);

					dwarf_dealloc(m_dbg, locs[i]->ld_s, DW_DLA_LOC_BLOCK);
					dwarf_dealloc(m_dbg, locs[i], DW_DLA_LOCDESC);
				}

				dwarf_dealloc(m_dbg, locs, DW_DLA_LIST);
			}

			// Expression location - occured on x86.
			else if (theform == DW_FORM_exprloc)
			{
				// Get expression location pointer.
				Dwarf_Unsigned retExprLen; // Length of location expression.
				Dwarf_Ptr blockPtr = nullptr; // Pointer to location expression.
				m_res = dwarf_formexprloc(attr, &retExprLen, &blockPtr, &m_error);

				if (m_res != DW_DLV_OK)
				{
					if (m_res == DW_DLV_ERROR)
					{
						DWARF_ERROR("dwarf_formexprloc() error.");
					}

					delete ret;
					ret = nullptr;
					return false;
				}

				// Get address size.
				Dwarf_Half addrSize = 0;
				m_res = dwarf_get_die_address_size(m_die, &addrSize, &m_error);

				if (m_res != DW_DLV_OK)
				{
					delete ret;
					ret = nullptr;
					return false;
				}

				// Get list of location descriptors -- only one location expression.
				Dwarf_Locdesc *loc = nullptr;
				Dwarf_Signed cnt;

				m_res = dwarf_loclist_from_expr_a(m_dbg,
						blockPtr,
						retExprLen,
						addrSize,
						&loc,
						&cnt, // should be set to 1.
						&m_error);
				if (m_res != DW_DLV_OK) {
					delete ret;
					ret = nullptr;
					return false;
				}

				// Copy single location to higher representation.
				DwarfLocationDesc::Expression e;
				e.lowAddr = loc->ld_lopc;
				e.highAddr = loc->ld_hipc;
				// List of atoms in one expression.
				for (int j=0; j<loc->ld_cents;j++)
				{
					Dwarf_Loc *atom = &(loc->ld_s[j]);
					DwarfLocationDesc::Atom a;

					a.opcode = atom->lr_atom;
					a.op1 = atom->lr_number;
					a.op2 = atom->lr_number2;
					a.off = atom->lr_offset;

					e.atoms.push_back(a);
				}
				ret->addExpr(e);

				dwarf_dealloc(m_dbg, loc->ld_s, DW_DLA_LOC_BLOCK);
				dwarf_dealloc(m_dbg, loc, DW_DLA_LOCDESC);
			}

			//
			else if (theform == DW_FORM_data1 ||
						theform == DW_FORM_data2 ||
						theform == DW_FORM_data4 ||
						theform == DW_FORM_data8)
			{
				// TODO: dwarf-cpp-test: DW_AT_data_member_location:
				// tu by to chcelo vratit konstantu a nie location,
				// data member su vacsinou aj tak hodnoty a nie vyrazy.
				//
				//Dwarf_Unsigned *num = (Dwarf_Unsigned*) ret
				//*num = getAttrNumb(attr)
				break;
			}

			// Bad attribute form.
			else
			{
				DWARF_ERROR("Attribute form error: " << hex << attrCode << " : " << theform);
				delete ret;
				ret = nullptr;
				return false;
			}

			break;
		}
		default:
		{
			r =  false;
		}
	}

	dwarf_dealloc(m_dbg, attr, DW_DLA_ATTR);
	return r;
}

bool AttrProcessor::get(Dwarf_Half attrCode, DwarfType* &ret)
{
	ret = m_parent->getTypes()->getVoid();

	Dwarf_Attribute attr;
	m_res = dwarf_attr(m_die, attrCode, &attr, &m_error);
	if (m_res != DW_DLV_OK)
	{
		if (m_res == DW_DLV_ERROR)
			DWARF_ERROR(getDwarfError(m_error));
		return false;
	}

	bool r = true;
	switch (attrCode)
	{
		case DW_AT_type:
		{
			Dwarf_Off typeRef = getAttrGlobalRef(attr);
			Dwarf_Die typeDie;

			m_res = dwarf_offdie_b(m_dbg, typeRef, is_info, &typeDie, &m_error);

			if (m_res == DW_DLV_ERROR)
			{
				DWARF_ERROR(getDwarfError(m_error));
				return false;
			}

			if (m_res == DW_DLV_NO_ENTRY)
			{
				return false;
			}

			ret = m_parent->getTypes()->loadAndGetDie(typeDie, 0);
			if (ret == nullptr)
			{
				ret = m_parent->getTypes()->getVoid();
				return false;
			}

			break;
		}
		default:
		{
			r = false;
		}
	}

	dwarf_dealloc(m_dbg, attr, DW_DLA_ATTR);
	return r;
}

bool AttrProcessor::geti(Dwarf_Half attrCode, int& ret)
{
	ret = 0;

	Dwarf_Attribute attr;
	m_res = dwarf_attr(m_die, attrCode, &attr, &m_error);
	if (m_res != DW_DLV_OK)
	{
		if (m_res == DW_DLV_ERROR)
			DWARF_ERROR(getDwarfError(m_error));
		return false;
	}

	bool r = true;
	switch (attrCode)
	{
		case DW_AT_type:
		{
			Dwarf_Off typeRef = getAttrGlobalRef(attr);
			Dwarf_Die typeDie;

			m_res = dwarf_offdie_b(m_dbg, typeRef, is_info, &typeDie, &m_error);

			if (m_res == DW_DLV_ERROR)
			{
				DWARF_ERROR(getDwarfError(m_error));
				return false;
			}

			if (m_res == DW_DLV_NO_ENTRY)
			{
				return false;
			}

			ret = m_parent->getTypes()->getDieFlags(typeDie, 0);
			break;
		}
		default:
		{
			r = false;
		}
	}

	dwarf_dealloc(m_dbg, attr, DW_DLA_ATTR);
	return r;
}

} // namespace dwarfparser
} // namespace retdec
