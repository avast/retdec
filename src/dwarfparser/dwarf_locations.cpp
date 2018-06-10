/**
 * @file src/dwarfparser/dwarf_locations.cpp
 * @brief Implementaion of classes representing locations.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <stack>

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#include "retdec/dwarfparser/dwarf_file.h"
#include "retdec/dwarfparser/dwarf_locations.h"

using namespace std;

namespace retdec {
namespace dwarfparser {

/**
 * @brief ctor.
 * @param tt Location type.
 */
DwarfLocationDesc::cLocType::cLocType(eLocType tt) :
	t(tt)
{

}

/**
 * @brief Test if location is register.
 * @return True if register, flase otherwise.
 */
bool DwarfLocationDesc::cLocType::isRegister()
{
	return (t == REGISTER) ? (true) : (false);
}

/**
 * @brief Test if location is address.
 * @return True if address, false otherwise.
 */
bool DwarfLocationDesc::cLocType::isAddress()
{
	return (t == ADDRESS) ? (true) : (false);
}

/**
 * @brief Test if location is a value of the object.
 * @return True if value, false otherwise.
 */
bool DwarfLocationDesc::cLocType::isValue()
{
	return (t == VALUE) ? (true) : (false);
}

/**
 * @brief Test if location type is invalid.
 * @return True if invalid, false otherwise.
 */
bool DwarfLocationDesc::cLocType::failed()
{
	return (t == FAIL) ? (true) : (false);
}

/**
 * @brief ctor.
 */
DwarfLocationDesc::DwarfLocationDesc() :
		m_baseFunc(nullptr),
		m_parent(nullptr)
{

}

/**
 * @brief Add expression to location descriptor.
 * @param e Expression to add.
 */
void DwarfLocationDesc::addExpr(Expression e)
{
	m_exprs.push_back(e);
}

/**
 * @brief Get resource access object.
 * @return Pointer to resource access object.
 */
DwarfResources *DwarfLocationDesc::getResources()
{
	return &(m_parent->getParentFile()->resources);
}

/**
 * @brief Set base function of this location.
 * @param f Pointer to base function.
 */
void DwarfLocationDesc::setBaseFunc(DwarfFunction *f)
{
	m_baseFunc = f;
}

/**
 * @brief Get frame base location.
 * @return Frame base.
 */
DwarfLocationDesc *DwarfLocationDesc::getBaseLoc()
{
	return (m_baseFunc->frameBase);
}

/**
 * @brief Set parent of this location.
 * @param p Parent.
 */
void DwarfLocationDesc::setParent(DwarfBaseElement *p)
{
	m_parent = p;
}

/**
 * @brief Set compilation unit for this location.
 */
DwarfCU *DwarfLocationDesc::getCuParent()
{
	if (m_parent != nullptr)
		return (m_parent->getCuParent());
	else
		return nullptr;
}

/**
 * @brief Get name of parent object.
 * @return Parent name.
 */
string DwarfLocationDesc::getParentName()
{
	if (DwarfFunction *f = dynamic_cast<DwarfFunction*> (m_parent))
		return f->name;
	else if (DwarfVar *v = dynamic_cast<DwarfVar*> (m_parent))
		return v->name;
	else
		return "";

}

/**
 * @brief Get number of expressions of this location descriptor.
 * @return Number of expressions.
 */
std::size_t DwarfLocationDesc::count() const
{
	return m_exprs.size();
}

/**
 * @brief Location description is empty if id does not have any expression records.
 * @return True if empty, false otherwise.
 */
bool DwarfLocationDesc::isEmpty()
{
	return (count() == 0);
}

/**
 * @brief Location description is normal if it has only one expression record.
 * @return True if normal, false otherwise.
 */
bool DwarfLocationDesc::isNormal() const
{
	return (count() == 1);
}

/**
 * @brief Location description is list if it has multiple expression records.
 * @return True if list, false otherwise.
 */
bool DwarfLocationDesc::isList()
{
	return (count() > 1);
}

/**
 * @brief If variable is on stack, get its offset from stack pointer;
 * @param off Pointer to offset that will be filled by method.
 *        If variable is not on stack it will be set to zero.
 * @param deref  Pointer to boolean value that will be filled by method.
 *        If true then on address counted using returned offset is an
 *        address of variable data.
 *        If false then there are actual data on counted address.
 *        If variable is not on stack it will be set to false.
 * @param pc Actual program counter.
 * @param regNum Pointer to number of register where the offset is, filled by method.
 *        -1 if on stack. This is used in case of DW_OP_bregX.
 * @return True if variable on stack, false otherwise.
 */
bool DwarfLocationDesc::isOnStack(Dwarf_Signed *off, bool *deref, Dwarf_Addr pc, int *regNum)
{
	Expression *e = nullptr;

	//
	// Only one expression.
	//
	if (isNormal() && getCuParent())
	{
		Expression &ex = m_exprs.front();

		// Expression range is unlimited -> get expression.
		if (ex.lowAddr==0 && ex.highAddr==numeric_limits<Dwarf_Unsigned>::max())
			e = &(ex);

		// CUs lowpc is base for expression's range.
		Dwarf_Addr low = ex.lowAddr + getCuParent()->lowAddr;
		Dwarf_Addr high = ex.highAddr  + getCuParent()->highAddr;

		if ((pc >= low) &&
			(pc < high))
		{
			e = &(ex);
		}
	}
	//
	// Expression list -- determine correct one based on program counter address.
	//
	else if (isList() && getCuParent())
	{
		vector<Expression>::iterator iter;

		for (iter=m_exprs.begin(); iter!=m_exprs.end(); ++iter)
		{
			// Expression range is unlimited -> get expression.
			// This should not happen in expression list, but check anyway.
			if ((*iter).lowAddr==0 && (*iter).highAddr==numeric_limits<Dwarf_Unsigned>::max())
				e = &(*iter);

			// CUs lowpc is base for location list ranges.
			Dwarf_Addr low = (*iter).lowAddr + getCuParent()->lowAddr;
			Dwarf_Addr high = (*iter).highAddr + getCuParent()->highAddr;

			if ((pc >= low) &&
				(pc < high))
			{
				e = &(*iter);
			}
		}
	}
	//
	// Should not happen.
	//
	else
	{
		DWARF_ERROR("Invalid type of location description in isOnStack() method.");
	}

	//
	// Expression have only one atom -- DW_OP_fbreg,
	// or two atoms -- DW_OP_fbreg, DW_OP_deref.
	//
	if (e!=nullptr && e->atoms.size() == 1)
	{
		Atom &a = e->atoms.front();

		if (a.opcode == DW_OP_fbreg)
		{
			*off = a.op1;
			*deref = false;
			if (regNum) *regNum = -1;
			return true;
		}

		if (a.opcode >= DW_OP_breg0 && a.opcode <= DW_OP_breg31)
		{
			*off = a.op1;
			*deref = false;
			if (regNum) *regNum = a.opcode - DW_OP_breg0;
			return true;
		}
	}
	else if (e!=nullptr && e->atoms.size() == 2)
	{
		Atom &a0 = e->atoms[0];
		Atom &a1 = e->atoms[1];

		if (a0.opcode == DW_OP_fbreg && a1.opcode == DW_OP_deref)
		{
			*off = a0.op1;
			*deref = true;
			if (regNum) *regNum = -1;
			return true;
		}
	}

	*off = 0;
	*deref = false;
	if (regNum) *regNum = -1;
	return false;
}

/**
 * @brief Print contents of location descriptor class.
 */
void DwarfLocationDesc::dump()
{
	for (unsigned i=0; i<m_exprs.size(); i++)
	{
		cout << "range :  " << hex << m_exprs[i].lowAddr << " - " << m_exprs[i].highAddr << endl;
		cout << "atoms :  " << m_exprs[i].atoms.size() << endl;
		for (unsigned j=0; j<m_exprs[i].atoms.size(); j++)
		{
			Atom a = m_exprs[i].atoms[j];

			const char *name;
			dwarf_get_OP_name(a.opcode, &name);

			if (dwarf_get_OP_name(a.opcode, &name) == DW_DLV_OK)
				cout << "\t" << name << " (" << a.op1 << ") (" << a.op2 << ")" << endl;
			else
				cout << "\t<NO_NAME_IN_LIBDWARF> (" << a.op1 << ") (" << a.op2 << ")" << endl;
		}
		cout << endl;
	}
}

/**
 * @brief Compute value of location descriptor.
 * @param n  Pointer to string that will be filled by method.
 *        If location is address this is a name of address space.
 *        If location is register this is a name of register array.
 * @param a  Pointer to value that will be filled by method.
 *        If location is address this is an address in address space.
 *        If location is register this is a number in register array.
 * @param pc Program counter value.
 * @param base Base address.
 * @param hasBase @c true if it has a base address; @c false otherwise.
 * @return Type of location - address or register.
 */
DwarfLocationDesc::cLocType DwarfLocationDesc::computeLocation(string *n,
	Dwarf_Addr *a, Dwarf_Addr pc, Dwarf_Addr base, bool hasBase)
{
	n->clear();

	//
	// Only one expression -- check that program counter is in this expression's range.
	//
	if (isNormal() && getCuParent())
	{
		Expression &e = m_exprs.front();

		// Expression range is unlimited -> evaluate.
		if (e.lowAddr==0 && e.highAddr==numeric_limits<Dwarf_Unsigned>::max())
			return (evaluateExpression(e, n, a, pc, base, hasBase));

		// We have got program counter, check if it is in range of the expression.
		// CUs lowpc is base for expression's range.
		Dwarf_Addr low = e.lowAddr + getCuParent()->lowAddr;
		Dwarf_Addr high = e.highAddr  + getCuParent()->highAddr;

		if ((pc >= low) &&
			(pc < high))
		{
			return (evaluateExpression(e, n, a, pc, base, hasBase));
		}
	}

	//
	// There are multiple expressions.
	// Find correct one based on program counter address.
	//
	else if (isList() && getCuParent())
	{
		vector<Expression>::iterator iter;

		for (iter=m_exprs.begin(); iter!=m_exprs.end(); ++iter)
		{
			// Expression range is unlimited -> evaluate.
			// This should not happen in expression list, but check anyway.
			if ((*iter).lowAddr==0 && (*iter).highAddr==numeric_limits<Dwarf_Unsigned>::max())
				return (evaluateExpression((*iter), n, a, pc, base, hasBase));

			// CUs lowpc is base for location list ranges.
			Dwarf_Addr low = (*iter).lowAddr + getCuParent()->lowAddr;
			Dwarf_Addr high = (*iter).highAddr + getCuParent()->highAddr;

			if ((pc >= low) &&
				(pc < high))
			{
				return (evaluateExpression((*iter), n, a, pc, base, hasBase));
			}
		}

		// TODO - Temporary disabled, create some flag/define that will control warning printing.
		//string warMsg = "Program counter not in range of frame base.";
		//dwarfapi_warning(warMsg.c_str());
	}

	//
	// Should not happen.
	//
	else
	{
		DWARF_ERROR("Invalid type of location description in computeLocation() method: " << count());
	}

	return cLocType(FAIL);
}

/**
 * @brief Evaluate DWARF expression.
 * @param expr Reference to expression to evaluate.
 * @param retN Pointer to string that will be filled by method.
 *        If location is address this is a name of address space.
 *        If location is register this is a name of register array.
 *        If location is actual value this is nullptr.
 * @param retA Pointer to value that will be filled by method.
 *        If location is address this is an address in address space.
 *        If location is register this is a number in register array.
 *        If location is actual value this is a the value.
 * @param pc   Program counter value.
 * @param base Base address.
 * @param hasBase @c true if it has a base address; @c false otherwise.
 * @return Type of variable location - address or register.
 *
 *
 * According to DWARF specification:
 * http://www.dwarfstd.org/doc/040408.1.html
 * Warning - some opcodes like DW_OP_const1_type, DW_OP_regval, ...
 * (the green ones in web page) are not processed -- there is no support
 * in libdwarf for them.
 *
 * TODO - Dwarf_Addr alebo Dwarf_Signed -- moze to byt zaporne?
 *      - Asi ano -- nemusi to byt len adresa.
 */
DwarfLocationDesc::cLocType
DwarfLocationDesc::evaluateExpression(Expression &expr, string *retN,
	Dwarf_Addr *retA, Dwarf_Addr pc, Dwarf_Addr base, bool hasBase)
{

	//
	// There must be at least one atom.
	//
	if (expr.count() < 1)
	{
		DWARF_WARNING("There are no atoms in DWARF expression.");
		return cLocType(FAIL);
	}

	//
	// Register Location Descriptions.
	//
	// TODO - right now it works only if there is only one atom determining register
	// but there might be multiple atoms, for example if Composite Location Descriptions
	// are used.
	//

	if ((expr.atoms[0].opcode >= DW_OP_reg0) &&
		(expr.atoms[0].opcode <= DW_OP_reg31))
	{
		if (hasBase)
		{
			// Evaluation with base is supported only with address location
			return cLocType(FAIL);
		}
		// Special case for long/double registers composed from two registers.
		// They do not have to be one after another.
		if (expr.count() == 4)
		{
			// There must be exact sequence of OP codes, and second register.
			if (expr.atoms[1].opcode != DW_OP_piece || expr.atoms[1].op1 != 4) return cLocType(FAIL);
			if (!(expr.atoms[2].opcode >= DW_OP_reg0 && expr.atoms[2].opcode <= DW_OP_reg31)) return cLocType(FAIL);
			if (expr.atoms[3].opcode != DW_OP_piece || expr.atoms[3].op1 != 4) return cLocType(FAIL);

			// TODO - only the first register is returned at the moment.
			Dwarf_Half regNum = expr.atoms[0].opcode - DW_OP_reg0;
			getResources()->setReg(regNum, retN, retA);
			return cLocType(REGISTER);
		}

		// One atom check -- TODO: remove after implementing
		if (expr.count() > 1)
		{
			// "There are multiple atoms in DWARF expression.
			return cLocType(FAIL);
		}

		Dwarf_Half regNum = expr.atoms[0].opcode - DW_OP_reg0;
		getResources()->setReg(regNum, retN, retA);

		return cLocType(REGISTER);
	}
	else if (expr.atoms[0].opcode == DW_OP_regx)
	{
		if (hasBase)
		{
			// Evaluation with base is supported only with address location
			return cLocType(FAIL);
		}
		// Special case for double registers composed from two float registers.
		if (expr.count() == 4)
		{
			// There must be exact sequence of OP codes, and second register
			// must folow the first one.
			Dwarf_Half firstReg = expr.atoms[0].op1;
			if (expr.atoms[1].opcode != DW_OP_piece || expr.atoms[1].op1 != 4) return cLocType(FAIL);
			if (expr.atoms[2].opcode != DW_OP_regx || expr.atoms[2].op1 != unsigned(firstReg+1)) return cLocType(FAIL);
			if (expr.atoms[3].opcode != DW_OP_piece || expr.atoms[3].op1 != 4) return cLocType(FAIL);

			getResources()->setReg(expr.atoms[0].op1 + expr.atoms[2].op1, retN, retA);
			return cLocType(REGISTER);
		}

		// One atom check -- TODO: remove after implementing
		if (expr.count() > 1)
		{
			// There are multiple atoms in DWARF expression.
			return cLocType(FAIL);
		}

		getResources()->setReg(expr.atoms[0].op1, retN, retA);
		return cLocType(REGISTER);
	}

	//
	// Address Location Descriptions.
	//
	// Use stack machine to evaluate.
	// Iterate through all atoms, perform operations on stack and value at
	// the top is the result.
	//

	stack<Dwarf_Signed> mystack;

	if (hasBase)
	{
		mystack.push(base);
	}

	vector<Atom>::iterator iter;
	for (iter=expr.atoms.begin(); iter!=expr.atoms.end(); ++iter)
	{
		Atom &a = (*iter);

		switch(a.opcode)
		{
		//
		// Literal Encodings.
		// Push a value onto the DWARF stack.
		//

			// Literals.
			case DW_OP_lit0:
			case DW_OP_lit1:
			case DW_OP_lit2:
			case DW_OP_lit3:
			case DW_OP_lit4:
			case DW_OP_lit5:
			case DW_OP_lit6:
			case DW_OP_lit7:
			case DW_OP_lit8:
			case DW_OP_lit9:
			case DW_OP_lit10:
			case DW_OP_lit11:
			case DW_OP_lit12:
			case DW_OP_lit13:
			case DW_OP_lit14:
			case DW_OP_lit15:
			case DW_OP_lit16:
			case DW_OP_lit17:
			case DW_OP_lit18:
			case DW_OP_lit19:
			case DW_OP_lit20:
			case DW_OP_lit21:
			case DW_OP_lit22:
			case DW_OP_lit23:
			case DW_OP_lit24:
			case DW_OP_lit25:
			case DW_OP_lit26:
			case DW_OP_lit27:
			case DW_OP_lit28:
			case DW_OP_lit29:
			case DW_OP_lit30:
			case DW_OP_lit31:
				mystack.push(a.opcode - DW_OP_lit0);
				break;

			// First operand pushed to stack.
			// Signed and unsigned together.
			case DW_OP_addr:
			case DW_OP_const1u:
			case DW_OP_const1s:
			case DW_OP_const2u:
			case DW_OP_const2s:
			case DW_OP_const4u:
			case DW_OP_const4s:
			case DW_OP_const8u:
			case DW_OP_const8s:
			case DW_OP_constu:
			case DW_OP_consts:
				mystack.push(a.op1);
				break;

		//
		// Register Based Addressing.
		// Pushed value is result of adding the contents of a register
		// with a given signed offset.
		//

			// Frame base plus signed first operand.
			case DW_OP_fbreg:
			{
				string name;
				Dwarf_Addr fbase;

				Dwarf_Addr pcReg = pc;
				DwarfLocationDesc::cLocType ret = getBaseLoc()->computeLocation(&name, &fbase, pcReg);

				if (ret.isAddress())
				{
					mystack.push(fbase + Dwarf_Signed(a.op1));
				}
				else if (ret.isRegister())
				{
					return cLocType(FAIL);
				}
				else
				{
					// PC may be outside of frame base range.
					return cLocType(FAIL);
				}

				break;
			}

			// Content of register (address) plus signed first operand.
			case DW_OP_breg0:
			case DW_OP_breg1:
			case DW_OP_breg2:
			case DW_OP_breg3:
			case DW_OP_breg4:
			case DW_OP_breg5:
			case DW_OP_breg6:
			case DW_OP_breg7:
			case DW_OP_breg8:
			case DW_OP_breg9:
			case DW_OP_breg10:
			case DW_OP_breg11:
			case DW_OP_breg12:
			case DW_OP_breg13:
			case DW_OP_breg14:
			case DW_OP_breg15:
			case DW_OP_breg16:
			case DW_OP_breg17:
			case DW_OP_breg18:
			case DW_OP_breg19:
			case DW_OP_breg20:
			case DW_OP_breg21:
			case DW_OP_breg22:
			case DW_OP_breg23:
			case DW_OP_breg24:
			case DW_OP_breg25:
			case DW_OP_breg26:
			case DW_OP_breg27:
			case DW_OP_breg28:
			case DW_OP_breg29:
			case DW_OP_breg30:
			case DW_OP_breg31:
			{
				return cLocType(FAIL);
			}

			//
			case DW_OP_bregx:
			{
				return cLocType(FAIL);
			}

		//
		// Stack Operations.
		// Operations manipulate the DWARF stack.
		//

			// Duplicates the value at the top of the stack.
			case DW_OP_dup:
				if (mystack.empty())
				{
					return cLocType(FAIL);
				}
				mystack.push(mystack.top());
				break;

			// Pops the value at the top of the stack
			case DW_OP_drop:
				if (mystack.empty())
				{
					return cLocType(FAIL);
				}
				mystack.pop();
				break;

			// Entry with specified index is copied at the top.
			case DW_OP_pick:
			{
				Dwarf_Unsigned idx = a.op1;
				stack<Dwarf_Signed> t;

				if (mystack.size() < (idx + 1))
				{
					return cLocType(FAIL);
				}

				for (unsigned i=0; i<idx; i++)
				{
					t.push(mystack.top());
					mystack.pop();
				}

				Dwarf_Signed pick = mystack.top();

				for (unsigned i=0; i<idx; i++)
				{
					mystack.push(t.top());
					t.pop();
				}

				mystack.push(pick);
				break;
			}

			// Duplicates the second entry to the top of the stack.
			case DW_OP_over:
			{
				if (mystack.size() < 2)
				{
					return cLocType(FAIL);
				}

				Dwarf_Signed t = mystack.top();
				mystack.pop();
				Dwarf_Signed d = mystack.top();

				mystack.push(t);
				mystack.push(d);
				break;
			}

			// Swaps the top two stack entries.
			case DW_OP_swap:
			{
				if (mystack.size() < 2)
				{
					return cLocType(FAIL);
				}

				Dwarf_Signed e1 = mystack.top();
				mystack.pop();
				Dwarf_Signed e2 = mystack.top();
				mystack.pop();

				mystack.push(e1);
				mystack.push(e2);
				break;
			}

			// Rotates the first three stack entries
			case DW_OP_rot:
			{
				if (mystack.size() < 3)
				{
					return cLocType(FAIL);
				}

				Dwarf_Signed e1 = mystack.top();
				mystack.pop();
				Dwarf_Signed e2 = mystack.top();
				mystack.pop();
				Dwarf_Signed e3 = mystack.top();
				mystack.pop();

				mystack.push(e1);
				mystack.push(e3);
				mystack.push(e2);
				break;
			}

			// Pops the top stack entry and treats it as an address.
			// The value retrieved from that address is pushed.
			case DW_OP_deref:
			{
				if (mystack.empty())
				{
					return cLocType(FAIL);
				}

				Dwarf_Addr adr = mystack.top();
				mystack.pop();
				mystack.push(getResources()->getAddr(adr));
				break;
			}

			//
			case DW_OP_deref_size:
			{
				// TODO
				break;
			}

			//
			case DW_OP_xderef:
			{
				// TODO
				break;
			}

			//
			case DW_OP_xderef_size:
			{
				// TODO
				break;
			}

			//
			case DW_OP_push_object_address:
			{
				// TODO
				break;
			}

			//
			case DW_OP_form_tls_address:
			{
				// TODO
				break;
			}

			//
			case DW_OP_call_frame_cfa:
			{
				// TODO
				DWARF_ERROR("DW_OP_call_frame_cfa.");
				return cLocType(FAIL);
			}

		//
		// Arithmetic and Logical Operations.
		// The arithmetic operations perform addressing arithmetic, that is,
		// unsigned arithmetic that wraps on an address-sized boundary.
		//

			// Operates on top entry.
			case DW_OP_abs:
			case DW_OP_neg:
			case DW_OP_not:
			case DW_OP_plus_uconst:
			{
				if (mystack.empty())
				{
					return cLocType(FAIL);
				}
				Dwarf_Signed top = mystack.top();
				mystack.pop();

				switch(a.opcode)
				{
					// Replace top with it's absolute value.
					case DW_OP_abs: mystack.push(abs(top));
						break;

					// Negate top.
					case DW_OP_neg: mystack.push(-top);
						break;

					// Bitwise complement of the top.
					case DW_OP_not: mystack.push(~top);
						break;

					// Top value plus unsigned first operand.
					case DW_OP_plus_uconst: mystack.push(top + a.op1);
						break;

					// Should not happen.
					default:
						DWARF_ERROR("Should not happen.");
						return cLocType(FAIL);
				}

				break;
			}

			// Operates on top two entries.
			case DW_OP_and:
			case DW_OP_div:
			case DW_OP_minus:
			case DW_OP_mod:
			case DW_OP_mul:
			case DW_OP_or:
			case DW_OP_plus:
			case DW_OP_shl:
			case DW_OP_shr:
			case DW_OP_shra:
			case DW_OP_xor:
			{
				if (mystack.size() < 2)
				{
					return cLocType(FAIL);
				}
				Dwarf_Signed e1 = mystack.top();
				mystack.pop();
				Dwarf_Signed e2 = mystack.top();
				mystack.pop();

				switch(a.opcode)
				{
					// Bitwise and on top 2 values.
					case DW_OP_and: mystack.push(e1 & e2);
						break;

					// Second div first from top (signed division).
					case DW_OP_div: mystack.push(e2 / e1);
						break;

					// Second minus first from top.
					case DW_OP_minus: mystack.push(e2 - e1);
						break;

					// Second modulo first from top.
					case DW_OP_mod: mystack.push(e2 % e1);
						break;

					// Second times first from top.
					case DW_OP_mul: mystack.push(e2 * e1);
						break;

					// Bitwise or of top 2 entries.
					case DW_OP_or: mystack.push(e2 | e1);
						break;

					// Adds together top two entries.
					case DW_OP_plus: mystack.push(e2 + e1);
						break;

					// Shift second entry to left by first entry.
					case DW_OP_shl: mystack.push(e2 << e1);
						break;

					// Shift second entry to right by first entry.
					case DW_OP_shr: mystack.push(e2 >> e1);
						break;

					// Shift second entry arithmetically to right by first entry.
					case DW_OP_shra: mystack.push(e2 >> e1);
						break;

					// Bitwise XOR on top two entries.
					case DW_OP_xor: mystack.push(e2 ^ e1);
						break;

					// Should not happen.
					default:
						DWARF_ERROR("Should not happen.");
						return cLocType(FAIL);
				}

				break;
			}

		//
		// Control Flow Operations.
		// TODO - not implemented at all right now.
		//
			case DW_OP_le:
			case DW_OP_ge:
			case DW_OP_eq:
			case DW_OP_lt:
			case DW_OP_gt:
			case DW_OP_ne:
			case DW_OP_skip:
			case DW_OP_bra:
			case DW_OP_call2:
			case DW_OP_call4:
			case DW_OP_call_ref:
			{
				break;
			}

		//
		// Implicit Location Descriptions.
		//

			case DW_OP_implicit_value:
			{
				// TODO
				break;
			}

		//
		// Composite Location Descriptions.
		// TODO - not implemented at all right now.
		//

			case DW_OP_piece:
			case DW_OP_bit_piece:
			{
				break;
			}

		//
		// Special Operations.
		//

			// This has no effect.
			case DW_OP_nop:
				break;

		//
		// Object does not exist in memory but its value is known and it is at the top
		// of the DWARF expression stack.
		// DWARF expression represents actual value of the object, rather then its location.
		// DW_OP_stack_alue operation terminates the expression.
		//
			case DW_OP_stack_value:
				if (mystack.empty())
				{
					return cLocType(FAIL);
				}
				retN = nullptr;
				*retA = mystack.top();
				return cLocType(VALUE);
				break;

		//
		// Invalid or unrecognized operations.
		//
			default:
			{
				const char *opName;
				if (dwarf_get_OP_name(a.opcode, &opName) == DW_DLV_OK)
				{
					DWARF_ERROR("Invalid or unrecognized expression operation: " << string(opName));
				}
				else
				{
					DWARF_ERROR("Invalid or unrecognized expression operation: <NO_NAME_IN_LIBDWARF>");
				}

				return cLocType(FAIL);
				break;
			}

		} // switch
	} // for

	if (mystack.empty())
	{
		return cLocType(FAIL);
	}
	else
	{
		*retA = mystack.top();
		return cLocType(ADDRESS);
	}
}

} // namespace dwarfparser
} // namespace retdec
