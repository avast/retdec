/**
* @file src/llvmir2hll/support/value_text_repr_visitor.cpp
* @brief Implementation of ValueTextReprVisitor.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/comma_op_expr.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/const_symbol.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/value_text_repr_visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new visitor.
*/
ValueTextReprVisitor::ValueTextReprVisitor():
	OrderedAllVisitor(), textRepr() {}

/**
* @brief Returns a textual representation of @a value.
*
* @param[in] value Value whose textual representation will be obtained.
*
* The returned representation is a concise representation of @a value in a
* Python-like language. It is meant to be used for debugging and developing
* purposes (for example, you can use it during debugging or when emitting a
* control-flow graph). The returned string is never ended with a new line. No
* successors of statements are considered, i.e. if @a value is a statement,
* only its representation is returned.
*
* If @a value is a compound statement or a function, the bodies of nested
* blocks are not considered. However, in this case, the returned string may
* contain new lines for better readability.
*
* @par Preconditions
*  - @a value is non-null
*
* TODO: Incorporate this functionality into HLL writers? The implementation of
*       this class is based on PyHLLWriter, anyhow.
*/
std::string ValueTextReprVisitor::getTextRepr(Value* value) {
	PRECONDITION_NON_NULL(value);

	ValueTextReprVisitor* visitor(new ValueTextReprVisitor());
	value->accept(visitor);
	return visitor->textRepr.str();
}

void ValueTextReprVisitor::visit(GlobalVarDef* varDef) {
	varDef->getVar()->accept(this);

	if (Expression* init = varDef->getInitializer()) {
		textRepr << " = ";
		init->accept(this);
	}
}

void ValueTextReprVisitor::visit(Function* func) {
	textRepr << "def " << func->getName() << "(";

	// For each parameter...
	bool paramEmitted = false;
	for (const auto &param : func->getParams()) {
		if (paramEmitted) {
			textRepr << ", ";
		}
		// If the parameter is a pointer, emit a proper amount of "*"s.
		if (PointerType* type = cast<PointerType>(param->getType())) {
			do {
				textRepr << "*";
			} while ((type = cast<PointerType>(type->getContainedType())));
		}
		param->accept(this);
		paramEmitted = true;
	}

	// Optional vararg indication.
	if (func->isVarArg()) {
		if (paramEmitted) {
			textRepr << ", ";
		}
		textRepr << "...";
	}

	textRepr << ")";
}

void ValueTextReprVisitor::visit(Variable* var) {
	textRepr << var->getName();
}

void ValueTextReprVisitor::visit(AddressOpExpr* expr) {
	textRepr << "&(";
	expr->getOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(AssignOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " = ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(ArrayIndexOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	textRepr << "[";
	expr->getSecondOperand()->accept(this);
	textRepr << "]";
}

void ValueTextReprVisitor::visit(StructIndexOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	textRepr << "['";
	expr->getSecondOperand()->accept(this);
	textRepr << "']";
}

void ValueTextReprVisitor::visit(DerefOpExpr* expr) {
	textRepr << "*(";
	expr->getOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(NotOpExpr* expr) {
	textRepr << "not (";
	expr->getOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(NegOpExpr* expr) {
	textRepr << "-(";
	expr->getOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(EqOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " == ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(NeqOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " != ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(LtOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " < ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(GtOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " > ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(LtEqOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " <= ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(GtEqOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " >= ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(TernaryOpExpr* expr) {
	textRepr << "(";
	expr->getTrueValue()->accept(this);
	textRepr << " if ";
	expr->getCondition()->accept(this);
	textRepr << " else ";
	expr->getFalseValue()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(AddOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " + ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(SubOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " - ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(MulOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " * ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(ModOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " % ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(DivOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " / ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(AndOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " and ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(OrOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " or ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(BitAndOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " & ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(BitOrOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " | ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(BitXorOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " ^ ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(BitShlOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " << ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(BitShrOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << " >> ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(CallExpr* expr) {
	expr->getCalledExpr()->accept(this);
	textRepr << "(";
	// For each argument...
	bool argEmitted = false;
	for (const auto &arg : expr->getArgs()) {
		if (argEmitted) {
			textRepr << ", ";
		}
		arg->accept(this);
		argEmitted = true;
	}
	textRepr << ")";
}

void ValueTextReprVisitor::visit(CommaOpExpr* expr) {
	textRepr << "(";
	expr->getFirstOperand()->accept(this);
	textRepr << ", ";
	expr->getSecondOperand()->accept(this);
	textRepr << ")";
}

// Casts.
void ValueTextReprVisitor::visit(BitCastExpr* expr) {
	textRepr << "BitCastExpr<";
	expr->getType()->accept(this);
	textRepr << ">(";
	expr->getOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(ExtCastExpr* expr) {
	textRepr << "ExtCastExpr<";
	expr->getType()->accept(this);
	textRepr << ">(";
	expr->getOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(TruncCastExpr* expr) {
	textRepr << "TruncCastExpr<";
	expr->getType()->accept(this);
	textRepr << ">(";
	expr->getOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(FPToIntCastExpr* expr) {
	textRepr << "FPToIntCastExpr<";
	expr->getType()->accept(this);
	textRepr << ">(";
	expr->getOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(IntToFPCastExpr* expr) {
	textRepr << "IntToFPCastExpr<";
	expr->getType()->accept(this);
	textRepr << ">(";
	expr->getOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(IntToPtrCastExpr* expr) {
	textRepr << "IntToPtrCastExpr<";
	expr->getType()->accept(this);
	textRepr << ">(";
	expr->getOperand()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(PtrToIntCastExpr* expr) {
	textRepr << "PtrToIntCastExpr<";
	expr->getType()->accept(this);
	textRepr << ">(";
	expr->getOperand()->accept(this);
	textRepr << ")";
}
// End of casts.

void ValueTextReprVisitor::visit(ConstBool* constant) {
	textRepr << (constant->getValue() ? "True" : "False");
}

void ValueTextReprVisitor::visit(ConstFloat* constant) {
	textRepr << constant->toString();
}

void ValueTextReprVisitor::visit(ConstInt* constant) {
	textRepr << constant->toString();
}

void ValueTextReprVisitor::visit(ConstNullPointer* constant) {
	textRepr << "NULL";
}

void ValueTextReprVisitor::visit(ConstString* constant) {
	textRepr << "\"";
	textRepr << constant->getValueAsEscapedCString();
	textRepr << "\"";
}

void ValueTextReprVisitor::visit(ConstArray* constant) {
	if (constant->isInitialized()) {
		textRepr << "[";
		bool first = true;
		for (const auto &element : constant->getInitializedValue()) {
			if (!first) {
				textRepr << ", ";
			}
			element->accept(this);
			first = false;
		}
		textRepr << "]";
	} else {
		// The array is not initialized.
		ArrayType::Dimensions dims(constant->getDimensions());
		if (dims.empty()) {
			textRepr << "[]";
			return;
		}

		// To prevent an emission of a lot of code, instead of emitting a
		// full-blown initializer, we emit just a call to array(). For example,
		// an initializer for an array of type `int [10][5][5]` is emitted as
		// `array(10, 5, 5)`.
		textRepr << "array(";
		bool first = true;
		for (const auto &dim : dims) {
			if (!first) {
				textRepr << ", ";
			}
			textRepr << dim;
			first = false;
		}
		textRepr << ")";
	}
}

void ValueTextReprVisitor::visit(ConstStruct* constant) {
	textRepr << "{";
	bool first = true;
	for (const auto &member : constant->getValue()) {
		if (!first) {
			textRepr << ", ";
		}
		textRepr << "'";
		member.first->accept(this);
		textRepr << "': ";
		member.second->accept(this);
		first = false;
	}
	textRepr << "}";
}

void ValueTextReprVisitor::visit(ConstSymbol* constant) {
	// (name -> value)
	textRepr << "(" << constant->getName() << " -> ";
	constant->getValue()->accept(this);
	textRepr << ")";
}

void ValueTextReprVisitor::visit(AssignStmt* stmt) {
	stmt->getLhs()->accept(this);
	textRepr << " = ";
	stmt->getRhs()->accept(this);
}

void ValueTextReprVisitor::visit(VarDefStmt* stmt) {
	stmt->getVar()->accept(this);

	if (Expression* init = stmt->getInitializer()) {
		textRepr << " = ";
		init->accept(this);
	}
}

void ValueTextReprVisitor::visit(CallStmt* stmt) {
	stmt->getCall()->accept(this);
}

void ValueTextReprVisitor::visit(ReturnStmt* stmt) {
	textRepr << "return";
	if (Expression* retVal = stmt->getRetVal()) {
		textRepr << " ";
		retVal->accept(this);
	}
}

void ValueTextReprVisitor::visit(EmptyStmt* stmt) {
	textRepr << "# empty statement";
}

void ValueTextReprVisitor::visit(IfStmt* stmt) {
	// Emit the first if clause and other else-if clauses (if any).
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		textRepr << (i == stmt->clause_begin() ? "if " : "\nelif ");
		i->first->accept(this);
		textRepr << ":";
	}

	// Emit the else clause (if any).
	if (stmt->hasElseClause()) {
		textRepr << "\nelse:";
	}
}

void ValueTextReprVisitor::visit(SwitchStmt* stmt) {
	textRepr << "switch ";
	stmt->getControlExpr()->accept(this);
	textRepr << ":";
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		textRepr << "\n";
		if (i->first) {
			textRepr << "case ";
			i->first->accept(this);
			textRepr<< ":";
		} else {
			textRepr << "default:";
		}
	}
}

void ValueTextReprVisitor::visit(WhileLoopStmt* stmt) {
	textRepr << "while ";
	stmt->getCondition()->accept(this);
	textRepr << ":";
}

void ValueTextReprVisitor::visit(ForLoopStmt* stmt) {
	textRepr << "for ";
	stmt->getIndVar()->accept(this);
	textRepr << " in range(";
	stmt->getStartValue()->accept(this);
	textRepr << ", ";
	// If the end condition is of the form `i < x`, emit just `x`, otherwise
	// emit the complete condition.
	bool endCondEmitted = false;
	if (LtOpExpr* ltEndCond = cast<LtOpExpr>(stmt->getEndCond())) {
		if (stmt->getIndVar() == ltEndCond->getFirstOperand()) {
			ltEndCond->getSecondOperand()->accept(this);
			endCondEmitted = true;
		}
	}
	if (!endCondEmitted) {
		// TODO How to make this more pythonic?
		stmt->getEndCond()->accept(this);
	}
	// Emit step only if it differs from 1.
	ConstInt* stepInt = cast<ConstInt>(stmt->getStep());
	if (!stepInt || stepInt->getValue() != 1) {
		textRepr << ", ";
		stmt->getStep()->accept(this);
	}
	textRepr << "):";
}

void ValueTextReprVisitor::visit(UForLoopStmt* stmt) {
	// Use a C version because Python does not support our "universal" for
	// loops.
	textRepr << "for (";
	if (auto init = stmt->getInit()) {
		init->accept(this);
	}
	textRepr << "; ";
	if (auto cond = stmt->getCond()) {
		cond->accept(this);
	}
	textRepr << "; ";
	if (auto step = stmt->getStep()) {
		step->accept(this);
	}
	textRepr << "):";
}

void ValueTextReprVisitor::visit(BreakStmt* stmt) {
	textRepr << "break";
}

void ValueTextReprVisitor::visit(ContinueStmt* stmt) {
	textRepr << "continue";
}

void ValueTextReprVisitor::visit(GotoStmt* stmt) {
	textRepr << "goto " << stmt->getTarget()->getLabel();
}

void ValueTextReprVisitor::visit(UnreachableStmt* stmt) {
	textRepr << "# UNREACHABLE";
}

void ValueTextReprVisitor::visit(FloatType* type) {
	textRepr << "double";
}

void ValueTextReprVisitor::visit(IntType* type) {
	if (type->isUnsigned()) {
		textRepr << "u";
	}
	textRepr << "int" << type->getSize();
}

void ValueTextReprVisitor::visit(PointerType* type) {
	textRepr << "ptr";
}

void ValueTextReprVisitor::visit(StringType* type) {
	textRepr << "string";
}

void ValueTextReprVisitor::visit(ArrayType* type) {
	textRepr << "array";
}

void ValueTextReprVisitor::visit(StructType* type) {
	textRepr << "struct (" <<
		(type->hasName() ? type->getName() : "anonymous") << ")";
}

void ValueTextReprVisitor::visit(FunctionType* type) {
	textRepr << "function";
}

void ValueTextReprVisitor::visit(VoidType* type) {
	textRepr << "void";
}

void ValueTextReprVisitor::visit(UnknownType* type) {
	textRepr << "unknown";
}

} // namespace llvmir2hll
} // namespace retdec
