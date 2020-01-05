/**
* @file src/llvmir2hll/support/visitors/ordered_all_visitor.cpp
* @brief Implementation of OrderedAllVisitor.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
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
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_type.h"
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
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/string_type.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new visitor.
*/
OrderedAllVisitor::OrderedAllVisitor(bool visitSuccessors, bool visitNestedStmts):
	Visitor(), lastStmt(), accessedStmts(), visitSuccessors(visitSuccessors),
	visitNestedStmts(visitNestedStmts) {}

void OrderedAllVisitor::visit(GlobalVarDef* varDef) {
	varDef->getVar()->accept(this);
	if (Expression* init = varDef->getInitializer()) {
		init->accept(this);
	}
}

void OrderedAllVisitor::visit(Function* func) {
	// For each parameter...
	for (const auto &param : func->getParams()) {
		param->accept(this);
	}

	if (Statement* body = func->getBody()) {
		visitStmt(body);
	}
}

//
// Statements
//

void OrderedAllVisitor::visit(AssignStmt* stmt) {
	lastStmt = stmt;
	stmt->getLhs()->accept(this);
	stmt->getRhs()->accept(this);
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(VarDefStmt* stmt) {
	lastStmt = stmt;
	stmt->getVar()->accept(this);
	if (Expression* init = stmt->getInitializer()) {
		init->accept(this);
	}
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(CallStmt* stmt) {
	lastStmt = stmt;
	stmt->getCall()->accept(this);
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(ReturnStmt* stmt) {
	lastStmt = stmt;
	if (Expression* retVal = stmt->getRetVal()) {
		retVal->accept(this);
	}
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(EmptyStmt* stmt) {
	lastStmt = stmt;
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(IfStmt* stmt) {
	lastStmt = stmt;
	// For each clause...
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		i->first->accept(this);
		if (visitNestedStmts) {
			visitStmt(i->second);
		}
	}

	if (visitNestedStmts && stmt->hasElseClause()) {
		visitStmt(stmt->getElseClause());
	}
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(SwitchStmt* stmt) {
	lastStmt = stmt;
	stmt->getControlExpr()->accept(this);

	// For each clause...
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		if (i->first) {
			i->first->accept(this);
		}
		if (visitNestedStmts && i->second) {
			visitStmt(i->second);
		}
	}
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(WhileLoopStmt* stmt) {
	lastStmt = stmt;
	stmt->getCondition()->accept(this);
	if (visitNestedStmts) {
		visitStmt(stmt->getBody());
	}
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(ForLoopStmt* stmt) {
	lastStmt = stmt;
	stmt->getIndVar()->accept(this);
	stmt->getStartValue()->accept(this);
	stmt->getEndCond()->accept(this);
	stmt->getStep()->accept(this);
	if (visitNestedStmts) {
		visitStmt(stmt->getBody());
	}
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(UForLoopStmt* stmt) {
	lastStmt = stmt;
	if (auto init = stmt->getInit()) {
		init->accept(this);
	}
	if (auto cond = stmt->getCond()) {
		cond->accept(this);
	}
	if (auto step = stmt->getStep()) {
		step->accept(this);
	}
	if (visitNestedStmts) {
		visitStmt(stmt->getBody());
	}
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(BreakStmt* stmt) {
	lastStmt = stmt;
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(ContinueStmt* stmt) {
	lastStmt = stmt;
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(GotoStmt* stmt) {
	lastStmt = stmt;
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getTarget());
		visitStmt(stmt->getSuccessor());
	}
}

void OrderedAllVisitor::visit(UnreachableStmt* stmt) {
	lastStmt = stmt;
	if (visitSuccessors && stmt->hasSuccessor()) {
		visitStmt(stmt->getSuccessor());
	}
}

//
// Expressions
//

void OrderedAllVisitor::visit(AddressOpExpr* expr) {
	expr->getOperand()->accept(this);
}

void OrderedAllVisitor::visit(AssignOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(ArrayIndexOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(StructIndexOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(DerefOpExpr* expr) {
	expr->getOperand()->accept(this);
}

void OrderedAllVisitor::visit(NotOpExpr* expr) {
	expr->getOperand()->accept(this);
}

void OrderedAllVisitor::visit(NegOpExpr* expr) {
	expr->getOperand()->accept(this);
}

void OrderedAllVisitor::visit(EqOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(NeqOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(LtEqOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(GtEqOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(LtOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(GtOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(AddOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(SubOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(MulOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(ModOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(DivOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(AndOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(OrOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(BitAndOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(BitOrOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(BitXorOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(BitShlOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(BitShrOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(TernaryOpExpr* expr) {
	expr->getCondition()->accept(this);
	expr->getTrueValue()->accept(this);
	expr->getFalseValue()->accept(this);
}

void OrderedAllVisitor::visit(CallExpr* expr) {
	expr->getCalledExpr()->accept(this);

	// For each argument...
	for (const auto &arg : expr->getArgs()) {
		arg->accept(this);
	}
}

void OrderedAllVisitor::visit(CommaOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
}

void OrderedAllVisitor::visit(Variable* var) {}

//
// Casts
//

void OrderedAllVisitor::visit(BitCastExpr* expr) {
	expr->getOperand()->accept(this);
}

void OrderedAllVisitor::visit(ExtCastExpr* expr) {
	expr->getOperand()->accept(this);
}

void OrderedAllVisitor::visit(TruncCastExpr* expr) {
	expr->getOperand()->accept(this);
}

void OrderedAllVisitor::visit(FPToIntCastExpr* expr) {
	expr->getOperand()->accept(this);
}

void OrderedAllVisitor::visit(IntToFPCastExpr* expr) {
	expr->getOperand()->accept(this);
}

void OrderedAllVisitor::visit(IntToPtrCastExpr* expr) {
	expr->getOperand()->accept(this);
}

void OrderedAllVisitor::visit(PtrToIntCastExpr* expr) {
	expr->getOperand()->accept(this);
}

//
// Constants
//

void OrderedAllVisitor::visit(ConstBool* constant) {}

void OrderedAllVisitor::visit(ConstFloat* constant) {}

void OrderedAllVisitor::visit(ConstInt* constant) {}

void OrderedAllVisitor::visit(ConstNullPointer* constant) {}

void OrderedAllVisitor::visit(ConstString* constant) {}

void OrderedAllVisitor::visit(ConstArray* constant) {
	if (constant->isInitialized()) {
		for (const auto &element : constant->getInitializedValue()) {
			element->accept(this);
		}
	}
}

void OrderedAllVisitor::visit(ConstStruct* constant) {
	for (const auto &member : constant->getValue()) {
		member.first->accept(this);
		member.second->accept(this);
	}
}

void OrderedAllVisitor::visit(ConstSymbol* constant) {
	constant->getValue()->accept(this);
}

//
// Types
//

void OrderedAllVisitor::visit(FloatType* type) {
	if (makeAccessedAndCheckIfAccessed(type)) {
		return;
	}
}

void OrderedAllVisitor::visit(IntType* type) {
	if (makeAccessedAndCheckIfAccessed(type)) {
		return;
	}
}

void OrderedAllVisitor::visit(PointerType* type) {
	type->getContainedType()->accept(this);
	if (makeAccessedAndCheckIfAccessed(type)) {
		return;
	}
}

void OrderedAllVisitor::visit(StringType* type) {
	if (makeAccessedAndCheckIfAccessed(type)) {
		return;
	}
}

void OrderedAllVisitor::visit(ArrayType* type) {
	if (makeAccessedAndCheckIfAccessed(type)) {
		return;
	}

	type->getContainedType()->accept(this);
}

void OrderedAllVisitor::visit(StructType* type) {
	if (makeAccessedAndCheckIfAccessed(type)) {
		return;
	}

	const StructType::ElementTypes &elements(type->getElementTypes());
	for (StructType::ElementTypes::size_type i = 0, e = elements.size(); i < e; ++i) {
		elements[i]->accept(this);
	}
}

void OrderedAllVisitor::visit(FunctionType* type) {
	if (makeAccessedAndCheckIfAccessed(type)) {
		return;
	}

	// Return type.
	type->getRetType()->accept(this);

	// Argument types.
	for (auto i = type->param_begin(), e = type->param_end(); i != e; ++i) {
		(*i)->accept(this);
	}
}

void OrderedAllVisitor::visit(VoidType* type) {
	if (makeAccessedAndCheckIfAccessed(type)) {
		return;
	}
}

void OrderedAllVisitor::visit(UnknownType* type) {
	if (makeAccessedAndCheckIfAccessed(type)) {
		return;
	}
}

/**
* @brief Visits the given statement, and possibly its successors or nested
*        statements.
*
* @param[in] stmt Statement to be visited.
* @param[in] visitSuccessors If @c true, a successor of @a stmt is also visited
*                            (and a successor of this successor, and so on).
* @param[in] visitNestedStmts If @c true, nested statements are also visited,
*                             e.g. loop, if, and switch statement's bodies.
*
* If @a stmt has already been accessed, this function does nothing. If @a stmt
* is the null pointer, it also does nothing. Before visiting @a stmt, this
* function adds it to @c accessedStmts.
*/
void OrderedAllVisitor::visitStmt(Statement* stmt, bool visitSuccessors,
		bool visitNestedStmts) {
	if (stmt && !hasItem(accessedStmts, stmt)) {
		this->visitSuccessors = visitSuccessors;
		this->visitNestedStmts = visitNestedStmts;
		accessedStmts.insert(stmt);
		stmt->accept(this);
	}
}

/**
* @brief "Restarts" the visitor so it is in the state like it was when it was
*        created.
*
* @param[in] visitSuccessors New value of this attribute.
* @param[in] visitNestedStmts New value of this attribute.
*/
void OrderedAllVisitor::restart(bool visitSuccessors, bool visitNestedStmts) {
	accessedStmts.clear();
	accessedTypes.clear();
	this->visitSuccessors = visitSuccessors;
	this->visitNestedStmts = visitNestedStmts;
}

/**
* @brief Makes the given type accessed.
*
* @return @c true if @a type has already been accessed, @c false otherwise.
*/
bool OrderedAllVisitor::makeAccessedAndCheckIfAccessed(Type* type) {
	if (hasItem(accessedTypes, type)) {
		return true;
	}
	accessedTypes.insert(type);
	return false;
}

} // namespace llvmir2hll
} // namespace retdec
