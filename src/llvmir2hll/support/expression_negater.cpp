/**
* @file src/llvmir2hll/support/expression_negater.cpp
* @brief Implementation of ExpressionNegater.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/comma_op_expr.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/const_symbol.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expression_negater.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new expression negater.
*/
ExpressionNegater::ExpressionNegater(): Visitor() {}

/**
* @brief Negates the given expression.
*
* See the class description for more details.
*
* @par Preconditions
*  - @a expr is non-null
*/
Expression* ExpressionNegater::negate(Expression* expr) {
	PRECONDITION_NON_NULL(expr);

	ExpressionNegater* negater(new ExpressionNegater());
	return negater->negateInternal(expr);
}

/**
* @brief Negates the given expression.
*
* Since visitation functions return void, we use the private variable @c
* exprStack to manually simulate recursion. Hence, instead of returning a value
* from a visitation function, we push it onto the stack.
*
* @par Preconditions
*  - @a expr is non-null
*/
Expression* ExpressionNegater::negateInternal(Expression* expr) {
	PRECONDITION_NON_NULL(expr);

	expr->accept(this);
	return exprStack.top();
}

void ExpressionNegater::visit(Variable* var) {
	exprStack.push(NotOpExpr::create(var));
}

void ExpressionNegater::visit(AddressOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(AssignOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(ArrayIndexOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(StructIndexOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(DerefOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(NotOpExpr* expr) {
	// not not expr -> expr
	// We have to clone the operand to prevent errors later.
	exprStack.push(ucast<Expression>(expr->getOperand()->clone()));
}

void ExpressionNegater::visit(NegOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(EqOpExpr* expr) {
	exprStack.push(NeqOpExpr::create(expr->getFirstOperand(), expr->getSecondOperand()));
}

void ExpressionNegater::visit(NeqOpExpr* expr) {
	exprStack.push(EqOpExpr::create(expr->getFirstOperand(), expr->getSecondOperand()));
}

void ExpressionNegater::visit(LtEqOpExpr* expr) {
	exprStack.push(GtOpExpr::create(expr->getFirstOperand(), expr->getSecondOperand()));
}

void ExpressionNegater::visit(GtEqOpExpr* expr) {
	exprStack.push(LtOpExpr::create(expr->getFirstOperand(), expr->getSecondOperand()));
}

void ExpressionNegater::visit(LtOpExpr* expr) {
	exprStack.push(GtEqOpExpr::create(expr->getFirstOperand(), expr->getSecondOperand()));
}

void ExpressionNegater::visit(GtOpExpr* expr) {
	exprStack.push(LtEqOpExpr::create(expr->getFirstOperand(), expr->getSecondOperand()));
}

void ExpressionNegater::visit(AddOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(SubOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(MulOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(ModOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(DivOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(AndOpExpr* expr) {
	// Use De-Morgan laws.
	expr->getFirstOperand()->accept(this);
	Expression* firstOperandNegated(exprStack.top());
	exprStack.pop();

	expr->getSecondOperand()->accept(this);
	Expression* secondOperandNegated(exprStack.top());
	exprStack.pop();

	exprStack.push(OrOpExpr::create(firstOperandNegated, secondOperandNegated));
}

void ExpressionNegater::visit(OrOpExpr* expr) {
	// Use De-Morgan laws.
	expr->getFirstOperand()->accept(this);
	Expression* firstOperandNegated(exprStack.top());
	exprStack.pop();

	expr->getSecondOperand()->accept(this);
	Expression* secondOperandNegated(exprStack.top());
	exprStack.pop();

	exprStack.push(AndOpExpr::create(firstOperandNegated, secondOperandNegated));
}

void ExpressionNegater::visit(BitAndOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(BitOrOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(BitXorOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(BitShlOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(BitShrOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(TernaryOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(CallExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(CommaOpExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

// Casts.
void ExpressionNegater::visit(BitCastExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(ExtCastExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(TruncCastExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(FPToIntCastExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(IntToFPCastExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(IntToPtrCastExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}

void ExpressionNegater::visit(PtrToIntCastExpr* expr) {
	exprStack.push(NotOpExpr::create(expr));
}
// End of casts.

void ExpressionNegater::visit(ConstBool* constant) {
	// true -> false, false -> true
	exprStack.push(ConstBool::create(!constant->getValue()));
}

void ExpressionNegater::visit(ConstFloat* constant) {
	exprStack.push(NotOpExpr::create(constant));
}

void ExpressionNegater::visit(ConstInt* constant) {
	exprStack.push(NotOpExpr::create(constant));
}

void ExpressionNegater::visit(ConstNullPointer* constant) {
	exprStack.push(NotOpExpr::create(constant));
}

void ExpressionNegater::visit(ConstString* constant) {
	exprStack.push(NotOpExpr::create(constant));
}

void ExpressionNegater::visit(ConstArray* constant) {
	exprStack.push(NotOpExpr::create(constant));
}

void ExpressionNegater::visit(ConstStruct* constant) {
	exprStack.push(NotOpExpr::create(constant));
}

void ExpressionNegater::visit(ConstSymbol* constant) {
	exprStack.push(NotOpExpr::create(constant));
}

void ExpressionNegater::visit(GlobalVarDef* varDef) {
	FAIL("you cannot negate a global variable definition");
}

void ExpressionNegater::visit(Function* func) {
	FAIL("you cannot negate a function");
}

void ExpressionNegater::visit(AssignStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(VarDefStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(CallStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(ReturnStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(EmptyStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(IfStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(SwitchStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(WhileLoopStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(ForLoopStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(UForLoopStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(BreakStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(ContinueStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(GotoStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(UnreachableStmt* stmt) {
	FAIL("you cannot negate a statement");
}

void ExpressionNegater::visit(FloatType* type) {
	FAIL("you cannot negate a type");
}

void ExpressionNegater::visit(IntType* type) {
	FAIL("you cannot negate a type");
}

void ExpressionNegater::visit(PointerType* type) {
	FAIL("you cannot negate a type");
}

void ExpressionNegater::visit(StringType* type) {
	FAIL("you cannot negate a type");
}

void ExpressionNegater::visit(ArrayType* type) {
	FAIL("you cannot negate a type");
}

void ExpressionNegater::visit(StructType* type) {
	FAIL("you cannot negate a type");
}

void ExpressionNegater::visit(FunctionType* type) {
	FAIL("you cannot negate a type");
}

void ExpressionNegater::visit(VoidType* type) {
	FAIL("you cannot negate a type");
}

void ExpressionNegater::visit(UnknownType* type) {
	FAIL("you cannot negate a type");
}

} // namespace llvmir2hll
} // namespace retdec
