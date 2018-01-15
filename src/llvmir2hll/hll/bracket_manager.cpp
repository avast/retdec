/**
* @file src/llvmir2hll/hll/bracket_manager.cpp
* @brief Implementation of BracketManager.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/bracket_manager.h"
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
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
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
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/utils/container.h"

using retdec::utils::mapGetValueOrDefault;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new base class for brackets managers.
*
* @param[in] module The module to be analyzed.
*/
BracketManager::BracketManager(ShPtr<Module> module) {
	this->module = module;
}

/**
* @brief Destructs the brackets manager.
*/
BracketManager::~BracketManager() {}

/**
* @brief Iterate through the module and visit all functions and all global
*        variables. Starts brackets analyse.
*/
void BracketManager::init() {
	// Visit the initializer of all global variables.
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		if (ShPtr<Expression> init = (*i)->getInitializer()) {
			init->accept(this);
		}
	}

	// Visit all functions.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		(*i)->accept(this);
	}
}

/**
* @brief Function that decides whether the brackets are needed. This function
*        is needed to be called from HLL writers.
*
* @param[in] expr Input expression.
*
* @return @c true if brackets are needed, @c false otherwise.
*/
bool BracketManager::areBracketsNeeded(ShPtr<Expression> expr) {
	// Try to find an expression.
	return mapGetValueOrDefault(bracketsAreNeededMap, expr, true);
}

/**
* @brief Function find out, if brackets are needed for input @a expression.
*
* @param[in] expr Input @a expression.
* @param currentOperator enum @c Operators.
*/
void BracketManager::areBracketsNeededForExpr(ShPtr<Expression> expr,
		Operators currentOperator) {
	if (prevOperatorsStack.empty()) {
		bracketsAreNeededMap[expr] = false;
	} else {
		bracketsAreNeededMap[expr] = areBracketsNeededPrecTable(currentOperator);
	}
}

/**
* @brief This function enter to precedence table with function @c checkPrecTable(...)
*        and accordance it decide to if brackets are needed or not.
*
* @param[in] currentOperator enum @c Operators.
*
* @return @c true if brackets are needed, @c false otherwise.
*/
bool BracketManager::areBracketsNeededPrecTable(Operators currentOperator) {
	// Get previous operator from stack of previous operators.
	PrevOperators prevOperator = getPrevOperator();
	// Check precedence table.
	ItemOfPrecTable item = checkPrecTable(currentOperator, prevOperator.prevOperator);

	if (item.bracketsNeeded) {
		// Brackets are needed. Operators haven't got same priority.
		return true;
	} else if (item.association == N) {
		// Brackets are not needed. Operators haven't got same priority.
		return false;
	} else { // Operators with same priority. Need to decide by association.
		if ((item.association == L) && (prevOperator.treeDirection == Direction::LEFT)) {
			return false;
		} else if ((item.association == R) && (prevOperator.treeDirection == Direction::RIGHT)){
			return false;
		} else {
			return true;
		}
	}
}

/**
* @brief Top element from @c prevOperatorsStack.
*
* @return @c PrevOperators which is a structure with previous operator and
*         direction of tree traversal.
*/
BracketManager::PrevOperators BracketManager::getPrevOperator() {
	return prevOperatorsStack.top();
}

/**
* @brief Create a structure which contains previous operator and direction of
*        tree traversal and add it on stack of @c prevOperatorsStack. If operator
*        is not supported, operator is not pushed on stack.
*
* @param[in] currentOperator enum @c Operators. It is used for creating item
*            which is pushed as @a previous operator on stack.
* @param[in] direction enum @c Direction. Enumeration for direction tree traversal.
*/
void BracketManager::addOperatorOnStackIfSupported(Operators currentOperator,
		Direction direction) {
	if (isOperatorSupported(currentOperator)) {
		PrevOperators prevOperator = { currentOperator, direction };
		prevOperatorsStack.push(prevOperator);
	}
}

/**
* @brief Pop element from @a prevOperatorsStack. If operator is not supported,
*        operator is not popped from stack.
*
* @param[in] currentOperator enum @c Operators. Operator is used for check whether
*            is supported.
*/
void BracketManager::removeOperatorFromStackIfSupported(
		Operators currentOperator) {
	if (isOperatorSupported(currentOperator)) {
		prevOperatorsStack.pop();
	}
}

/**
* @brief Function visit operand of @c UnaryOpExpr. Function also add operator
*        on stack of previous operators and after visit operand remove this operator
*        from stack.
*
* @param[in] expr Current @a expression.
* @param[in] currentOperator enum @c Operators. Current operator.
*/
void BracketManager::treeTraversalForUnaryOpWithStackOperations(
		ShPtr<UnaryOpExpr> expr, Operators currentOperator) {
	addOperatorOnStackIfSupported(currentOperator, Direction::CENTER);
	expr->getOperand()->accept(this);
	removeOperatorFromStackIfSupported(currentOperator);
}

/**
* @brief Function visit operands of @c BinaryOpExpr. Function also add operator
*        on stack of previous operators and after visit operand remove this operator
*        from stack.
*
* @param[in] expr Current @a expression.
* @param[in] currentOperator enum @c Operators.
*/
void BracketManager::treeTraversalForBinaryOpWithStackOperations(
		ShPtr<BinaryOpExpr> expr, Operators currentOperator) {
	addOperatorOnStackIfSupported(currentOperator, Direction::LEFT);
	expr->getFirstOperand()->accept(this);
	removeOperatorFromStackIfSupported(currentOperator);

	addOperatorOnStackIfSupported(currentOperator, Direction::RIGHT);
	expr->getSecondOperand()->accept(this);
	removeOperatorFromStackIfSupported(currentOperator);
}

/**
* @brief Function visit operands of @c TernaryOpExpr. Function also add operator
*        on stack of previous operators and after visit operand remove this operator
*        from stack.
*
* @param[in] expr Current @a expression.
* @param[in] currentOperator enum @c Operators.
*/
void BracketManager::treeTraversalForTernaryOpWithStackOperations(
		ShPtr<TernaryOpExpr> expr, Operators currentOperator) {
	addOperatorOnStackIfSupported(currentOperator, Direction::RIGHT);
	expr->getTrueValue()->accept(this);
	removeOperatorFromStackIfSupported(currentOperator);

	addOperatorOnStackIfSupported(currentOperator, Direction::RIGHT);
	expr->getCondition()->accept(this);
	removeOperatorFromStackIfSupported(currentOperator);

	addOperatorOnStackIfSupported(currentOperator, Direction::RIGHT);
	expr->getFalseValue()->accept(this);
	removeOperatorFromStackIfSupported(currentOperator);
}

/**
* @brief Function visit operand of @c CastExpr. Function also add operator on
*        stack of previous operators and after visit operand remove this operator
*        from stack.
*
* @param[in] expr Current @a expression.
* @param[in] currentOperator enum @c Operators.
*/
void BracketManager::treeTraversalForCastWithStackOperations(
		ShPtr<CastExpr> expr, Operators currentOperator) {
	addOperatorOnStackIfSupported(currentOperator, Direction::CENTER);
	expr->getOperand()->accept(this);
	removeOperatorFromStackIfSupported(currentOperator);
}

/**
* @brief Function visit @a arguments of @c CallExpr. Function also add operator on
*        stack of previous operators and after visit operand remove this operator
*        from stack.
*
* @param[in] expr Current @a expression.
* @param[in] currentOperator enum @c Operators.
*/
void BracketManager::treeTraversalForCallWithStackOperations(
		ShPtr<CallExpr> expr, Operators currentOperator) {
	// Called expression.
	addOperatorOnStackIfSupported(currentOperator, Direction::LEFT);
	expr->getCalledExpr()->accept(this);
	removeOperatorFromStackIfSupported(currentOperator);

	// Arguments.
	for (const auto &arg : expr->getArgs()) {
		addOperatorOnStackIfSupported(currentOperator, Direction::LEFT);
		arg->accept(this);
		removeOperatorFromStackIfSupported(currentOperator);
	}
}

void BracketManager::visit(ShPtr<AddressOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::ADDRESS);
	treeTraversalForUnaryOpWithStackOperations(expr, Operators::ADDRESS);
}

void BracketManager::visit(ShPtr<AssignOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::ASSIGN);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::ASSIGN);
}

void BracketManager::visit(ShPtr<ArrayIndexOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::ARRAY);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::ARRAY);
}

void BracketManager::visit(ShPtr<StructIndexOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::STRUCT);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::STRUCT);
}

void BracketManager::visit(ShPtr<DerefOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::DEREF);
	treeTraversalForUnaryOpWithStackOperations(expr, Operators::DEREF);
}

void BracketManager::visit(ShPtr<NotOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::NOT);
	treeTraversalForUnaryOpWithStackOperations(expr, Operators::NOT);
}

void BracketManager::visit(ShPtr<NegOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::NEG);
	treeTraversalForUnaryOpWithStackOperations(expr, Operators::NEG);
}

void BracketManager::visit(ShPtr<EqOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::EQ);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::EQ);
}

void BracketManager::visit(ShPtr<NeqOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::NEQ);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::NEQ);
}

void BracketManager::visit(ShPtr<LtEqOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::LTEQ);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::LTEQ);
}

void BracketManager::visit(ShPtr<GtEqOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::GTEQ);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::GTEQ);
}

void BracketManager::visit(ShPtr<LtOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::LT);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::LT);
}

void BracketManager::visit(ShPtr<GtOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::GT);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::GT);
}

void BracketManager::visit(ShPtr<AddOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::ADD);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::ADD);
}

void BracketManager::visit(ShPtr<SubOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::SUB);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::SUB);
}

void BracketManager::visit(ShPtr<MulOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::MUL);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::MUL);
}

void BracketManager::visit(ShPtr<ModOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::MOD);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::MOD);
}

void BracketManager::visit(ShPtr<DivOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::DIV);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::DIV);
}

void BracketManager::visit(ShPtr<AndOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::AND);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::AND);
}

void BracketManager::visit(ShPtr<OrOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::OR);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::OR);
}

void BracketManager::visit(ShPtr<BitAndOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::BITAND);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::BITAND);
}

void BracketManager::visit(ShPtr<BitOrOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::BITOR);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::BITOR);
}

void BracketManager::visit(ShPtr<BitXorOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::BITXOR);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::BITXOR);
}

void BracketManager::visit(ShPtr<BitShlOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::BITSHL);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::BITSHL);
}

void BracketManager::visit(ShPtr<BitShrOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::BITSHR);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::BITSHR);
}

void BracketManager::visit(ShPtr<TernaryOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::TERNARY);
	treeTraversalForTernaryOpWithStackOperations(expr, Operators::TERNARY);
}

void BracketManager::visit(ShPtr<CallExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::CALL);
	treeTraversalForCallWithStackOperations(expr, Operators::CALL);
}

void BracketManager::visit(ShPtr<CommaOpExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::COMMA);
	treeTraversalForBinaryOpWithStackOperations(expr, Operators::COMMA);
}

void BracketManager::visit(ShPtr<BitCastExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::CAST);
	treeTraversalForCastWithStackOperations(expr, Operators::CAST);
}

void BracketManager::visit(ShPtr<ExtCastExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::CAST);
	treeTraversalForCastWithStackOperations(expr, Operators::CAST);
}

void BracketManager::visit(ShPtr<TruncCastExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::CAST);
	treeTraversalForCastWithStackOperations(expr, Operators::CAST);
}

void BracketManager::visit(ShPtr<FPToIntCastExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::CAST);
	treeTraversalForCastWithStackOperations(expr, Operators::CAST);
}

void BracketManager::visit(ShPtr<IntToFPCastExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::CAST);
	treeTraversalForCastWithStackOperations(expr, Operators::CAST);
}

void BracketManager::visit(ShPtr<IntToPtrCastExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::CAST);
	treeTraversalForCastWithStackOperations(expr, Operators::CAST);
}

void BracketManager::visit(ShPtr<PtrToIntCastExpr> expr) {
	areBracketsNeededForExpr(expr, Operators::CAST);
	treeTraversalForCastWithStackOperations(expr, Operators::CAST);
}

void BracketManager::visit(ShPtr<ConstBool> constant) {
	// Brackets are never needed around constants.
	bracketsAreNeededMap[constant] = false;
}

void BracketManager::visit(ShPtr<ConstFloat> constant) {
	// Brackets are never needed around constants.
	bracketsAreNeededMap[constant] = false;
}

void BracketManager::visit(ShPtr<ConstInt> constant) {
	// Brackets are never needed around constants.
	bracketsAreNeededMap[constant] = false;
}

void BracketManager::visit(ShPtr<ConstNullPointer> constant) {
	// Brackets are never needed around constants.
	bracketsAreNeededMap[constant] = false;
}

void BracketManager::visit(ShPtr<ConstString> constant) {
	// Brackets are never needed around constants.
	bracketsAreNeededMap[constant] = false;
}

void BracketManager::visit(ShPtr<ConstArray> constant) {
	// Brackets are never needed around constants.
	bracketsAreNeededMap[constant] = false;

	// We need to visit elements which are possible present in the constant.
	OrderedAllVisitor::visit(constant);
}

void BracketManager::visit(ShPtr<ConstStruct> constant) {
	// Brackets are never needed around constants.
	bracketsAreNeededMap[constant] = false;

	// We need to visit elements which are possible present in the constant.
	OrderedAllVisitor::visit(constant);
}

void BracketManager::visit(ShPtr<ConstSymbol> constant) {
	// Brackets are never needed around constants.
	bracketsAreNeededMap[constant] = false;
}

void BracketManager::visit(ShPtr<Variable> var) {
	// Brackets are never needed around variables.
	bracketsAreNeededMap[var] = false;
}

} // namespace llvmir2hll
} // namespace retdec
