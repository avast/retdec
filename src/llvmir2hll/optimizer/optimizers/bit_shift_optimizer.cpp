/**
* @file src/llvmir2hll/optimizer/optimizers/bit_shift_optimizer.cpp
* @brief Implementation of BitShiftOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/bit_shift_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {
namespace {

/**
* @brief Check @c firstOperand of @a expr whether @c firstOperand is
*        a constant int >= 0 or an unsigned IntType.
*
* @return @c true if everything is alright, @c false otherwise.
*/
bool isFirstOpUnsignedIntTypeOrPositiveConstInt(ShPtr<BinaryOpExpr> expr) {
	ShPtr<IntType> varTypeInt(cast<IntType>(expr->getFirstOperand()->getType()));
	ShPtr<ConstInt> firstOpConstInt(cast<ConstInt>(expr->getFirstOperand()));

	if (firstOpConstInt){
		// The first operand cannot be < 0 because in this case, the
		// optimization might not be correct.
		if (firstOpConstInt->isNegative()) {
			return false;
		}
		return true;
	} else if (varTypeInt) {
		// The IntType must be unsigned.
		if (varTypeInt->isSigned()) {
			return false;
		}
		return true;
	}
	// Expression is not a ConstanInt >=0 or unsigned IntType.
	return false;
}

/**
* @brief Check @c firstOperand of @a expr whether it is of IntType.
*
* @return @c true if everything is alright, @c false otherwise.
*/
bool isFirstOpIntType(ShPtr<BinaryOpExpr> expr) {
	return isa<IntType>(expr->getFirstOperand()->getType());
}

/**
* @brief Check @c secondOperand of @a expr whether it is a constant int but
*        only >= 0.
*
* @return @c true if everything is alright, @c false otherwise.
*/
bool isSecondOpPositiveConstInt(ShPtr<BinaryOpExpr> expr) {
	ShPtr<ConstInt> secOpConstInt(cast<ConstInt>(expr->getSecondOperand()));
	// Check if the second operand is a constant.
	if (!secOpConstInt) {
		return false;
	}
	// Check if the second operand is negative.
	if (secOpConstInt->isNegative()) {
		return false;
	}
	// Everything is alright.
	return true;
}

} // anonymous namespace

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
*
* @par Preconditions
*  - @a module is non-null
*/
BitShiftOptimizer::BitShiftOptimizer(ShPtr<Module> module):
	Optimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
BitShiftOptimizer::~BitShiftOptimizer() {}

void BitShiftOptimizer::doOptimization() {
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

void BitShiftOptimizer::visit(ShPtr<BitShlOpExpr> expr) {
	// First, visit (and possibly optimize) nested expression.
	Optimizer::visit(expr);

	// Check whether we can optimize this shift.
	if (!isFirstOpIntType(expr)) {
		return;
	}
	if (!isSecondOpPositiveConstInt(expr)) {
		return;
	}

	// Replace the shift with multiplication and update the second operand.
	ShPtr<ConstInt> secOpConstInt(cast<ConstInt>(expr->getSecondOperand()));
	ShPtr<MulOpExpr> mulOpExpr(MulOpExpr::create(expr->getFirstOperand(),
		ConstInt::getTwoToPositivePower(secOpConstInt)));
	Expression::replaceExpression(expr, mulOpExpr);
}

void BitShiftOptimizer::visit(ShPtr<BitShrOpExpr> expr) {
	// First, visit (and possibly optimize) nested expression.
	Optimizer::visit(expr);

	// Check whether we can optimize this shift.
	if (!isFirstOpUnsignedIntTypeOrPositiveConstInt(expr)) {
		return;
	}
	if (!isSecondOpPositiveConstInt(expr)) {
		return;
	}

	// Replace the shift with division and update the second operand.
	ShPtr<ConstInt> secOpConstInt(cast<ConstInt>(expr->getSecondOperand()));
	ShPtr<DivOpExpr> divOpExpr(DivOpExpr::create(expr->getFirstOperand(),
		ConstInt::getTwoToPositivePower(secOpConstInt)));
	Expression::replaceExpression(expr, divOpExpr);
}

} // namespace llvmir2hll
} // namespace retdec
