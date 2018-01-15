/**
* @file src/llvmir2hll/optimizer/optimizers/bit_op_to_log_op_optimizer.cpp
* @brief Implementation of BitOpToLogOpOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/bit_op_to_log_op_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module @a Module to be optimized.
* @param[in] va @a Analysis of values.
*
* @par Preconditions
*  - @a module and @a va are non-null
*/
BitOpToLogOpOptimizer::BitOpToLogOpOptimizer(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va): FuncOptimizer(module), va(va),
		isCondition(false) {
	PRECONDITION_NON_NULL(module);
	PRECONDITION_NON_NULL(va);
}

/**
* @brief Destructs the optimizer.
*/
BitOpToLogOpOptimizer::~BitOpToLogOpOptimizer() {}

void BitOpToLogOpOptimizer::visit(ShPtr<IfStmt> stmt) {
	// First of all, visit nested and subsequent statements.
	FuncOptimizer::visit(stmt);

	// Try to optimize first if condition.
	tryOptimizeCond(stmt->getFirstIfCond());
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		// Try to optimize else if conditions.
		tryOptimizeCond(i->first);
	}
}

void BitOpToLogOpOptimizer::visit(ShPtr<SwitchStmt> stmt) {
	// First of all, visit nested and subsequent statements.
	FuncOptimizer::visit(stmt);

	// Try to optimize switch control expression.
	tryOptimizeCond(stmt->getControlExpr());
}

void BitOpToLogOpOptimizer::visit(ShPtr<WhileLoopStmt> stmt) {
	// First of all, visit nested and subsequent statements.
	FuncOptimizer::visit(stmt);

	// Try to optimize while condition.
	tryOptimizeCond(stmt->getCondition());
}

void BitOpToLogOpOptimizer::visit(ShPtr<BitAndOpExpr> expr) {
	// BitAnd which is not in condition.
	if (!isCondition) {
		return;
	}

	// We can optimize only bool expressions because we don't want to optimize
	// a = 1;
	// b = 2;
	// if (a & b) { printf("something"); }
	// because in this case, condition result is false. But if we optimize
	// condition to if (a and b), in this case condition result is true.
	ShPtr<IntType> exprFirstOpTypeInt(
		cast<IntType>(expr->getFirstOperand()->getType()));
	ShPtr<IntType> exprSecOpTypeInt(
		cast<IntType>(expr->getSecondOperand()->getType()));
	if (!exprFirstOpTypeInt || !exprFirstOpTypeInt->isBool()) {
		return;
	}
	if (!exprSecOpTypeInt || !exprSecOpTypeInt->isBool()) {
		return;
	}

	// Can be optimized?
	if (canBeBitOrBitAndOptimized(expr->getSecondOperand())) {
		// Optimize to AndOpExpr.
		ShPtr<AndOpExpr> andOpExpr(AndOpExpr::create(
			expr->getFirstOperand(),
			expr->getSecondOperand()
		));
		Expression::replaceExpression(expr, andOpExpr);
	}
}

void BitOpToLogOpOptimizer::visit(ShPtr<BitOrOpExpr> expr) {
	// BitAnd which is not in condition.
	if (!isCondition) {
		return;
	}

	// Can be optimized?
	if (canBeBitOrBitAndOptimized(expr->getSecondOperand())) {
		// Optimize to OrOpExpr.
		ShPtr<OrOpExpr> orOpExpr(OrOpExpr::create(
			expr->getFirstOperand(),
			expr->getSecondOperand()
		));
		Expression::replaceExpression(expr, orOpExpr);
	}
}

void BitOpToLogOpOptimizer::visit(ShPtr<DivOpExpr> expr) {
	// BitAnd which is not in condition.
	if (!isCondition) {
		return;
	}

	if (isPotentionalDivProblem(expr)) {
		isPotentionalProblem = true;
	}
}

void BitOpToLogOpOptimizer::visit(ShPtr<ModOpExpr> expr) {
	// BitAnd which is not in condition.
	if (!isCondition) {
		return;
	}

	if (isPotentionalModProblem(expr->getSecondOperand())) {
		isPotentionalProblem = true;
	}
}

void BitOpToLogOpOptimizer::visit(ShPtr<MulOpExpr> expr) {
	// BitAnd which is not in condition.
	if (!isCondition) {
		return;
	}

	if (isPotentionalMulProblem(expr)) {
		isPotentionalProblem = true;
	}
}

/**
* @brief Function checks if @a expr has an array access or has a call or has a
*        derefs or has a divide with zero.
*
* @param[in] expr An @a expr to check.
*
* @return @c true if @a expr can be optimized, otherwise @c false.
*/
bool BitOpToLogOpOptimizer::canBeBitOrBitAndOptimized(ShPtr<Expression> expr) {
	ShPtr<ValueData> exprData(va->getValueData(expr));

	if (exprData->hasCalls() || exprData->hasArrayAccesses() ||
			exprData->hasDerefs()) {
		return false;
	}

	// Check if exists dividing with zero in expr.
	isPotentionalProblem = false;
	expr->accept(this);
	if (isPotentionalProblem) {
		isPotentionalProblem = false;
		return false;
	}
	return true;
}

/**
* @brief Function checks if @a divOpExpr can cause problem in optimization.
*
* @param[in] divOpExpr An @a divOpExpr to check.
*
* @return @c true if @a divOpExpr can cause problems in optimizations,
*         otherwise @c false.
*/
bool BitOpToLogOpOptimizer::isPotentionalDivProblem(ShPtr<DivOpExpr> divOpExpr) {
	ShPtr<ConstInt> firstOpConstInt(cast<ConstInt>(divOpExpr->getFirstOperand()));
	ShPtr<ConstFloat> secOpConstFloat(cast<ConstFloat>(divOpExpr->getFirstOperand()));
	ShPtr<ConstInt> secOpConstInt(cast<ConstInt>(divOpExpr->getSecondOperand()));

	if (secOpConstInt) {
		if (secOpConstInt->isZero()) {
			// Second operand is 0(ConstInt).
			return true;
		}
		// Is second operand -1 and first operand IntType? IntType / -1 can cause
		// problems like -8 / -1 on 4 bits.
		if (secOpConstInt->isSigned() && secOpConstInt->isNegativeOne() &&
				isa<IntType>(divOpExpr->getFirstOperand()->getType())) {
			if (firstOpConstInt) {
				// Check if first operand is minimal signed number.
				return firstOpConstInt->isSigned() && firstOpConstInt->isMinSigned();
			} else {
				// We can find out if first operand is minimal number on bitwidth.
				// This number can be inside variable.
				return true;
			}
		}
		// No problems.
		return false;
	} else if (secOpConstFloat) {
		// Second operand is 0(ConstFloat).
		return secOpConstFloat->isZero();
	} else {
		// We can't find out if second operand is a zero. For example it can be
		// variable with zero value.
		return true;
	}
}

/**
* @brief Function checks if a @a expr is @c ConstInt or @c ConstFloat zero.
*
* @param[in] expr An @a expr to check.
*
* @return @c true if @a expr is not a ConstInt or ConstFloat or is a zero, otherwise
*         @c false.
*/
bool BitOpToLogOpOptimizer::isPotentionalModProblem(ShPtr<Expression> expr) {
	ShPtr<ConstInt> exprConstInt(cast<ConstInt>(expr));
	ShPtr<ConstFloat> exprConstFloat(cast<ConstFloat>(expr));

	if (exprConstInt) {
		// Is expr % 0(ConstInt)?
		return exprConstInt->isZero();
	} else if (exprConstFloat) {
		// Is expr 0(ConstFloat)?
		return exprConstFloat->isZero();
	} else {
		// We can't find out if second operand is a zero. For example it can be
		// variable with zero value.
		return true;
	}
}

/**
* @brief Function checks if @a mulOpExpr can cause problem in optimization.
*
* @param[in] mulOpExpr An @a mulOpExpr to check.
*
* @return @c true if @a divOpExpr can cause problems in optimizations,
*         otherwise @c false.
*/
bool BitOpToLogOpOptimizer::isPotentionalMulProblem(ShPtr<MulOpExpr> mulOpExpr) {
	ShPtr<ConstInt> firstOpConstInt(cast<ConstInt>(mulOpExpr->getFirstOperand()));
	ShPtr<ConstInt> secOpConstInt(cast<ConstInt>(mulOpExpr->getSecondOperand()));
	ShPtr<ConstFloat> firstOpConstFloat(cast<ConstFloat>(mulOpExpr->getFirstOperand()));
	ShPtr<ConstFloat> secOpConstFloat(cast<ConstFloat>(mulOpExpr->getSecondOperand()));

	// The only one problem with multiplication is when one operand is -1 and
	// the second one operand is an IntType. For example, we can have expression
	// like this -8 * -1 where -8 is on 4 bits because due to short evaluating
	// we can lost this error when optimize on logical and.
	if (isa<IntType>(mulOpExpr->getFirstOperand()->getType())) {
		// Is second operand -1(ConstInt/ConstFloat)?
		if ((secOpConstInt && secOpConstInt->isSigned() &&
					secOpConstInt->isNegativeOne()) ||
				(secOpConstFloat && secOpConstFloat->isNegativeOne())) {
			// We know that first operand is IntType. Now need to check if is
			// minimal on bitwidth.
			if (firstOpConstInt) {
				return firstOpConstInt->isSigned() && firstOpConstInt->isMinSigned();
			} else {
				// We can't find out if we have minimal number on bitwidth. We
				// can have variable on first operand.
				return true;
			}
		}
	}

	if (isa<IntType>(mulOpExpr->getSecondOperand()->getType())) {
		// Is first operand -1(ConstInt/ConstFloat)?
		if ((firstOpConstInt && firstOpConstInt->isSigned() &&
					firstOpConstInt->isNegativeOne()) ||
				(firstOpConstFloat && firstOpConstFloat->isNegativeOne())) {
			// We know that second operand is IntType. Now need to check if is
			// minimal on bitwidth.
			if (secOpConstInt) {
				return secOpConstInt->isSigned() && secOpConstInt->isMinSigned();
			} else {
				// We can't find out if we have minimal number on bitwidth. We
				// can have variable on first operand.
				return true;
			}
		}
	}
	// First operand or second operand is not an IntType.
	return false;
}

/**
* @brief This function try optimize on conditions.
*/
void BitOpToLogOpOptimizer::tryOptimizeCond(ShPtr<Expression> expr) {
	isCondition = true;
	expr->accept(this);
	isCondition = false;
}

} // namespace llvmir2hll
} // namespace retdec
