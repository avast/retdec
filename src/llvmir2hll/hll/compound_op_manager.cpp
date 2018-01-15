/**
* @file src/llvmir2hll/hll/compound_op_manager.cpp
* @brief Implementation of CompoundOpManager.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/compound_op_manager.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Checks if @a expr is a supported left-hand side of AssignStmt.
*
* @param[in] expr An expression to be checked.
*
* @return @c true if @a expr is supported left-hand side of AssignStmt,
*         otherwise @c false.
*/
bool isSupportedLhs(ShPtr<Expression> expr) {
	return isa<Variable>(expr) || isa<ArrayIndexOpExpr>(expr) ||
		isa<StructIndexOpExpr>(expr);
}

}

/**
* @brief A constructor of a unary compound operator.
*
* @par Preconditions
*   - @a op is non-empty
*/
CompoundOpManager::CompoundOp::CompoundOp(std::string op):
	op(op) {
		PRECONDITION(!op.empty(), "the operator cannot be empty");
	}

/**
* @brief A constructor of a binary compound operator.
*
* @par Preconditions
*   - @a op is non-empty
*   - @a operand is non-null
*/
CompoundOpManager::CompoundOp::CompoundOp(std::string op,
		ShPtr<Expression> operand):
	op(op), operand(operand) {
		PRECONDITION(!op.empty(), "the operator cannot be empty");
		PRECONDITION_NON_NULL(operand);
	}

/**
* @brief Returns the operator.
*/
const std::string &CompoundOpManager::CompoundOp::getOperator() const {
	return op;
}

/**
* @brief Returns the operand of a binary operator.
*
* @par Preconditions
*   - the operator is binary
*/
ShPtr<Expression> CompoundOpManager::CompoundOp::getOperand() const {
	PRECONDITION(operand, "trying to get an operand of a unary operator");
	return operand;
}

/**
* @brief Returns @c true if the operator is unary, @c false otherwise.
*
* This function returns @c false if and only if the operator is binary.
*
* @see isBinaryOperator()
*/
bool CompoundOpManager::CompoundOp::isUnaryOperator() const {
	return !operand;
}

/**
* @brief Returns @c true if the operator is binary, @c false otherwise.
*
* This function returns @c true if and only if the operator is unary.
*
* @see isUnaryOperator()
*/
bool CompoundOpManager::CompoundOp::isBinaryOperator() const {
	return operand != nullptr;
}

/**
* @brief Constructs a new base class for compound operator managers.
*/
CompoundOpManager::CompoundOpManager():
	compoundOp("?") {}

/**
* @brief Destructs the compound operator manager.
*/
CompoundOpManager::~CompoundOpManager() {}

/**
* @brief Tries to optimize @a stmt to a compound operator.
*
* @param[in] stmt Statement to optimize.
*
* @return The compound operator if @a stmt can be optimized, or normal assign
*         operator if it can't be optimized. Also returns the right operand.
*/
CompoundOpManager::CompoundOp CompoundOpManager::tryOptimizeToCompoundOp(
		ShPtr<AssignStmt> stmt) {
	return tryOptimizeToCompoundOp(stmt->getLhs(), stmt->getRhs());
}

/**
* @brief Tries to optimize @a expr to a compound operator.
*
* @param[in] expr Expression to optimize.
*
* @return The compound operator if @a expr can be optimized, or normal assign
*         operator if it can't be optimized. Also returns the right operand.
*/
CompoundOpManager::CompoundOp CompoundOpManager::tryOptimizeToCompoundOp(
		ShPtr<AssignOpExpr> expr) {
	return tryOptimizeToCompoundOp(
		expr->getFirstOperand(),
		expr->getSecondOperand()
	);
}

/**
* @brief Tries to optimize assignment <tt>lhs = rhs</tt> to a compound
*        operator.
*
* @param[in] lhs Left-hand side of the assignment.
* @param[in] rhs Right-hand side of the assignment.
*
* @return The compound operator if the assignment can be optimized, or normal
*         assign operator if it can't be optimized. Also returns the right
*         operand.
*/
CompoundOpManager::CompoundOp CompoundOpManager::tryOptimizeToCompoundOp(
		ShPtr<Expression> lhs, ShPtr<Expression> rhs) {
	// Set to default result.
	createResultingBinaryCompoundOp("=", rhs);

	if (!isSupportedLhs(lhs)) {
		return compoundOp;
	}
	lhsOfAssignStmt = lhs;

	// Analyze the right-hand side of AssignStmt.
	rhs->accept(this);

	return compoundOp;
}

void CompoundOpManager::visit(ShPtr<AddOpExpr> expr) {
	tryOptimizeWhenOneOfOperandsEqWithLhsOfAssignStmt(expr);
}

void CompoundOpManager::visit(ShPtr<SubOpExpr> expr) {
	tryOptimizeWhenLeftOperandEqWithLhsOfAssignStmt(expr);
}

void CompoundOpManager::visit(ShPtr<MulOpExpr> expr) {
	tryOptimizeWhenOneOfOperandsEqWithLhsOfAssignStmt(expr);
}

void CompoundOpManager::visit(ShPtr<DivOpExpr> expr) {
	tryOptimizeWhenLeftOperandEqWithLhsOfAssignStmt(expr);
}

void CompoundOpManager::visit(ShPtr<ModOpExpr> expr) {
	tryOptimizeWhenLeftOperandEqWithLhsOfAssignStmt(expr);
}

void CompoundOpManager::visit(ShPtr<BitShlOpExpr> expr) {
	tryOptimizeWhenLeftOperandEqWithLhsOfAssignStmt(expr);
}

void CompoundOpManager::visit(ShPtr<BitShrOpExpr> expr) {
	tryOptimizeWhenLeftOperandEqWithLhsOfAssignStmt(expr);
}

void CompoundOpManager::visit(ShPtr<BitAndOpExpr> expr) {
	tryOptimizeWhenOneOfOperandsEqWithLhsOfAssignStmt(expr);
}

void CompoundOpManager::visit(ShPtr<BitOrOpExpr> expr) {
	tryOptimizeWhenOneOfOperandsEqWithLhsOfAssignStmt(expr);
}

void CompoundOpManager::visit(ShPtr<BitXorOpExpr> expr) {
	tryOptimizeWhenOneOfOperandsEqWithLhsOfAssignStmt(expr);
}

/**
* @brief Sets the resulting operator to the default one which is the same like
*        nothing is to be optimized.
*
* In subclasses you can override this method that @a expr is used to recognize
* type of compound operator and @a operand is used as right operand of operator.
*
* @param[in] expr Type of operator.
* @param[in] operand The right operand of result operator.
*/
void CompoundOpManager::optimizeToCompoundOp(ShPtr<AddOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("=", expr);
}

/// @see optimizeToCompoundOp
void CompoundOpManager::optimizeToCompoundOp(ShPtr<SubOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("=", expr);
}

/// @see optimizeToCompoundOp
void CompoundOpManager::optimizeToCompoundOp(ShPtr<MulOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("=", expr);
}

/// @see optimizeToCompoundOp
void CompoundOpManager::optimizeToCompoundOp(ShPtr<DivOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("=", expr);
}

/// @see optimizeToCompoundOp
void CompoundOpManager::optimizeToCompoundOp(ShPtr<ModOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("=", expr);
}

/// @see optimizeToCompoundOp
void CompoundOpManager::optimizeToCompoundOp(ShPtr<BitShlOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("=", expr);
}

/// @see optimizeToCompoundOp
void CompoundOpManager::optimizeToCompoundOp(ShPtr<BitShrOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("=", expr);
}

/// @see optimizeToCompoundOp
void CompoundOpManager::optimizeToCompoundOp(ShPtr<BitAndOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("=", expr);
}

/// @see optimizeToCompoundOp
void CompoundOpManager::optimizeToCompoundOp(ShPtr<BitOrOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("=", expr);
}

/// @see optimizeToCompoundOp
void CompoundOpManager::optimizeToCompoundOp(ShPtr<BitXorOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("=", expr);
}

/**
* @brief Creates the resulting unary compound operator and saves it into @c
*        compoundOp.
*
* @param[in] op Result operator.
*/
void CompoundOpManager::createResultingUnaryCompoundOp(const std::string &op) {
	compoundOp = CompoundOp(op);
}

/**
* @brief Creates the resulting binary compound operator and saves it into @c
*        compoundOp.
*
* @param[in] op Result operator.
* @param[in] operand Result right operand for @a op.
*/
void CompoundOpManager::createResultingBinaryCompoundOp(const std::string &op,
		ShPtr<Expression> operand) {
	compoundOp = CompoundOp(op, operand);
}

/**
* @brief Checks if one of the operands is equal with the saved left-hand side of
*        AssignStmt.
*
* @param[in] expr An expression to be checked.
*
* @return The next one operand if one of operands are equal with saved
*         left-hand side of AssignStmt, otherwise the null pointer.
*/
ShPtr<Expression> CompoundOpManager::getNextOpIfSecondOneIsEqWithLhsOfAssign(
		ShPtr<BinaryOpExpr> expr) {
	if (lhsOfAssignStmt->isEqualTo(expr->getFirstOperand())) {
		return expr->getSecondOperand();
	} else if (lhsOfAssignStmt->isEqualTo(expr->getSecondOperand())) {
		return expr->getFirstOperand();
	} else {
		return ShPtr<Expression>();
	}
}

/**
* @brief Tries to optimize @a expr to compound operator when one of operands is
*        equal with left-hand side of AssignStmt.
*
* @tparam expr An expression to optimize.
*/
template<typename ToOptimizeExpr>
void CompoundOpManager::tryOptimizeWhenOneOfOperandsEqWithLhsOfAssignStmt(
		ShPtr<ToOptimizeExpr> expr) {
	ShPtr<Expression> operand(getNextOpIfSecondOneIsEqWithLhsOfAssign(expr));
	if (operand) {
		optimizeToCompoundOp(expr, operand);
	}
}

/**
* @brief Tries to optimize @a expr to compound operator when left operand is
*        equal with left-hand side of AssignStmt.
*
* @tparam expr An expression to optimize.
*/
template<typename ToOptimizeExpr>
void CompoundOpManager::tryOptimizeWhenLeftOperandEqWithLhsOfAssignStmt(
		ShPtr<ToOptimizeExpr> expr) {
	if (lhsOfAssignStmt->isEqualTo(expr->getFirstOperand())) {
		optimizeToCompoundOp(expr, expr->getSecondOperand());
	}
}

} // namespace llvmir2hll
} // namespace retdec
