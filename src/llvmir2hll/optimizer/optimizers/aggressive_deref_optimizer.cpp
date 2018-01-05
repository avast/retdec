/**
* @file src/llvmir2hll/optimizer/optimizers/aggressive_deref_optimizer.cpp
* @brief Implementation of AggressiveDerefOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/aggressive_deref_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
*
* @par Preconditions
*  - @a module is non-null
*/
AggressiveDerefOptimizer::AggressiveDerefOptimizer(ShPtr<Module> module):
	FuncOptimizer(module), intDerefFound(false) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
AggressiveDerefOptimizer::~AggressiveDerefOptimizer() {}

/**
* @brief Tries to optimize the given statement @a stmt, composed of @a lhs and
*        @a rhs.
*/
void AggressiveDerefOptimizer::tryToOptimizeStmt(ShPtr<Statement> stmt,
		ShPtr<Expression> lhs, ShPtr<Expression> rhs) {
	intDerefFound = false;
	lhs->accept(this);
	if (!intDerefFound && rhs) {
		rhs->accept(this);
	}
	if (intDerefFound) {
		Statement::removeStatementButKeepDebugComment(stmt);
	}
}

void AggressiveDerefOptimizer::visit(ShPtr<DerefOpExpr> expr) {
	// First, visit nested expressions.
	FuncOptimizer::visit(expr);

	if (!intDerefFound) {
		ShPtr<Expression> derefdExpr(skipCasts(expr->getOperand()));
		if (isa<IntType>(derefdExpr->getType())) {
			intDerefFound = true;
		}
	}
}

void AggressiveDerefOptimizer::visit(ShPtr<AssignStmt> stmt) {
	// First, visit nested/subsequent statements.
	FuncOptimizer::visit(stmt);

	tryToOptimizeStmt(stmt, stmt->getLhs(), stmt->getRhs());
}

void AggressiveDerefOptimizer::visit(ShPtr<VarDefStmt> stmt) {
	// First, visit nested/subsequent statements.
	FuncOptimizer::visit(stmt);

	tryToOptimizeStmt(stmt, stmt->getVar(), stmt->getInitializer());
}

} // namespace llvmir2hll
} // namespace retdec
