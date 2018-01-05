/**
* @file src/llvmir2hll/optimizer/optimizers/remove_useless_casts_optimizer.cpp
* @brief Implementation of RemoveUselessCastsOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/remove_useless_casts_optimizer.h"
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
RemoveUselessCastsOptimizer::RemoveUselessCastsOptimizer(ShPtr<Module> module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
RemoveUselessCastsOptimizer::~RemoveUselessCastsOptimizer() {}

void RemoveUselessCastsOptimizer::visit(ShPtr<AssignStmt> stmt) {
	if (tryOptimizationCase1(stmt)) {
		return;
	}
	// Here can come other optimizations.

	// Visit subsequent statements.
	FuncOptimizer::visit(stmt);
}

/**
* @brief Tries to optimize the given statement according case (1) in the class
*        description.
*
* @return @c true if the optimization was performed, @c false otherwise.
*/
bool RemoveUselessCastsOptimizer::tryOptimizationCase1(ShPtr<AssignStmt> stmt) {
	ShPtr<Variable> lhsVar(cast<Variable>(stmt->getLhs()));
	if (!lhsVar) {
		// The statement is not of the form `a = ...`.
		return false;
	}

	ShPtr<CastExpr> rhsCast(cast<CastExpr>(stmt->getRhs()));
	if (!rhsCast) {
		// The statement is not of the form `a = cast<>(...)`.
		return false;
	}

	if (lhsVar->getType() != rhsCast->getType()) {
		// The types of `a` and the cast differ.
		return false;
	}

	ShPtr<Variable> rhsCastVar(cast<Variable>(rhsCast->getOperand()));
	if (!rhsCastVar) {
		// The statement is not of the form `a = cast<>(b)`.
		return false;
	}

	if (lhsVar->getType() != rhsCastVar->getType()) {
		// The types of `a` and `b` differ.
		return false;
	}

	// Perform the optimization.
	stmt->setRhs(rhsCast->getOperand());

	return true;
}

} // namespace llvmir2hll
} // namespace retdec
