/**
* @file src/llvmir2hll/optimizer/optimizers/self_assign_optimizer.cpp
* @brief Implementation of SelfAssignOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/optimizer/optimizers/self_assign_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

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
SelfAssignOptimizer::SelfAssignOptimizer(ShPtr<Module> module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
SelfAssignOptimizer::~SelfAssignOptimizer() {}

void SelfAssignOptimizer::visit(ShPtr<AssignStmt> stmt) {
	// First, visit the successor so that when there is a list of self
	// assignments, they are all properly removed.
	visitStmt(stmt->getSuccessor());

	if (stmt->getLhs()->isEqualTo(stmt->getRhs())) {
		Statement::removeStatementButKeepDebugComment(stmt);
	}
}

} // namespace llvmir2hll
} // namespace retdec
