/**
* @file src/llvmir2hll/optimizer/optimizers/no_init_var_def_optimizer.cpp
* @brief Implementation of NoInitVarDefOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/no_init_var_def_optimizer.h"
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
NoInitVarDefOptimizer::NoInitVarDefOptimizer(ShPtr<Module> module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
NoInitVarDefOptimizer::~NoInitVarDefOptimizer() {}

void NoInitVarDefOptimizer::visit(ShPtr<VarDefStmt> stmt) {
	if (stmt->hasInitializer()) {
		// There is an initializer, so keep traversing.
		visitStmt(stmt->getSuccessor());
		return;
	}

	// We have to store the statement's successor because
	// Statement::removeStatement() resets it.
	ShPtr<Statement> stmtSucc(stmt->getSuccessor());
	Statement::removeStatement(stmt);
	visitStmt(stmtSucc);
}

} // namespace llvmir2hll
} // namespace retdec
