/**
* @file src/llvmir2hll/optimizer/optimizers/empty_stmt_optimizer.cpp
* @brief Implementation of EmptyStmtOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/empty_stmt_optimizer.h"
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
EmptyStmtOptimizer::EmptyStmtOptimizer(ShPtr<Module> module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
EmptyStmtOptimizer::~EmptyStmtOptimizer() {}

void EmptyStmtOptimizer::visit(ShPtr<EmptyStmt> stmt) {
	// We have to store the statement's successor because
	// Statement::removeStatement() resets it.
	ShPtr<Statement> stmtSucc(stmt->getSuccessor());
	Statement::removeStatement(stmt);
	visitStmt(stmtSucc);
}

} // namespace llvmir2hll
} // namespace retdec
