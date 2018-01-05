/**
* @file src/llvmir2hll/optimizer/optimizers/void_return_optimizer.cpp
* @brief Implementation of VoidReturnOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/void_return_optimizer.h"
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
VoidReturnOptimizer::VoidReturnOptimizer(ShPtr<Module> module):
	FuncOptimizer(module), nestingLevel(0) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
VoidReturnOptimizer::~VoidReturnOptimizer() {}

void VoidReturnOptimizer::visit(ShPtr<ReturnStmt> stmt) {
	// The return statement can be eliminated only if
	//  (1) it doesn't return a value, i.e. it is a void return;
	//  (2) it is not the only statement in the function;
	//  (3) it is not nested, i.e. it is in the entry block of the function.
	// Notice that the third condition is only a sufficient one, not a
	// necessary one. To obtain a necessary condition, we would need to make
	// this optimization more complex.

	// Ignore returns with a value.
	if (stmt->getRetVal()) {
		return;
	}

	// Ignore returns which are the only statement in the function.
	if (!stmt->hasPredecessors()) {
		return;
	}

	// Ignore returns in nested blocks.
	if (nestingLevel > 0) {
		return;
	}

	// The statement can be optimized.
	Statement::removeStatement(stmt);
}

//
// The following functions are overridden for these two reasons:
//
// (1) We need to increase nestingLevel when a new block is accessed. This is
// because return statements can be optimized only from the first block in a
// function. To this end, we keep the nestingLevel counter.
//
// (2) To make the optimization more effective: expressions do not need to be
// traversed at all, so do not traverse them.
//
// TODO: Do this also with other optimizations?
//
void VoidReturnOptimizer::visit(ShPtr<AssignStmt> stmt) {
	visitStmt(stmt->getSuccessor());
}

void VoidReturnOptimizer::visit(ShPtr<VarDefStmt> stmt) {
	visitStmt(stmt->getSuccessor());
}

void VoidReturnOptimizer::visit(ShPtr<CallStmt> stmt) {
	visitStmt(stmt->getSuccessor());
}

void VoidReturnOptimizer::visit(ShPtr<IfStmt> stmt) {
	// For each clause...
	++nestingLevel;
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		visitStmt(i->second);
	}
	visitStmt(stmt->getElseClause());
	--nestingLevel;

	visitStmt(stmt->getSuccessor());
}

void VoidReturnOptimizer::visit(ShPtr<SwitchStmt> stmt) {
	// For each clause...
	++nestingLevel;
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		visitStmt(i->second);
	}
	--nestingLevel;

	visitStmt(stmt->getSuccessor());
}

void VoidReturnOptimizer::visit(ShPtr<WhileLoopStmt> stmt) {
	++nestingLevel;
	visitStmt(stmt->getBody());
	--nestingLevel;

	visitStmt(stmt->getSuccessor());
}

void VoidReturnOptimizer::visit(ShPtr<ForLoopStmt> stmt) {
	++nestingLevel;
	visitStmt(stmt->getBody());
	--nestingLevel;

	visitStmt(stmt->getSuccessor());
}

void VoidReturnOptimizer::visit(ShPtr<UForLoopStmt> stmt) {
	++nestingLevel;
	visitStmt(stmt->getBody());
	--nestingLevel;

	visitStmt(stmt->getSuccessor());
}

} // namespace llvmir2hll
} // namespace retdec
