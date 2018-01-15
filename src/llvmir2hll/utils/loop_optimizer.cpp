/**
* @file src/llvmir2hll/utils/loop_optimizer.cpp
* @brief Implementation of the utilities for optimizers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/used_vars_visitor.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvmir2hll/utils/loop_optimizer.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Returns @c true if @a stmt is the ending statement of a loop, @c false
*        otherwise.
*
* The ending statement is of the following form:
* @code
* if cond:
*     either nothing or a variable assignment
*     break or return
* @endcode
* Furhermore, none of the statements is a goto target.
*/
bool isLoopEnd(ShPtr<Statement> stmt) {
	// It has to be an if statement.
	auto ifStmt = cast<IfStmt>(stmt);
	if (!ifStmt) {
		return false;
	}

	// There should be no else-if clauses and no else clause.
	if (ifStmt->hasElseIfClauses() || ifStmt->hasElseClause()) {
		return false;
	}

	// It cannot be a goto target.
	if (ifStmt->isGotoTarget()) {
		return false;
	}

	// The body of the if statement has to either (1) contain just a
	// break/return or (2) contain an assignment followed by a break/return.
	// TODO: Should we also check that the left-hand side of the assignment is
	//       not used anywhere in the loop?
	auto ifBodyStmt = skipEmptyStmts(ifStmt->getFirstIfBody());
	if (isa<BreakStmt>(ifBodyStmt) || isa<ReturnStmt>(ifBodyStmt)) {
		return !ifBodyStmt->isGotoTarget();
	} else if (auto assignStmt = cast<AssignStmt>(ifBodyStmt)) {
		ShPtr<Statement> endStmt(skipEmptyStmts(assignStmt->getSuccessor()));
		if (!isa<BreakStmt>(endStmt) && !isa<ReturnStmt>(endStmt)) {
			// There are some other statements.
			return false;
		}

		// Currently, the assignment has to be of the form
		//
		//    lhs = rhs
		//
		// where lhs and rhs are two variables.
		//
		// TODO: What about other cases? For example, see the `strlen` test,
		//       where there is lhs = &str[i + 1], which might cause a
		//       segmentation fault.
		return isa<Variable>(assignStmt->getRhs()) && !assignStmt->isGotoTarget();
	}

	return false;
}

/**
* @brief Returns the exit condition from the given loop end.
*
* @par Preconditions
*  - @a loopEnd is a loop's end
*/
ShPtr<Expression> getExitCondition(ShPtr<Statement> loopEnd) {
	auto ifStmt = cast<IfStmt>(loopEnd);
	ASSERT(ifStmt);
	return ifStmt->getFirstIfCond();
}

/**
* @brief Splits the given "while True" loop @a stmt into three parts.
*
* @param[in] stmt "while True" loop to be splitted.
*
* See the description of SplittedWhileTrueLoop for more details.
*
* Each statement in the loop will be cloned by calling @c clone() on it.
*
* If the loop either isn't a "while True" loop or it cannot be splitted into
* the three parts, the null pointer is returned.
*/
ShPtr<SplittedWhileTrueLoop> splitWhileTrueLoop(ShPtr<WhileLoopStmt> stmt) {
	// It has to be a "while True" loop.
	if (!isWhileTrueLoop(stmt)) {
		return {};
	}

	// Split the loop.
	auto splittedLoop = std::make_shared<SplittedWhileTrueLoop>();
	ShPtr<Expression> exitCond;
	auto currStmt = stmt->getBody();
	while (currStmt) {
		// When a statement in the loop is a goto target, we cannot split the
		// loop. Otherwise, after optimizing the loop, we might end up with
		// incorrect code.
		if (currStmt->isGotoTarget()) {
			return {};
		}

		// If there is more than one loop end, use the first one.
		if (isLoopEnd(currStmt) && !exitCond) {
			exitCond = getExitCondition(currStmt);
			splittedLoop->loopEnd = cast<IfStmt>(currStmt);
			currStmt = currStmt->getSuccessor();
			continue;
		}

		// TODO Currently, if there is a compound statement other than the
		// loop's end, we cannot make a deep clone of it. Indeed, recall that
		// the clone() member function doesn't clone successors of nested
		// statements. Consequently, we cannot optimize such loops at the
		// moment.
		if (currStmt->isCompound()) {
			return {};
		}

		if (exitCond) {
			// TODO This can be done more efficiently.
			splittedLoop->afterLoopEndStmts = Statement::mergeStatements(
				splittedLoop->afterLoopEndStmts, ucast<Statement>(currStmt->clone()));
		} else {
			// TODO This can be done more efficiently.
			splittedLoop->beforeLoopEndStmts = Statement::mergeStatements(
				splittedLoop->beforeLoopEndStmts, ucast<Statement>(currStmt->clone()));
		}

		currStmt = currStmt->getSuccessor();
	}

	// Check that the loop has been successfully splitted.
	if (!splittedLoop->loopEnd || !exitCond) {
		return {};
	}

	return splittedLoop;
}

/**
* @brief Returns information about the induction variable in the given "while
*        true" loop.
*
* If the loop either isn't a "while True" loop or complete information cannot
* be obtained, the null pointer is returned.
*/
ShPtr<IndVarInfo> getIndVarInfo(ShPtr<WhileLoopStmt> stmt) {
	// It has to be a "while True" loop.
	if (!isWhileTrueLoop(stmt)) {
		return {};
	}

	// First, we assume that the update statement is the first statement after
	// the stmts's end. We then get the variable which is modified by this
	// statement---this should be the induction variable. Finally, once we know
	// the induction variable, we get its initializer.

	// Obtain the update statement of the induction variable. During this,
	// get also the exit condition.
	ShPtr<Statement> updateStmt;
	ShPtr<Expression> exitCond;
	auto currStmt = stmt->getBody();
	while (currStmt) {
		if (isLoopEnd(currStmt)) {
			updateStmt = skipEmptyStmts(currStmt->getSuccessor());
			exitCond = getExitCondition(currStmt);
			break;
		}

		currStmt = currStmt->getSuccessor();
	}
	// Check that both the update statement and the exit condition exist, and
	// that the update statement is a single statement (empty statements can
	// be skipped).
	if (!updateStmt || !exitCond || skipEmptyStmts(updateStmt->getSuccessor())) {
		// There is either no update statement or no exit condition.
		return {};
	}

	// Obtain the induction variable.
	auto modifiedVarsInUpdateStmt = UsedVarsVisitor::getUsedVars(
		updateStmt, false)->getWrittenVars();
	auto indVarIter = modifiedVarsInUpdateStmt.begin();
	if (indVarIter == modifiedVarsInUpdateStmt.end()) {
		return {};
	}
	auto indVar = *indVarIter;

	// Obtain the initializer of the induction variable.
	ShPtr<Statement> initStmt;
	auto pred = ucast<Statement>(stmt);
	while (pred) {
		pred = pred->getUniquePredecessor();

		// The initializer has to be either a VarDefStmt or an AssignStmt (or
		// an EmptyStmt, in which case we ignore it end keep searching).
		if (isa<EmptyStmt>(pred)) {
			continue;
		} else if (!isa<VarDefStmt>(pred) && !isa<AssignStmt>(pred)) {
			// Unexpected statement.
			return {};
		}

		auto modifiedVarsInStmt = UsedVarsVisitor::getUsedVars(
			pred, false)->getWrittenVars();
		if (hasItem(modifiedVarsInStmt, indVar)) {
			initStmt = pred;
			break;
		}
	}
	if (!initStmt) {
		// There is no initialization statement.
		return {};
	}

	// TODO Check that indVar is used only on "safe" places, meaning that the
	//      loop can be optimized into a for loop.

	return std::make_shared<IndVarInfo>(initStmt, indVar, exitCond, updateStmt);
}

} // namespace llvmir2hll
} // namespace retdec
