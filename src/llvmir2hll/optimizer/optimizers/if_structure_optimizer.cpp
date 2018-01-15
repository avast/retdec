/**
* @file src/llvmir2hll/optimizer/optimizers/if_structure_optimizer.cpp
* @brief Implementation of IfStructureOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/optimizer/optimizers/if_structure_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expression_negater.h"
#include "retdec/llvmir2hll/support/statements_counter.h"
#include "retdec/llvmir2hll/utils/ir.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Does @a stmt contain an else clause or some else-if clauses?
*/
bool hasElseIfOrElseClauses(ShPtr<IfStmt> stmt) {
	return stmt->hasElseClause() || stmt->hasElseIfClauses();
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
IfStructureOptimizer::IfStructureOptimizer(ShPtr<Module> module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
IfStructureOptimizer::~IfStructureOptimizer() {}

void IfStructureOptimizer::visit(ShPtr<IfStmt> stmt) {
	// First of all, visit nested and subsequent statements.
	FuncOptimizer::visit(stmt);

	// Try several optimizations. The numbers correspond the numbers in the
	// class description.
	tryOptimization1(stmt);
	tryOptimization2(stmt);
	tryOptimization3(stmt);
	tryOptimization4(stmt);
	tryOptimization5(stmt);
}

/**
* @brief Tries the optimization (1) from the class description on @a stmt.
*
* @return @c true if @a stmt has been optimized, @c false otherwise.
*/
bool IfStructureOptimizer::tryOptimization1(ShPtr<IfStmt> stmt) {
	// We are going to optimize a piece of code of the following form
	//
	// if cond:
	//    return/unreachable statement
	// else:
	//    statements
	//
	// to
	//
	// if cond:
	//    return/unreachable statement
	// statements
	//
	// To this end, we first check that stmt is of the above form.
	if (stmt->hasElseIfClauses() || !stmt->hasElseClause() ||
			!endsWithRetOrUnreach(stmt->getFirstIfBody())) {
		return false;
	}

	// Move the body of the else clause right after the if statement.
	stmt->appendStatement(stmt->getElseClause());
	stmt->removeElseClause();
	return true;
}

/**
* @brief Tries the optimization (2) from the class description on @a stmt.
*
* @return @c true if @a stmt has been optimized, @c false otherwise.
*/
bool IfStructureOptimizer::tryOptimization2(ShPtr<IfStmt> stmt) {
	// We are going to optimize a piece of code of the following form
	//
	// if cond:
	//    statements
	// else:
	//    return/unreachable statement
	//
	// to
	//
	// if not cond:
	//    return/unreachable statement
	// statements
	//
	// To this end, we first check that stmt is of the above form.
	if (stmt->hasElseIfClauses() || !stmt->hasElseClause() ||
			!endsWithRetOrUnreach(stmt->getElseClause())) {
		return false;
	}

	// Negate the if clause's condition.
	stmt->setFirstIfCond(ExpressionNegater::negate(stmt->getFirstIfCond()));

	// Move the body of the if clause right after the if statement.
	stmt->appendStatement(stmt->getFirstIfBody());

	// Move the body of the else clause to the if clause.
	stmt->setFirstIfBody(stmt->getElseClause());
	stmt->removeElseClause();

	return true;
}

/**
* @brief Tries the optimization (3) from the class description on @a stmt.
*
* @return @c true if @a stmt has been optimized, @c false otherwise.
*/
bool IfStructureOptimizer::tryOptimization3(ShPtr<IfStmt> stmt) {
	// We are going to optimize a piece of code of the following form
	//
	// if cond:
	//     // ...
	//     return/unreachable (A)
	// return/unreachable (B)
	//
	// to
	//
	// if not cond:
	//     return/unreachable (B)
	// // ...
	// return/unreachable (A)
	//
	// To this end, we first check that the code if of the above form.
	if (hasElseIfOrElseClauses(stmt) ||
			!endsWithRetOrUnreach(stmt->getFirstIfBody()) ||
			!endsWithRetOrUnreach(stmt->getSuccessor())) {
		return false;
	}

	// Check that the if statement's body contains more statements than the
	// part after the statement. Otherwise, it makes no sense to
	// optimize it.
	if (StatementsCounter::count(stmt->getFirstIfBody()) <=
			StatementsCounter::count(stmt->getSuccessor())) {
		return false;
	}

	// Negate the if clause's condition, and use it only if it was "easy" to
	// negate it, meaning that the resulting negated expression doesn't start
	// with not().
	auto negatedIfCond = ExpressionNegater::negate(stmt->getFirstIfCond());
	if (isa<NotOpExpr>(negatedIfCond)) {
		return false;
	}
	stmt->setFirstIfCond(negatedIfCond);

	// Replace the if statement's body with the successor of the if statement.
	auto originalIfBody = stmt->getFirstIfBody();
	stmt->setFirstIfBody(stmt->getSuccessor());
	stmt->setSuccessor(originalIfBody);

	return true;
}

/**
* @brief Tries the optimization (4) from the class description on @a stmt.
*
* @return @c true if @a stmt has been optimized, @c false otherwise.
*/
bool IfStructureOptimizer::tryOptimization4(ShPtr<IfStmt> stmt) {
	// We are going to optimize a piece of code of the following form:
	//
	// if cond1:
	//     // ... (a)
	// if cond2
	//     // the exact same statements as in (a)
	//
	// to
	//
	// if cond1 or cond2:
	//     // ... (a)

	// Check that the next statement is an if statement.
	auto nextIfStmt = cast<IfStmt>(stmt->getSuccessor());
	if (!nextIfStmt) {
		return false;
	}

	// Check that both if statements have no else-if/else clauses.
	// TODO: This restriction can be relaxed a little bit, but the question is
	//       whether it is worth the effort.
	if (hasElseIfOrElseClauses(stmt) || hasElseIfOrElseClauses(nextIfStmt)) {
		return false;
	}

	// Check that both bodies of the if statements are identical.
	if (!Statement::areEqualStatements(stmt->getFirstIfBody(),
			nextIfStmt->getFirstIfBody())) {
		return false;
	}

	// Check that both bodies end with a return/unreachable statement. Note
	// that since both bodies are identical, it suffices to check only one of
	// them.
	if (!endsWithRetOrUnreach(stmt->getFirstIfBody())) {
		return false;
	}

	// We are ready to perform the optimization.

	// Join the conditions.
	stmt->setFirstIfCond(OrOpExpr::create(stmt->getFirstIfCond(),
		nextIfStmt->getFirstIfCond()));
	// Remove the second if statement.
	Statement::removeStatement(nextIfStmt);
	return true;
}

/**
* @brief Tries the optimization (5) from the class description on @a stmt.
*
* @return @c true if @a stmt has been optimized, @c false otherwise.
*/
bool IfStructureOptimizer::tryOptimization5(ShPtr<IfStmt> stmt) {
	// We are going to optimize a piece of code of the following form:
	//
	// if cond:
	//     // ...
	// else:
	//     pass // No statements (or possibly just empty statements)
	//
	// to
	//
	// if cond:
	//     // ...

	// The statement must have an else clause.
	if (!stmt->hasElseClause()) {
		return false;
	}

	// The body of the else clause has to be empty.
	auto firstNonemptyStmt = skipEmptyStmts(stmt->getElseClause());
	if (firstNonemptyStmt) {
		// There is some non-empty statement.
		return false;
	}

	stmt->removeElseClause();
	return true;
}

} // namespace llvmir2hll
} // namespace retdec
