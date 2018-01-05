/**
* @file src/llvmir2hll/optimizer/optimizers/dead_code_optimizer.cpp
* @brief Implementation of DeadCodeOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/goto_target_analysis.h"
#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/value.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/dead_code_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module @a Module to be optimized.
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*
* @par Preconditions
*  - @a module is non-null
*  - @a arithmExprEvaluator is non-null
*/
DeadCodeOptimizer::DeadCodeOptimizer(ShPtr<Module> module,
		ShPtr<ArithmExprEvaluator> arithmExprEvaluator): FuncOptimizer(module),
			arithmExprEvaluator(arithmExprEvaluator) {
	PRECONDITION_NON_NULL(module);
	PRECONDITION_NON_NULL(arithmExprEvaluator);
}

/**
* @brief Destructs the optimizer.
*/
DeadCodeOptimizer::~DeadCodeOptimizer() {}

void DeadCodeOptimizer::visit(ShPtr<IfStmt> stmt) {
	FuncOptimizer::visit(stmt);

	tryToOptimizeIfStmt(stmt);
}

/**
* @brief Try to optimize @a stmt.
*
* @param[in] stmt Statement to optimize.
*/
void DeadCodeOptimizer::tryToOptimizeIfStmt(ShPtr<IfStmt> stmt) {
	removeFalseClausesWithoutGotoLabel(stmt);
	auto trueClauseIter = findTrueClause(stmt);
	if (trueClauseIter == stmt->clause_end()) {
		// Due to removing false clauses we can get if statement without first
		// if condition and body. We need to make correctness.
		// Correctness something like:
		// if () {
		// } else {
		//    statement;
		// }
		// to:
		// statement;
		correctIfStmtDueToPresenceOfFalseClauses(stmt);
		return;
	}

	optimizeBecauseTrueClauseIsPresent(stmt, trueClauseIter);
}

/**
* @brief Find first true clause in @a stmt and return it.
*
* @param[in] stmt Statement where is true clause searched.
*
* @return if clause found return iterator to this clause, otherwise
*         @c clause_end().
*/
IfStmt::clause_iterator DeadCodeOptimizer::findTrueClause(ShPtr<IfStmt> stmt) {
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		Maybe<bool> boolResult(arithmExprEvaluator->toBool(i->first));
		if (boolResult && boolResult.get()) {
			// Evaluation was successful and a true clause was found.
			return i;
		}
	}
	return stmt->clause_end();
}

/**
* @brief Removes if, else-if clauses with evaluated condition as false. Clause
*        can be removed if doesn't have goto label.
*
* @param[in] stmt Statement from which are removed false clause.
*/
void DeadCodeOptimizer::removeFalseClausesWithoutGotoLabel(ShPtr<IfStmt> stmt) {
	auto i = stmt->clause_begin();
	while (i != stmt->clause_end()) {
		Maybe<bool> boolResult(arithmExprEvaluator->toBool(i->first));
		if (!boolResult) {
			// Evaluation not successful. Can't be removed.
			i++;
		} else if (!boolResult.get()) {
			// Condition was evaluated as false.
			if (GotoTargetAnalysis::hasGotoTargets(i->second)) {
				// This clause can't be removed because has goto label.
				i++;
			} else {
				// False condition can be removed from ifStmt.
				i = stmt->removeClause(i);
			}
		} else {
			// Condition was evaluated as true.
			i++;
		}
	}
}

/**
* @brief Optimize @a stmt when one of clauses was evaluated as @c true.
*
* @param[in] stmt Statement to optimize.
* @param[in] trueClause First true clause.
*/
void DeadCodeOptimizer::optimizeBecauseTrueClauseIsPresent(ShPtr<IfStmt> stmt,
		IfStmt::clause_iterator trueClause) {
	bool atLeastOneClauseHasGotoLabel(false);
	auto i = stmt->clause_begin();
	while (i != stmt->clause_end()) {
		if (trueClause != i) {
			// if (true) {
			//    statement;
			// else if (false) {
			//    statement;
			// } else if (false) {
			//    label: statement;
			// } else {
			//    label: statement;
			// }
			// Can be optimized to:
			// if (true) {
			//    statement;
			// } else if (false) {
			//    label: statement;
			// } else {
			//    label: statement;
			// }
			if (GotoTargetAnalysis::hasGotoTargets(i->second)) {
				atLeastOneClauseHasGotoLabel = true;
				i++;
				continue;
			}
			i = stmt->removeClause(i);
		} else {
			i++;
		}
	}

	// Need to check if else clause can be removed. If has goto label than can't
	// be removed.
	if (stmt->hasElseClause()) {
		if (!GotoTargetAnalysis::hasGotoTargets(stmt->getElseClause())) {
			stmt->removeElseClause();
		}
	}

	if (!atLeastOneClauseHasGotoLabel && !stmt->hasElseClause()) {
		// if (true) {
		//    statement;
		// }
		// Can be optimized to:
		// statement;
		//
		Statement::replaceStatement(stmt, trueClause->second);
	}
}

/**
* @brief Make correctness on @a stmt in special cases.
*
* Due to removing false clauses we can get if statement without first if
* condition and body. We need to make correctness.
* For Example:
* @code
* if () {}
* statement2;
* @endcode
* To:
* @code
* statement2;
* @endcode
*
* @param[in] stmt Statement on which are made correctness.
*/
void DeadCodeOptimizer::correctIfStmtDueToPresenceOfFalseClauses(
		ShPtr<IfStmt> stmt) {
	if (!stmt->hasClauses()) {
		// Due to removing false clauses we can get if statement without first
		// if condition and body. We need to make correctness.
		// Correctness something like:
		// if () {}
		// statement2;
		// Can be optimized to:
		// statement2;
		Statement::removeStatement(stmt);
	} else if (stmt->hasElseClause() && !stmt->hasIfClause()) {
		// Due to removing false clauses we can get if statement without first
		// if condition and body. We need to make correctness.
		// Correctness something like:
		// if () {
		// } else {
		//    statement2;
		// }
		// Can be optimized to:
		// statement2;
		//
		Statement::replaceStatement(stmt, stmt->getElseClause());
	}
}

void DeadCodeOptimizer::visit(ShPtr<SwitchStmt> stmt) {
	FuncOptimizer::visit(stmt);

	tryToOptimizeSwitchStmt(stmt);
}

/**
* @brief Try to optimize @c SwitchStmt.
*
* Optimization is possible when all clauses have break, continue or return
* statement at last statement. Also is need to have clause with condition which
* is equal to control expression after evaluation.
*
* @param[in] stmt @c SwitchStmt to optimize.
*/
void DeadCodeOptimizer::tryToOptimizeSwitchStmt(ShPtr<SwitchStmt> stmt) {
	// Try to evaluate control expression of switch statement.
	auto controlExpr = arithmExprEvaluator->evaluate(stmt->getControlExpr());
	if (!controlExpr) {
		return;
	}

	if (!hasBreakContinueReturnInAllClausesAsLastStmt(stmt)) {
		// Need to have in all clauses break, continue, return statement.
		return;
	}

	// Clause that have evaluated condition equal with evaluated control
	// expression.
	auto resultClauseIter = findClauseWithCondEqualToControlExpr(
		stmt, controlExpr);

	if (resultClauseIter == stmt->clause_end()) {
		// No one clause has evaluated condition which is equal to evaluated
		// control expression.
		return;
	}

	optimizeSwitchStmt(stmt, resultClauseIter);
}

/**
* @brief Find if all clauses in @a stmt have break, continue, return statement
*        at last statement.
*
* @param[in] stmt Statement to analyse.
*
* @return @c true if all clauses in @a stmt have break, continue, return
*         statement at last statement, otherwise @c false.
*/
bool DeadCodeOptimizer::hasBreakContinueReturnInAllClausesAsLastStmt(
		ShPtr<SwitchStmt> stmt) {
	bool hasBreakContinueReturnInAllClauses(true);
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		auto lastStmt = Statement::getLastStatement(i->second);
		hasBreakContinueReturnInAllClauses &= isa<BreakStmt>(lastStmt) ||
			isa<ContinueStmt>(lastStmt) || isa<ReturnStmt>(lastStmt);
	}
	return hasBreakContinueReturnInAllClauses;
}

/**
* @brief Try to find the first clause with condition that is equal to control
*        expression.
*
* @param[in] stmt Statement to analyse.
* @param[in] controlExpr Control expression of @a stmt.
*
* @return if clause found return iterator to this clause, otherwise
*         @c clause_end().
*/
SwitchStmt::clause_iterator DeadCodeOptimizer::
		findClauseWithCondEqualToControlExpr(ShPtr<SwitchStmt> stmt,
			ShPtr<Constant> controlExpr) {
	auto controlExprConstInt = cast<ConstInt>(controlExpr);
	auto controlExprConstFloat = cast<ConstInt>(controlExpr);
	if (!controlExprConstInt && !controlExprConstFloat) {
		return stmt->clause_end();
	}

	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		if (!i->first) {
			// In default clause is none condition to evaluation.
			continue;
		}

		if (auto condConstInt = cast<ConstInt>(
				arithmExprEvaluator->evaluate(i->first))) {
			// Compare evaluated control expression with condition in clause.
			// If is equal save this clause but this clause must be first saved.
			if (condConstInt->isEqualTo(controlExprConstInt)) {
				return i;
			}
		} else if (auto condConstFloat = cast<ConstFloat>(
				arithmExprEvaluator->evaluate(i->first))) {
			// Compare evaluated control expression with condition in clause.
			// If is equal save this clause but this clause must be first saved.
			if (condConstFloat->isEqualTo(controlExprConstFloat)) {
				return i;
			}
		}
	}
	return stmt->clause_end();
}

/**
* @brief Optimize @a stmt.
*
* @param[in] stmt Statement to optimize.
* @param[in] resultClause Clause that has equal evaluated condition as control
*            expression.
*/
void DeadCodeOptimizer::optimizeSwitchStmt(ShPtr<SwitchStmt> stmt,
		SwitchStmt::clause_iterator resultClause) {
	bool atLeastOneClauseHasGotoLabel(false);
	auto i = stmt->clause_begin();
	while (i != stmt->clause_end()) {
		// switch (2) {
		//    case 2: statement; break;
		//    case 4: label: statement; break;
		//    case 8: statement; break;
		// }
		// Can be optimized to:
		// switch (2) {
		//    case 2: statement; break;
		//    case 4: label: statement; break;
		// }

		if (GotoTargetAnalysis::hasGotoTargets(i->second)) {
			// This clause can't be removed because has goto label.
			atLeastOneClauseHasGotoLabel = true;
			i++;
			continue;
		}

		if (i != resultClause) {
			// Clause don't have goto label and condition of this clause is
			// not equal with control expression, so remove this clause.
			i = stmt->removeClause(i);
		} else {
			i++;
		}
	}

	if (!atLeastOneClauseHasGotoLabel) {
		// switch (2) {
		//    case 2: statement; break;
		// }
		// Can be optimized to:
		// statement;
		//

		// Return statement on last statement can't be removed. Break or
		// continue statement must be removed.
		if (!isa<ReturnStmt>(Statement::getLastStatement(resultClause->second))) {
			Statement::removeLastStatement(resultClause->second);
		}
		Statement::replaceStatement(stmt, resultClause->second);
	}
}

void DeadCodeOptimizer::visit(ShPtr<WhileLoopStmt> stmt) {
	FuncOptimizer::visit(stmt);

	tryToOptimizeWhileLoopStmt(stmt);
}

/**
* @brief Try to optimize @c WhileLoopStmt.
*
* Optimization is possible when condition in while is evaluated as false and
* body of @a stmt doesn't have goto label.
*
* @param[in] stmt @c WhileLoopStmt to optimize.
*/
void DeadCodeOptimizer::tryToOptimizeWhileLoopStmt(ShPtr<WhileLoopStmt> stmt) {
	Maybe<bool> boolResult(arithmExprEvaluator->toBool(stmt->getCondition()));
	if (boolResult && !boolResult.get()) {
		// while (false) {
		//    statement;
		// }
		// statement2;
		// Can be optimized to:
		// statement2;
		//
		if (!GotoTargetAnalysis::hasGotoTargets(stmt->getBody())) {
			Statement::removeStatement(stmt);
		}
	}
}

void DeadCodeOptimizer::visit(ShPtr<ForLoopStmt> stmt) {
	FuncOptimizer::visit(stmt);

	tryToOptimizeForLoopStmt(stmt);
}

/**
* @brief Try to optimize @c ForLoopStmt.
*
* Optimization is possible when end condition in for is evaluated as false and
* body of @a stmt doesn't have goto label.
*
* @param[in] stmt @c ForLoopStmt to optimize.
*/
void DeadCodeOptimizer::tryToOptimizeForLoopStmt(ShPtr<ForLoopStmt> stmt) {
	// For loop can have variables in end condition which can be substituted
	// with initial variable that start value is a constant.
	ArithmExprEvaluator::VarConstMap varValues;
	if (auto startValue = cast<Constant>(stmt->getStartValue())) {
		varValues[stmt->getIndVar()] = startValue;
	}

	Maybe<bool> boolResult(arithmExprEvaluator->toBool(stmt->getEndCond(),
		varValues));
	if (boolResult && !boolResult.get()) {
		// for (i = 5; i < 4; i++) {
		//    statement;
		// }
		// statement2;
		// Can be optimized to:
		// statement2;
		//
		if (!GotoTargetAnalysis::hasGotoTargets(stmt->getBody())) {
			Statement::removeStatement(stmt);
		}
	}
}

} // namespace llvmir2hll
} // namespace retdec
