/**
* @file src/llvmir2hll/optimizer/optimizers/if_to_switch_optimizer.cpp
* @brief Implementation of IfToSwitchOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/break_in_if_analysis.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/optimizer/optimizers/if_to_switch_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
* @param[in] va Analysis of values.
*
* @par Preconditions
*  - @a module and @a va are non-null
*/
IfToSwitchOptimizer::IfToSwitchOptimizer(ShPtr<Module> module,
		ShPtr<ValueAnalysis> va): FuncOptimizer(module), va(va) {
	PRECONDITION_NON_NULL(module);
	PRECONDITION_NON_NULL(va);
}

/**
* @brief Destructs the optimizer.
*/
IfToSwitchOptimizer::~IfToSwitchOptimizer() {}

void IfToSwitchOptimizer::visit(ShPtr<IfStmt> stmt) {
	ShPtr<Expression> controlExpr(getControlExprIfConvertibleToSwitch(stmt));
	if (!controlExpr) {
		return;
	}

	convertIfStmtToSwitchStmt(stmt, controlExpr);
}

/**
* @brief Analyze if IfStmt can be optimized to SwitchStmt and if yes,
*        return control expression.
*
* @param[in] ifStmt IfStmt to analyse.
*
* @return Control expression if @a stmt can be optimized, otherwise the null
*         pointer
*/
ShPtr<Expression> IfToSwitchOptimizer::getControlExprIfConvertibleToSwitch(
		ShPtr<IfStmt> ifStmt) {
	if (!ifStmt->hasElseIfClauses()) {
		// Don't optimize simple if statements without else if clauses.
		return ShPtr<Expression>();
	}

	if (BreakInIfAnalysis::hasBreakStmt(ifStmt)) {
		// Expressions like
		// if (a == 2) {
		//     break;
		// } else if (a == 4) {
		//     a = 2;
		// }
		// can't be optimized, because this if statement can be placed in
		// while loop, and after transformation to switch statement  mentioned
		// break statement don't break the loop, but switch.
		return ShPtr<Expression>();
	}

	ShPtr<Expression> controlExpr;
	for (auto i = ifStmt->clause_begin(), e = ifStmt->clause_end(); i != e; ++i) {
		ShPtr<EqOpExpr> eqOpExpr(cast<EqOpExpr>(i->first));
		if (!eqOpExpr) {
			// Need to have condition like if (anything == ConstInt (vice versa)).
			return ShPtr<Expression>();
		}

		ShPtr<Expression> exprToCompareWithControlExpr(
			getNextOpIfSecondOneIsConstInt(eqOpExpr));
		if (!exprToCompareWithControlExpr) {
			// ConstInt wasn't found in some of operands.
			return ShPtr<Expression>();
		}

		if (!controlExpr) {
			controlExpr = exprToCompareWithControlExpr;
		} else if (!controlExpr->isEqualTo(exprToCompareWithControlExpr)) {
			// Need to have same control expressions.
			return ShPtr<Expression>();
		}

		ShPtr<ValueData> exprData(va->getValueData(exprToCompareWithControlExpr));
		if (exprData->hasCalls() || exprData->hasArrayAccesses() ||
				exprData->hasDerefs()) {
			// Control expression can't be func() or a[] or *a, because
			//      if (func() == 5) {
			//      } else if (func() == 6) {}
			// is not the same as
			//      switch(func()) {
			//          case 5: break;
			//          case 6: break;
			//      }
			// In the latter case, the function is called only once.
			return ShPtr<Expression>();
		}
	}

	return controlExpr;
}

/**
* @brief Optimize @a ifStmt to SwitchStmt.
*
* @param[in] ifStmt IfStmt to optimize.
* @param[in] controlExpr Control expression of new SwitchStmt.
*/
void IfToSwitchOptimizer::convertIfStmtToSwitchStmt(ShPtr<IfStmt> ifStmt,
		ShPtr<Expression> controlExpr) {
	ShPtr<SwitchStmt> switchStmt(SwitchStmt::create(controlExpr));
	for (auto i = ifStmt->clause_begin(), e = ifStmt->clause_end(); i != e; ++i) {
		// Append break statement at last statement of statements block. Because
		// then we paste this statements block to case clause.
		// This create something like:
		//      stm1;
		//      stmt2;
		//      break;
		// This is possible only when last statement is not a continue statement
		// or return statement or goto statement.
		appendBreakStmtIfNeeded(Statement::getLastStatement(i->second));

		// Create switch clause.
		ShPtr<EqOpExpr> eqOpExpr(cast<EqOpExpr>(i->first));
		if (eqOpExpr->getFirstOperand()->isEqualTo(controlExpr)) {
			switchStmt->addClause(eqOpExpr->getSecondOperand(), i->second);
		} else {
			switchStmt->addClause(eqOpExpr->getFirstOperand(), i->second);
		}
	}

	if (ifStmt->hasElseClause()) {
		// If if statement has else clause, we can convert this clause
		// to default clause in switch statement.
		switchStmt->addDefaultClause(ifStmt->getElseClause());
		// Append break statement at last statement of statements block. Because
		// then we paste this statements block to default clause.
		// This create something like:
		//      stm1;
		//      stmt2;
		//      break;
		// This is possible only when last statement is not a continue statement
		// or return statement or goto statement.
		appendBreakStmtIfNeeded(ifStmt->getElseClause());
	}

	Statement::replaceStatement(ifStmt, switchStmt);
}

/**
* @brief Append BreakStmt after @a stmt when @a stmt is not a ContinueStmt
*        or ReturnStmt or GotoStmt.
*
* @param[in] stmt Statement on which is BreakStmt append.
*/
void IfToSwitchOptimizer::appendBreakStmtIfNeeded(ShPtr<Statement> stmt) {
	if (!isa<ContinueStmt>(stmt) && !isa<ReturnStmt>(stmt) &&
			!isa<GotoStmt>(stmt)) {
		stmt->setSuccessor(BreakStmt::create());
	}
}

/**
* @brief Check if one of the operands is a ConstInt. If so, then return the
*        next one operand.
*
* @param[in] eqOpExpr EqOpExpr to check.
*
* @return If one of the operands is a ConstInt, than return the second
*         operand. Otherwise return the null pointer.
*/
ShPtr<Expression> IfToSwitchOptimizer::getNextOpIfSecondOneIsConstInt(
		ShPtr<EqOpExpr> eqOpExpr) {
	if (isa<ConstInt>(eqOpExpr->getFirstOperand())) {
		return eqOpExpr->getSecondOperand();
	} else if (isa<ConstInt>(eqOpExpr->getSecondOperand())) {
		return eqOpExpr->getFirstOperand();
	} else {
		return ShPtr<Expression>();
	}
}

} // namespace llvmir2hll
} // namespace retdec
