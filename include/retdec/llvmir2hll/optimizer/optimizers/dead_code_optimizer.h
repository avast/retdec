/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/dead_code_optimizer.h
* @brief Removes dead code.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_DEAD_CODE_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_DEAD_CODE_OPTIMIZER_H

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class ArithmExprEvaluator;

/**
* @brief Removes dead code. Examples are mentioned below.
*
* @par WhileLoopStmt
* @code
* while (false) {
*    statement;
* }
* statement2;
* @endcode
* can be optimized to
* @code
* statement2;
* @endcode
* @par IfStmt
* @code
* if (true) {
*    statement;
* }
* @endcode
* can be optimized to
* @code
* statement;
* @endcode
* @code
* if (false) {
*    statement;
* } else {
*    statement2;
* }
* @endcode
* can be optimized to
* @code
* statement2;
* @endcode
* @code
* if (true) {
*    statement;
* } else if (false) {
*    label: statement2;
* } else if (anything) {
*    statement3;
* } else if (false) {
*    statement4;
* }
* @endcode
* can be optimized to
* @code
* if (true) {
*    statement;
* } else if (false) {
*    label: statement2;
* }
* @endcode
* @par SwitchStmt
* @code
* switch (2) {
*    case 2: statement; break;
* }
* @endcode
* can be optimized to
* @code
* statement;
* @endcode
* @code
* switch (2) {
*    case 2: statement; break;
*    case 4: label: statement; break;
*    case 8: statement; break;
* }
* @endcode
* can be optimized to
* @code
* switch (2) {
*    case 2: statement; break;
*    case 4: label: statement; break;
* }
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class DeadCodeOptimizer final: public FuncOptimizer {
public:
	DeadCodeOptimizer(Module* module, ArithmExprEvaluator*
		arithmExprEvaluator);

	virtual std::string getId() const override { return "DeadCode"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(IfStmt* stmt) override;
	virtual void visit(SwitchStmt* stmt) override;
	virtual void visit(ForLoopStmt* stmt) override;
	virtual void visit(WhileLoopStmt* stmt) override;
	/// @}

	SwitchStmt::clause_iterator findClauseWithCondEqualToControlExpr(
		SwitchStmt* stmt, Constant* controlExpr);
	IfStmt::clause_iterator findTrueClause(IfStmt* stmt);
	bool hasBreakContinueReturnInAllClausesAsLastStmt(SwitchStmt* stmt);
	void optimizeBecauseTrueClauseIsPresent(IfStmt* stmt, IfStmt::
		clause_iterator trueClause);
	void optimizeSwitchStmt(SwitchStmt* stmt,
		SwitchStmt::clause_iterator resultClause);
	void removeFalseClausesWithoutGotoLabel(IfStmt* stmt);
	void correctIfStmtDueToPresenceOfFalseClauses(IfStmt* stmt);
	void tryToOptimizeForLoopStmt(ForLoopStmt* stmt);
	void tryToOptimizeIfStmt(IfStmt* stmt);
	void tryToOptimizeSwitchStmt(SwitchStmt* stmt);
	void tryToOptimizeWhileLoopStmt(WhileLoopStmt* stmt);

private:
	/// The used evaluator of arithmetical expressions.
	ArithmExprEvaluator* arithmExprEvaluator = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
