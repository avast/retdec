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
#include "retdec/llvmir2hll/support/maybe.h"
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
	DeadCodeOptimizer(ShPtr<Module> module, ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator);
	virtual ~DeadCodeOptimizer() override;

	virtual std::string getId() const override { return "DeadCode"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<IfStmt> stmt) override;
	virtual void visit(ShPtr<SwitchStmt> stmt) override;
	virtual void visit(ShPtr<ForLoopStmt> stmt) override;
	virtual void visit(ShPtr<WhileLoopStmt> stmt) override;
	/// @}

	SwitchStmt::clause_iterator findClauseWithCondEqualToControlExpr(
		ShPtr<SwitchStmt> stmt, ShPtr<Constant> controlExpr);
	IfStmt::clause_iterator findTrueClause(ShPtr<IfStmt> stmt);
	bool hasBreakContinueReturnInAllClausesAsLastStmt(ShPtr<SwitchStmt> stmt);
	void optimizeBecauseTrueClauseIsPresent(ShPtr<IfStmt> stmt, IfStmt::
		clause_iterator trueClause);
	void optimizeSwitchStmt(ShPtr<SwitchStmt> stmt,
		SwitchStmt::clause_iterator resultClause);
	void removeFalseClausesWithoutGotoLabel(ShPtr<IfStmt> stmt);
	void correctIfStmtDueToPresenceOfFalseClauses(ShPtr<IfStmt> stmt);
	void tryToOptimizeForLoopStmt(ShPtr<ForLoopStmt> stmt);
	void tryToOptimizeIfStmt(ShPtr<IfStmt> stmt);
	void tryToOptimizeSwitchStmt(ShPtr<SwitchStmt> stmt);
	void tryToOptimizeWhileLoopStmt(ShPtr<WhileLoopStmt> stmt);

private:
	/// The used evaluator of arithmetical expressions.
	ShPtr<ArithmExprEvaluator> arithmExprEvaluator;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
