/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/if_to_switch_optimizer.h
* @brief Optimizes if statements to switch statements.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_IF_TO_SWITCH_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_IF_TO_SWITCH_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/maybe.h"

namespace retdec {
namespace llvmir2hll {

class ValueAnalysis;

/**
* @brief Optimizes if statements to switch statements.
*
* For example,
* @code
* if (a == 5) {
*     c = 5;
* } else if (a == 6) {
*     c = 6;
* } else {
*     c = 3;
* }
* @endcode
* can be optimized to
* @code
* switch (a) {
*     case 5: c = 5; break;
*     case 6: c = 6; break;
*     default: c = 3; break;
* }
* @endcode
*
* In the following cases, this optimization is not possible:
*   -# When the if statement is a simple if without else if clauses.
*   -# When the control expression is not the same in all else if clauses.
*   -# When EqOpExpr is not in clauses conditions.
*   -# When at least one operand of EqOpExpr is not ConstInt.
*   -# When the control expression contains a function call, dereference, or
*      array.
*   -# When if statement has break statement in his body don't optimize because
*      this break can break out some loop and after place it into switch this
*      break jump out only switch statement. In some special cases like this:
*      @code
*      if (a == 5) {
*          while (true) {
*              break;
*          }
*      else if (a == 6) {
*          statement;
*      }
*      @endcode
*      This break don't cause this problem. But for simplification of
*      optimization is this don't optimized.
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class IfToSwitchOptimizer final: public FuncOptimizer {
public:
	IfToSwitchOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va);

	virtual ~IfToSwitchOptimizer() override;

	virtual std::string getId() const override { return "IfToSwitch"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<IfStmt> stmt) override;

	void appendBreakStmtIfNeeded(ShPtr<Statement> stmt);
	ShPtr<Expression> getControlExprIfConvertibleToSwitch(ShPtr<IfStmt> ifStmt);
	ShPtr<Expression> getNextOpIfSecondOneIsConstInt(ShPtr<EqOpExpr>
		eqOpExpr);
	void convertIfStmtToSwitchStmt(ShPtr<IfStmt> ifStmt, ShPtr<Expression>
		controlExpr);

private:
	/// Analysis of values.
	ShPtr<ValueAnalysis> va;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
